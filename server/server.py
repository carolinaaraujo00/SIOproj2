#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math

from datetime import datetime
import time

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

""" encriptar ficheiros """
from encrypt_dir import DirEncript

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            },
            'Black Pumas - Colors' :
                {
                    'name' : 'Black Pumas - Colors',
                    'album' : 'Colors',
                    'description' : 'best music 2025',
                    'duration' : 4*60+7,
                    'file_name' : 'Black Pumas - Colors.mp3',
                    'file_size' : 3947343
                },
            'ABBA - Mamma mia' : {
                'name' : 'ABBA - Mamma Mia',
                'album' : 'Album',
                'description' : 'best music ever (segundo a Carolina) (cuja opiniao vale round(0)',
                'duration' : 3*60+33,
                'file_name' : 'mammamia.mp3',
                'file_size' : 3394801
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024

ALGORITHMS = ['AES', 'ChaCha20', '3DES']
MODES = ['CBC', 'OFB', 'CFB', 'GCM']
DIGEST = ['SHA256', 'SHA512', 'BLAKE2b', 'SHA3_256', 'SHA3_512']


# PODE SER ALTERADO PARA UMA PASSWORD
KEY = b'\xc4\x8e*&\xf2 \x9c\xdd\xfb7Z\xed\x0fm*\xed}}\x18\xc6!\xb2\x9e\x0b\xef\x88\x92\xbfs\x87L9'
IV = b'\xb6^\xc9\xde\x1e\xe7\xa2<\x00<\x80w\x02\x1e\xee\xf7'

class MediaServer(resource.Resource):
    isLeaf = True
    def __init__(self):
        self.clients = {}

        # TODO alterar para uma coisa em condicoes        
        self.client_authorizations = set()
                
        self.file_encryptor = DirEncript()
        """ Usar quando ficheiros não estão cifrados """
        # self.file_encryptor.encrypt_catalog_chunks()
        # self.file_encryptor.encrypt_files()
        # self.file_encryptor.save_keys_and_ivs(KEY, IV)
        
        """ Quando já estiverem cifrados """
        self.file_encryptor.load_keys_and_ivs(KEY, IV)

        self.private_key = self.get_private_key()
            
    def get_private_key(self):
        return serialization.load_pem_private_key(
            self.file_encryptor.decrypt_file('./certificate/SIO_ServerPK.pem'), 
            password = None,
            backend = default_backend()
        )
    
    def do_get_protocols(self, request):
        logger.debug(f'Client asked for protocols')
        return json.dumps(
            {
                'algorithms': ALGORITHMS, 
                'modes': MODES, 
                'digests': DIGEST
            },indent=4
        ).encode('latin')
    
    def client_protocols(self, request, data):
        
        self.clients[request.getHeader('ip')] = {
            'client_algorithm' : data['algorithm'],
            'client_mode' : data['mode'],
            'client_digest' : data['digest'],
            'tag' : None
        }
        
        self.set_hash_algo(request.getHeader('ip'))
                
        logger.info(f'{request.getHeader("ip")} protocols: Cipher:{data["algorithm"]}; Mode:{data["mode"]}; Digest:{data["digest"]}')
        
    def dh_public_key(self, request, data):
        params_numbers = dh.DHParameterNumbers(data['p'], data['g'])
        dh_parameters = params_numbers.parameters(default_backend())
        
        self.clients[request.getHeader('ip')]['dh_parameters'] = dh_parameters
        
        private_key = dh_parameters.generate_private_key()
        
        client_pk_b = binascii.a2b_base64(data["pk"].encode('latin'))
        
        client_public_key = serialization.load_der_public_key(client_pk_b, backend=default_backend())
        
        public_key_dh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # chave comum a servidor e cliente
        shared_key = private_key.exchange(client_public_key)
        
        logger.debug(f'Shared Key created sucessfully')
        
        # inicializar o processo de criar encriptador e decriptador
        self.clients[request.getHeader('ip')]['key'] = self.get_key(shared_key, request.getHeader('ip'))
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({"key" : binascii.b2a_base64(public_key_dh).decode('latin').strip()}, indent=4).encode('latin')
    
    def rotate_key(self, request, data):
        private_key = self.clients[request.getHeader('ip')]['dh_parameters'].generate_private_key()
        
        client_pk_b = binascii.a2b_base64(data["pk"].encode('latin'))
        
        client_public_key = serialization.load_der_public_key(client_pk_b, backend=default_backend())
        
        public_key_dh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        shared_key = private_key.exchange(client_public_key)
        
        logger.debug(f'Succeded at rotating key')
        
        self.clients[request.getHeader('ip')]['key'] = self.get_key(shared_key, request.getHeader('ip'))
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({"key" : binascii.b2a_base64(public_key_dh).decode('latin').strip()}, indent=4).encode('latin')
        
        
    def get_key(self, shared_key, ip):
        if self.clients[ip]['client_algorithm'] == 'AES' or self.clients[ip]['client_algorithm'] == 'ChaCha20':
            return self.derive_shared_key(shared_key, self.clients[ip]['hash'], 32, None, b'handshake data')
        elif self.clients[ip]['client_algorithm'] == '3DES':
            return self.derive_shared_key(shared_key, self.clients[ip]['hash'], 24, None, b'handshake data')
        
    def derive_shared_key(self, shared_key, algorithm, length, salt, info):
        # utilizar PBKDF2HMAC talvez seja mais seguro
        derived_key = HKDF(
            algorithm=algorithm,
            length=length,
            salt=salt,
            info=info,
        ).derive(shared_key)
        
        return derived_key
    
    def get_iv(self, algo):
        if algo == 'AES':
            return os.urandom(16)
        elif algo == '3DES':
            return os.urandom(8)
        
    
    def get_mode(self, mode, iv, tag):                
        if mode == 'CBC':
            return modes.CBC(iv)
        elif mode == 'OFB':
            return modes.OFB(iv)
        elif mode == 'CFB':
            return modes.CFB(iv)
        elif mode == 'GCM':
            return modes.GCM(iv, tag)
    
    def get_algorithm(self, algo, key, nonce):
        if algo == 'AES':
            return algorithms.AES(key)
        elif algo == 'ChaCha20':
            return algorithms.ChaCha20(key, nonce)
        elif algo == '3DES':
            return algorithms.TripleDES(key)
            
    def get_encryptor(self, algorithm, mode):
        cipher = Cipher(algorithm, mode=mode, backend=default_backend())
        return cipher.encryptor()
        
    def get_decryptor(self, algorithm, mode):
        cipher = Cipher(algorithm, mode=mode, backend=default_backend())
        return cipher.decryptor()
        
    def set_hash_algo(self, ip):
        if self.clients[ip]['client_digest'] == 'SHA256':
            self.clients[ip]['hash'] = hashes.SHA256()
        elif self.clients[ip]['client_digest'] == 'SHA512':
            self.clients[ip]['hash'] = hashes.SHA512()
        elif self.clients[ip]['client_digest'] == 'BLAKE2b':
            self.clients[ip]['hash'] = hashes.BLAKE2b(64)
        elif self.clients[ip]['client_digest'] == 'SHA3_256':
            self.clients[ip]['hash'] = hashes.SHA3_256()
        elif self.clients[ip]['client_digest'] == 'SHA3_512':
            self.clients[ip]['hash'] = hashes.SHA3_512()
        
    def get_digest(self, ip):
        return hashes.Hash(self.clients[ip]['hash'])   
        
    def get_decryptor4msg(self, tag, nonce, iv, ip):
        mode = self.get_mode(self.clients[ip]['client_mode'], iv, tag)
        algorithm = self.get_algorithm(self.clients[ip]['client_algorithm'], self.clients[ip]['key'], nonce)
        return self.get_decryptor(algorithm, mode)
        
    def block_size(self, algo):
        if algo == '3DES':
            return 8
        return 16
        
    def decrypt_message(self, data, ip):
        tag = None
        nonce = None
        iv = None
        if "tag" in data:
            tag = binascii.a2b_base64(data["tag"].encode('latin'))
        if "nonce" in data:
            nonce = binascii.a2b_base64(data["nonce"].encode('latin'))
        if "iv" in data:
            iv = binascii.a2b_base64(data["iv"].encode('latin'))
            
        decryptor = self.get_decryptor4msg(tag, nonce, iv, ip)
        
        criptogram = binascii.a2b_base64(data["msg"].encode('latin'))

        if self.clients[ip]['client_algorithm'] == "ChaCha20":
            return json.loads(decryptor.update(criptogram).decode('latin'))

        block_size = self.block_size(self.clients[ip]['client_algorithm'])
        text = b''
        last_block = criptogram[len(criptogram) - block_size :]
        criptogram = criptogram[:-block_size]
        
        while True:
            portion = criptogram[:block_size]
            if len(portion) == 0:
                dec = decryptor.update(last_block) + decryptor.finalize()
                text += dec[:block_size - dec[-1]]
                break
            
            text += decryptor.update(portion)
            criptogram = criptogram[block_size:]
            
        return json.loads(text.decode('latin'))
    
    def encrypt_message(self, msg, ip):
        data = json.dumps(msg).encode('latin')
        
        client_algo = self.clients[ip]['client_algorithm']
        client_mode = self.clients[ip]['client_mode']        
        
        nonce = None
        tag = None
        if client_algo == "ChaCha20":
            nonce = os.urandom(16)
        
        mode = None
        iv = None
        if client_algo != 'Chacha20':
            iv = self.get_iv(client_algo)
            mode = self.get_mode(client_mode, iv, None)

        algorithm = self.get_algorithm(client_algo, self.clients[ip]['key'], nonce)
        encryptor = self.get_encryptor(algorithm, mode)

        blocksize = self.block_size(client_algo)
        
        if client_algo == "ChaCha20":
            return encryptor.update(data), iv, tag, nonce

        cripto = b''
        while True:
            portion = data[:blocksize]
            if len(portion) != blocksize:
                portion = portion + bytes([blocksize - len(portion)] * (blocksize - len(portion)))
                cripto += encryptor.update(portion) + encryptor.finalize()
                break
            
            cripto += encryptor.update(portion)
            data = data[blocksize:]
        
        if self.client_mode == "GCM":
            tag = self.encryptor.tag
        
        return cripto, iv, tag, nonce
    
    # TODO alterar
    def check_integrity(self, msg, mac, ip):
        h = hmac.HMAC(self.clients[ip]['key'], self.clients[ip]['hash'], backend = default_backend())
        h.update(binascii.a2b_base64(msg.encode('latin')))

        try:
            h.verify(binascii.a2b_base64(mac.encode('latin')))
            logger.info("A mensagem chegou sem problemas :)")
            return True

        except InvalidSignature:
            logger.error("A mensagem foi corrompida a meio do caminho.")
            return False

    def msg_received(self, request, data):
        if data['type'] == 'msg':
            if not self.check_integrity(data['msg'], data['mac'], self.clients[request.getHeader('ip')]):
                return self.send_response(request, "error", {'error' : "Corrupted message."})
                
            dic_text = self.decrypt_message(data, request.getHeader('ip'))
            logger.info(f'Mensagem recebida: {dic_text}')
            
            msg = {"msg" : "Message is ok."}
            
            return self.send_response(request, msg)
        
    
    def send_response(self, request, type_, resp):         
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        ip = request.getHeader('ip')
        client_algo = self.clients[ip]['client_algorithm']
        
        cripto, iv, tag, nonce  = self.encrypt_message(resp, ip)
        
        h = hmac.HMAC(self.clients[ip]['key'], self.clients[ip]['hash'], backend = default_backend())
        h.update(cripto)
        
        json_message = {
                    "type" : type_,
                    "msg" : binascii.b2a_base64(cripto).decode('latin').strip(),
                    "mac" : binascii.b2a_base64(h.finalize()).decode('latin').strip() 
                    }
        
        if client_algo == "ChaCha20":
            json_message["nonce"] = binascii.b2a_base64(nonce).decode('latin').strip()
        else:
            json_message["iv"] = binascii.b2a_base64(iv).decode('latin').strip()
                
            if self.clients[ip]['client_mode'] == "GCM":
                json_message["tag"] = binascii.b2a_base64(tag).decode('latin').strip()
        
        return json.dumps(json_message).encode('latin')
    
    def authn_client(self, request, data):
        return self.license(request, self.decrypt_message(data, request.getHeader('ip')))
            

    def license(self, request, client_identifier):
        licenses = json.loads(self.file_encryptor.decrypt_file('./licenses.json').decode())
            
        if client_identifier in licenses:
            diff = datetime.fromtimestamp(time.time()) - datetime.fromisoformat(licenses[client_identifier]['timestamp'])
            
            # verificar se a licenca expirou
            if diff.seconds/60 <= 30:
                # tem uma licenca valida
                logger.info(f'O cliente {client_identifier} tem licenca')
                return self.send_response(request, "sucess", binascii.b2a_base64(self.gen_code()).decode('latin').strip())
        
        
        """ TODO falta fazer a autenticacao do cliente """
        
            
        # teria de emitir uma nova licenca
        licenses[client_identifier] = {'timestamp' : datetime.fromtimestamp(time.time()).__str__()}
        logger.info(f'Uma nova licenca foi criada para o cliente {client_identifier}')
            
        self.file_encryptor.encrypt_file('./licenses.json', json.dumps(licenses).encode())
                
        return self.send_response(request, "sucess", binascii.b2a_base64(self.gen_code()).decode('latin').strip())
    
    def gen_code(self):
        code = None
        while True:
            code = os.urandom(32)
            if not code in self.client_authorizations:
                break
            
        self.client_authorizations.add(code)
        return code
    
    """ Proj3 """
    def cert(self, request):
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        
        return json.dumps({'cert' : binascii.b2a_base64(self.file_encryptor.decrypt_file('./certificate/SIO_Server.crt')).decode('latin').strip()}, indent=4).encode('latin')
        
    def rsa_decrypt(self, content):
        return self.private_key.decrypt(content,
                                            padding = padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                            )
                                        )
    def sign_chunk(self, data):
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
    # Send the list of media files to clients
    def do_list(self, request):
    
        data = request.getHeader('Authorization')
        data = json.loads(data)
        
        # TODO este código pode ser gerado a partir dum hmac
        code = self.decrypt_message(data, request.getHeader('ip'))
        code = binascii.a2b_base64(code.encode('latin'))
        
        if not code in self.client_authorizations:
           request.setResponseCode(401)
           return self.send_response(request, "error", {'error': 'Not authorized'})


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        # request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return self.send_response(request, "data_list", media_list)

    # Send a media chunk to the client
    def do_download(self, request):
        data = request.getHeader('Authorization')
        data = json.loads(data)
        
        # TODO este código pode ser gerado a partir dum hmac
        code = self.decrypt_message(data, request.getHeader('ip'))
        code = binascii.a2b_base64(code.encode('latin'))
        
        if not code in self.client_authorizations:
           request.setResponseCode(401)
           logger.error('Invalid license')
           return self.send_response(request, "error", {'error': 'Not authorized'})
       
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            return self.send_response(request, "error", {'error': 'invalid media id'})
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            return self.send_response(request, "error", {'error': 'media file not found'})
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            return self.send_response(request, "error", {'error': 'invalid chunk id'})
                        
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        try:
            # print(os.path.join('.', CATALOG_BASE, 'chunks', media_item['file_name'].split('.')[0] + '#' + str(offset)))
            # TODO alterar path se funcionar
            data = self.file_encryptor.decrypt_file(os.path.join('.', CATALOG_BASE, 'chunks', media_item['file_name'].split('.')[0] + '#' + str(offset)))


            # request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return self.send_response(request, "data_download", {
                'media_id': media_id,
                'chunk': chunk_id,
                'data': binascii.b2a_base64(data).decode('latin').strip(),
                'signature' : binascii.b2a_base64(self.sign_chunk(data)).decode('latin').strip() # dá para assinar porque o tamanho da chunk é inferior ao tamanho da key
            })

        except :
            # File was not open?
            return self.send_response(request, "error", {'error': 'unknown'})
                
    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        # TODO informação sensível deve ir por POST
        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/cert':
                return self.cert(request)
            elif request.path == b'/api/list':
                return self.do_list(request)
            elif request.path == b'/api/download':
                return self.do_download(request)
            # elif request.path == b'/api/get_public_key_dh':
            #     request.responseHeaders.addRawHeader(b"content-type", b'application/json')
            #     return json.dumps(binascii.b2a_base64(self.public_key_dh).decode('latin').strip(), indent=4).encode('latin')

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        try:
            content = request.content.getvalue()
            
            if request.path == b'/api/protocol_choice':
                ass_data = self.rsa_decrypt(content)
                data = json.loads(ass_data.decode('latin'))
                print(data)
                self.client_protocols(request, data)
            elif request.path == b'/api/dh_client_public_key':
                data = json.loads(content.decode('latin'))
                print(data)
                return self.dh_public_key(request, data)
            elif request.path == b'/api/msg':
                data = json.loads(content.decode('latin'))
                print(data)
                if not self.check_integrity(data['msg'], data['mac'], request.getHeader('ip')):
                    return self.send_response(request, "error", {'error': 'Corrupted Message'})
                return self.msg_received(request, data)
            elif request.path == b'/api/authn':
                data = json.loads(content.decode('latin'))
                print(data)
                if not self.check_integrity(data['msg'], data['mac'], request.getHeader('ip')):
                    return self.send_response(request, "error", {'error': 'Corrupted Message'})
                return self.authn_client(request, data)
            elif request.path == b'/api/rotatekey':
                data = json.loads(content.decode('latin'))
                print(data)
                return self.rotate_key(request, data)
        
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(501)
            return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()