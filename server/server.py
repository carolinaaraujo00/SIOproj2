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
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

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


# TODO PODE SER ALTERADO PARA UMA PASSWORD
KEY = b'\xc4\x8e*&\xf2 \x9c\xdd\xfb7Z\xed\x0fm*\xed}}\x18\xc6!\xb2\x9e\x0b\xef\x88\x92\xbfs\x87L9'
IV = b'\xb6^\xc9\xde\x1e\xe7\xa2<\x00<\x80w\x02\x1e\xee\xf7'

class MediaServer(resource.Resource):
    isLeaf = True
    def __init__(self, init_type='loaded'):
        self.clients = {}

        self.can_download = set()

        self.file_encryptor = DirEncript()

        """ Usar quando ficheiros não estão cifrados """
        if init_type == 'encrypt':
            self.file_encryptor.encrypt_catalog_chunks()
            self.file_encryptor.encrypt_files()
            self.file_encryptor.save_keys_and_ivs(KEY, IV)
        
        """ Quando já estiverem cifrados """
        if init_type == 'loaded':
            self.file_encryptor.load_keys_and_ivs(KEY, IV)
        
        """ Para decriptar os ficheiros """
        if init_type == 'decrypt':
            self.file_encryptor.load_keys_and_ivs(KEY, IV)
            self.file_encryptor.decrypt_files()
            print('Files decrypted. Soo bye bye...')
            exit(0)
        
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
        
        self.clients[request.getHeader('ip')]['client_algorithm'] = data['algorithm']
        self.clients[request.getHeader('ip')]['client_mode'] = data['mode']
        self.clients[request.getHeader('ip')]['client_digest'] = data['digest']
        self.clients[request.getHeader('ip')]['tag'] = None

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
        # TODO utilizar PBKDF2HMAC talvez seja mais seguro
        derived_key = HKDF(
            algorithm=algorithm,
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
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
        
        if client_mode == "GCM":
            tag = encryptor.tag
        
        return cripto, iv, tag, nonce
    
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
    
    def authn_client(self, request):
        # TODO encriptar o ip TALVEZ
        return self.license(request)
            

    def license(self, request):
        licenses = json.loads(self.file_encryptor.decrypt_file('./licenses.json').decode())
        ip = request.getHeader('ip')

        if ip in licenses:
            diff = datetime.fromtimestamp(time.time()) - datetime.fromisoformat(licenses[ip]['timestamp'])
            
            # verificar se a licenca expirou
            if diff.seconds/60 <= 7:
                # tem uma licenca valida
                logger.info(f'O cliente {ip} tem licenca')

                self.clients[ip]['code'] = os.urandom(16)
                return self.send_response(request, "sucess", binascii.b2a_base64(self.clients[ip]['code']).decode('latin').strip())
            
            return self.send_response(request, 'error', 'The license expired.')

        return self.send_response(request, 'error', 'No license associated with this user.')
    
    def new_license(self, request):
        ip = request.getHeader('ip')

        # verificar se o user já está autenticado
        if not ip in self.clients and not self.clients[ip]['authenticated']:
            logger.error(f'Client with ip {ip} trying to get license is not authenticated.')
            return self.send_response(request, 'error', 'Unauthorized to get license. Authenticate first')
        
        # emitir uma nova licenca
        licenses = json.loads(self.file_encryptor.decrypt_file('./licenses.json').decode())
        
        licenses[ip] = {'timestamp' : datetime.fromtimestamp(time.time()).__str__()}
        logger.info(f'Uma nova licenca foi criada para o cliente {ip}')
            
        self.file_encryptor.encrypt_file('./licenses.json', json.dumps(licenses).encode())

        self.clients[ip]['code'] = os.urandom(16)
        return self.send_response(request, "sucess", binascii.b2a_base64(self.clients[ip]['code']).decode('latin').strip())
    
    
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
    def sign(self, data):
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def code_verify(self, code, ip):
        h = hmac.HMAC(self.clients[ip]['key'], self.clients[ip]['hash'], backend=default_backend())
        h.update(self.clients[ip]['code'])
        try:
            h.verify(code)
            logger.info("Authorized.")
            return True
        except InvalidSignature:
            logger.error("Invalid code - unauthorized.")
            return False

    def get_trusted_cas(self):
        return [
            x509.load_der_x509_certificate(self.file_encryptor.decrypt_file(f.path), backend=default_backend())
            for f in os.scandir('./trusted_cas/')
        ]

    def check_client_cert(self, request, data):
    	request.responseHeaders.addRawHeader(b"content-type", b"application/json")

    	trusted = self.get_trusted_cas()

    	client_chain_certs = [x509.load_der_x509_certificate(binascii.a2b_base64(c.encode('latin')), backend=default_backend()) for c in data]
    	for cert in client_chain_certs:
            for trust in trusted:
                if cert.issuer == trust.subject:
                    logger.info(f'Valid certificate.')
                    self.clients[request.getHeader('ip')] = {'cert' : client_chain_certs[0], 'authenticated' : False}
                    return json.dumps({'msg': 'Valid certificate'}).encode('latin')

    	request.setResponseCode(406)

    	logger.info('Invalid certificate.')
    	return json.dumps({'msg': 'Invalid certificate'}).encode('latin')
    
    def verify(self, msg, signature, ip):
        try:
            result = self.clients[ip]['cert'].public_key().verify(
                signature,
                msg,
                PKCS1v15(),
                hashes.SHA1(),
            )
            logger.info('Assinatura válida.')
        except InvalidSignature:
            logger.error('ERRO: Conteúdo e/ou assinatura falharam na verificação.')
            return False

        return True
        
    def challenge(self, request, data):
        ip = request.getHeader('ip')
        request.requestHeaders.addRawHeader(b'content-type', b'application/json')

        msg = binascii.a2b_base64(data['msg'].encode('latin'))
                
        if not self.verify(msg, binascii.a2b_base64(data['signature'].encode('latin')), ip):
            request.setResponseCode(400)
            return json.dumps({'msg' : 'Signature failed'}).encode('latin')

        sign_challenge = self.sign(msg)
        
        server_challenge = os.urandom(16)
        self.clients[ip]['server_challenge'] = server_challenge
        
        msg = {'signed_challenge' : binascii.b2a_base64(sign_challenge).decode('latin').strip(), 'server_challenge' : binascii.b2a_base64(server_challenge).decode('latin').strip()}
        msg = json.dumps(msg).encode('latin')
                
        return json.dumps({'msg' : binascii.b2a_base64(msg).decode('latin').strip(), 'signature' : binascii.b2a_base64(self.sign(msg)).decode('latin').strip()}).encode('latin')

    def authenticate(self, request, data):
        ip = request.getHeader('ip')

        signed_challenge = binascii.b2a_base64(data['signed_challenge'].encode('latin'))
        if not self.verify(signed_challenge, binascii.b2a_base64(data['signature'].encode('latin')), ip):
            return
        
        if self.verify(self.clients[ip]['server_challenge'], signed_challenge, ip):
            logger.info('Client signed correctly the challenge.')
            self.clients[ip]['authenticated'] = True
        else:
            logger.info('The verification of the signed challenge failed.')    
   
    # Send the list of media files to clients
    def do_list(self, request):
    
        data = request.getHeader('Authorization')
        data = json.loads(data)
        
        code = self.decrypt_message(data, request.getHeader('ip'))
        code = binascii.a2b_base64(code.encode('latin'))
        
        if not self.code_verify(code, request.getHeader('ip')):
           request.setResponseCode(401)
           return self.send_response(request, "error", {'error': 'Not authorized'})

        self.can_download.add(request.getHeader('ip'))

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
        return self.send_response(request, "data_list", media_list)

    # Send a media chunk to the client
    def do_download(self, request):       
        if not request.getHeader('ip') in self.can_download:
            request.setResponseCode(401)
            logger.error(f'{request.getHeader("ip")} is not authorized to do download.')
            return self.send_response(request, "error", {'error': 'Not authorized to do download.'})

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

        # remover cliente da lista de clientes que podem fazer download
        if chunk_id == math.ceil(media_item['file_size'] / CHUNK_SIZE):
            self.can_download.remove(request.getHeader('ip'))

        if not valid_chunk:
            request.setResponseCode(400)
            return self.send_response(request, "error", {'error': 'invalid chunk id'})
                        
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        try:
            data = self.file_encryptor.decrypt_file(os.path.join('.', CATALOG_BASE, 'chunks', media_item['file_name'].split('.')[0] + '#' + str(offset)))

            return self.send_response(request, "data_download", {
                'media_id': media_id,
                'chunk': chunk_id,
                'data': binascii.b2a_base64(data).decode('latin').strip()
            })

        except :
            # File was not open?
            return self.send_response(request, "error", {'error': 'unknown'})

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        # TODO informação sensível deve ir por POST
        if not request.getHeader('ip') in self.clients:
            request.setResponseCode(401)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'msg' : 'Not authorized to view this content'}).encode('latin')
        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/cert':
                return self.cert(request)
            elif request.path == b'/api/list':
                return self.do_list(request)
            elif request.path == b'/api/download':
                return self.do_download(request)
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
                # ass_data = self.rsa_decrypt(content)
                data = json.loads(content.decode('latin'))
                self.client_protocols(request, data)
            elif request.path == b'/api/dh_client_public_key':
                data = json.loads(content.decode('latin'))
                return self.dh_public_key(request, data)
            elif request.path == b'/api/msg':
                data = json.loads(content.decode('latin'))
                if not self.check_integrity(data['msg'], data['mac'], request.getHeader('ip')):
                    return self.send_response(request, "error", {'error': 'Corrupted Message'})
                return self.msg_received(request, data)
            elif request.path == b'/api/license':
                data = json.loads(content.decode('latin'))
                # if not self.check_integrity(data['msg'], data['mac'], request.getHeader('ip')):
                #     return self.send_response(request, "error", {'error': 'Corrupted Message'})
                return self.license(request)
            elif request.path == b'/api/rotatekey':
                data = json.loads(content.decode('latin'))
                return self.rotate_key(request, data)
            elif request.path == b'/api/hello':
            	data = json.loads(content.decode('latin'))
            	return self.check_client_cert(request, data)
            elif request.path == b'/api/challenge':
                data = json.loads(content.decode('latin'))
                return self.challenge(request, data)
            elif request.path == b'/api/authenticate':
                data = json.loads(content.decode('latin'))
                self.authenticate(request, data)
            elif request.path == b'/api/newlicense':
                return self.new_license(request)
        
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(501)
            return b''


print("Server started")
print("URL is: http://IP:8080")
""" Usar ficheiros encriptados """
s = server.Site(MediaServer())

""" Encriptar ficheiros """
# s = server.Site(MediaServer('encrypt'))

""" Decriptar ficheiros """
# s = server.Site(MediaServer('decrypt'))

reactor.listenTCP(8080, s)
reactor.run()