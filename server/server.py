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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
CHUNK_SIZE = 1024 * 4

ALGORITHMS = ['AES', 'ChaCha20', '3DES']
MODES = ['CBC', 'OFB', 'CFB', 'GCM']
DIGEST = ['SHA256', 'SHA512', 'BLAKE2b', 'SHA3_256', 'SHA3_512']

class MediaServer(resource.Resource):
    isLeaf = True
    def __init__(self):
        self.client_cipher = None
        self.client_mode = None
        self.client_digest = None
        self.private_key = None
        self.public_key = None
        self.tag = None
        self.client_authorizations = set()
    
    def do_get_protocols(self, request):
        logger.debug(f'Client asked for protocols')
        return json.dumps(
            {
                'algorithms': ALGORITHMS, 
                'modes': MODES, 
                'digests': DIGEST
            },indent=4
        ).encode('latin')
    
    def client_protocols(self, request):
        data = request.content.getvalue()
        data = json.loads(data)

        self.client_algorithm = data['algorithm']
        self.client_mode = data['mode']
        self.client_digest = data['digest']
                
        logger.info(f'Client protocols: Cipher:{self.client_algorithm}; Mode:{self.client_mode}; Digest:{self.client_digest}')
        
    def dh_public_key(self, request):
        # colocar key_size a 2048
        # p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        # g = 2
        
        data = request.content.getvalue()
        data = json.loads(data.decode('latin'))

        params_numbers = dh.DHParameterNumbers(data['p'], data['g'])
        self.dh_parameters = params_numbers.parameters(default_backend())
        
        # parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
        private_key = self.dh_parameters.generate_private_key()
        
        client_pk_b = binascii.a2b_base64(data["pk"].encode('latin'))
        
        client_public_key = serialization.load_der_public_key(client_pk_b, backend=default_backend())
        
        self.public_key_dh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # chave comum a servidor e cliente
        self.shared_key = private_key.exchange(client_public_key)
        
        logger.debug(f'Shared Key created sucessfully')
        
        # inicializar o processo de criar encriptador e decriptador
        self.get_key()
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({"key" : binascii.b2a_base64(self.public_key_dh).decode('latin').strip()}, indent=4).encode('latin')
    
    def rotate_key(self, request):
        data = request.content.getvalue()
        data = json.loads(data.decode('latin'))
        
        private_key = self.dh_parameters.generate_private_key()
        
        client_pk_b = binascii.a2b_base64(data["pk"].encode('latin'))
        
        client_public_key = serialization.load_der_public_key(client_pk_b, backend=default_backend())
        
        self.public_key_dh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.shared_key = private_key.exchange(client_public_key)
        
        logger.debug(f'Succeded at rotating key')
        
        self.get_key()
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({"key" : binascii.b2a_base64(self.public_key_dh).decode('latin').strip()}, indent=4).encode('latin')
        
        
    def get_key(self):
        if self.client_algorithm == 'AES' or self.client_algorithm == 'ChaCha20':
            self.key = self.derive_shared_key(hashes.SHA256(), 32, None, b'handshake data')
        elif self.client_algorithm == '3DES':
            self.key = self.derive_shared_key(hashes.SHA256(), 24, None, b'handshake data')
        
    def derive_shared_key(self, algorithm, length, salt, info):
        # utilizar PBKDF2HMAC talvez seja mais seguro
        derived_key = HKDF(
            algorithm=algorithm,
            length=length,
            salt=salt,
            info=info,
        ).derive(self.shared_key)
        
        return derived_key
    
    def get_iv(self, bytes_=16):
        self.iv = os.urandom(bytes_)
    
    def get_mode(self, make_iv=False):
        if self.client_algorithm == 'ChaCha20':
            self.mode = None
            return 
        if make_iv:
            if self.client_algorithm == 'AES':
                self.get_iv()
            elif self.client_algorithm == '3DES':
                self.get_iv(8)
                
        if self.client_mode == 'CBC':
            self.mode = modes.CBC(self.iv)
        elif self.client_mode == 'OFB':
            self.mode = modes.OFB(self.iv)
        elif self.client_mode == 'CFB':
            self.mode = modes.CFB(self.iv)
        elif self.client_mode == 'GCM':
            self.mode = modes.GCM(self.iv, self.tag)
    
    def get_algorithm(self):
        if self.client_algorithm == 'AES':
            self.algorithm = algorithms.AES(self.key)
        elif self.client_algorithm == 'ChaCha20':
            if not self.nonce:
                self.nonce = os.urandom(16)
            self.algorithm = algorithms.ChaCha20(self.key, self.nonce)
        elif self.client_algorithm == '3DES':
            self.algorithm = algorithms.TripleDES(self.key)
            
    def get_cipher(self):
        self.cipher = Cipher(self.algorithm, mode=self.mode, backend=default_backend())

    def get_encryptor(self):
        self.encryptor = self.cipher.encryptor()
        
    def get_decryptor(self):
        self.decryptor = self.cipher.decryptor()
        
    def get_digest(self):
        if self.client_digest == 'SHA256':
            self.digest = hashes.Hash(hashes.SHA256())
        elif self.client_digest == 'SHA512':
            self.digest = hashes.Hash(hashes.SHA512())
        elif self.client_digest == 'BLAKE2b':
            self.digest = hashes.Hash(hashes.BLAKE2b(64))
        elif self.client_digest == 'SHA3_256':
            self.digest = hashes.Hash(hashes.SHA3_256())
        elif self.client_digest == 'SHA3_512':
            self.digest = hashes.Hash(hashes.SHA3_512())
        
    def block_size(self):
        if self.client_algorithm == '3DES':
            return 8
        return 16
        
    def get_decryptor4msg(self):
        self.get_mode()
        self.get_algorithm()
        self.get_cipher()
        self.get_decryptor()
        
    def decrypt_message(self, data):
        if "tag" in data:
            self.tag = binascii.a2b_base64(data["tag"].encode('latin'))
        if "nonce" in data:
            self.nonce = binascii.a2b_base64(data["nonce"].encode('latin'))
        if "iv" in data:
            self.iv = binascii.a2b_base64(data["iv"].encode('latin'))
            
        self.get_decryptor4msg()
        
        criptogram = binascii.a2b_base64(data["msg"].encode('latin'))

        if self.client_algorithm == "ChaCha20":
            return json.loads(self.decryptor.update(criptogram).decode('latin'))

        block_size = self.block_size()
        text = b''
        last_block = criptogram[len(criptogram) - block_size :]
        criptogram = criptogram[:-block_size]
        
        while True:
            portion = criptogram[:block_size]
            if len(portion) == 0:
                dec = self.decryptor.update(last_block) + self.decryptor.finalize()
                text += dec[:block_size - dec[-1]]
                break
            
            text += self.decryptor.update(portion)
            criptogram = criptogram[block_size:]
            
        return json.loads(text.decode('latin'))
    
    def encrypt_message(self, msg):
        data = json.dumps(msg).encode('latin')

        if self.client_mode == "GCM":
            self.tag = None
            
        if self.client_algorithm == "ChaCha20":
            self.nonce = None

        self.get_mode(True)
        self.get_algorithm()
        self.get_cipher()
        self.get_encryptor()
        blocksize = self.block_size()
        
        if self.client_algorithm == "ChaCha20":
            return self.encryptor.update(data), ""

        cripto = b''
        while True:
            portion = data[:blocksize]
            if len(portion) != blocksize:
                portion = portion + bytes([blocksize - len(portion)] * (blocksize - len(portion)))
                cripto += self.encryptor.update(portion) + self.encryptor.finalize()
                break
            
            cripto += self.encryptor.update(portion)
            data = data[blocksize:]
        
        if self.client_mode == "GCM":
            return cripto, self.encryptor.tag
        
        return cripto, ""
    
    def check_integrity(self, msg, digest):
        self.get_digest()
        self.digest.update(binascii.a2b_base64(msg.encode('latin')))

        if binascii.a2b_base64(digest.encode('latin')) == self.digest.finalize():
            logger.info("A mensagem chegou sem problemas :)")
            return True
        logger.error("A mensagem foi corrompida a meio do caminho.")
        return False 

    def msg_received(self, request):
        data = request.content.getvalue()
        data = json.loads(data.decode('latin'))
        
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        
        if data['type'] == 'msg':
            if not self.check_integrity(data['msg'], data['digest']):
                return self.send_response(request, "error", {'error' : "manda isso de novo brow"})
                
            dic_text = self.decrypt_message(data)
            logger.info(f'Mensagem recebida: {dic_text}')
            
            msg = {"msg" : "A mensagem foi recebida brow."}
            
            return self.send_response(request, msg)
        
    
    def send_response(self, request, type_, resp):
        
        # logger.info(f'A enviar resposta para cliente: {resp}')
            
        cripto, tag = self.encrypt_message(resp)
        
        self.get_digest()
        self.digest.update(cripto)
        
        json_message = {
                    "type" : type_,
                    "msg" : binascii.b2a_base64(cripto).decode('latin').strip(),
                    "digest" : binascii.b2a_base64(self.digest.finalize()).decode('latin').strip()
                    }
        
        if self.client_algorithm == "ChaCha20":
            json_message["nonce"] = binascii.b2a_base64(self.nonce).decode('latin').strip()
        else:
            json_message["iv"] = binascii.b2a_base64(self.iv).decode('latin').strip()
                
            if self.client_mode == "GCM":
                json_message["tag"] = binascii.b2a_base64(tag).decode('latin').strip()
        
        return json.dumps(json_message).encode('latin')
    
    def authn_client(self, request):
        data = request.content.getvalue()
        data = json.loads(data.decode('latin'))
        return self.license(request, self.decrypt_message(data))
            

    def license(self, request, client_identifier):
        with open('licenses.json', 'r') as json_file:
            licenses = json.loads(json_file.read())
            
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
            
        with open('licenses.json', 'w') as json_file:
            json_file.write(json.dumps(licenses))
                
        return self.send_response(request, "sucess", binascii.b2a_base64(self.gen_code()).decode('latin').strip())
    
    def gen_code(self):
        code = None
        while True:
            code = os.urandom(32)
            if not code in self.client_authorizations:
                break
            
        self.client_authorizations.add(code)
        return code
        
    # Send the list of media files to clients
    def do_list(self, request):

        data = request.getHeader('Authorization')
        data = json.loads(data)
        
        # TODO este código pode ser gerado a partir dum hmac
        code = self.decrypt_message(data)
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
        return self.send_response(request, "data", media_list)


    # Send a media chunk to the client
    def do_download(self, request):
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
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            # request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return self.send_response(request, "data", {
                'media_id': media_id,
                'chunk': chunk_id,
                'data': binascii.b2a_base64(data).decode('latin').strip()
            })

        # File was not open?
        return self.send_response(request, "error", {'error': 'unknown'})
                
    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            #elif request.uri == 'api/key':
            #...
            #elif request.uri == 'api/auth':

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
            if request.path == b'/api/protocol_choice':
                self.client_protocols(request)
            elif request.path == b'/api/dh_client_public_key':
                return self.dh_public_key(request)
            elif request.path == b'/api/msg':
                return self.msg_received(request)
            elif request.path == b'/api/authn':
                return self.authn_client(request)
            elif request.path == b'/api/rotatekey':
                return self.rotate_key(request)
        
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(501)
            return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()