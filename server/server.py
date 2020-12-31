#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math

import getpass
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


IV = b'\xb6^\xc9\xde\x1e\xe7\xa2<\x00<\x80w\x02\x1e\xee\xf7'

class MediaServer(resource.Resource):
    isLeaf = True
    def __init__(self, init_type='loaded'):
        self.name = 'SIO_Server'
        self.clients = {}

        self.can_download = set()

        self.file_encryptor = DirEncript()

        """ Usar quando ficheiros não estão cifrados """
        if init_type == 'encrypt':
            self.file_encryptor.encrypt_catalog_chunks()
            self.file_encryptor.encrypt_files()
            print('Please choose carefully the password.')
            key = self.encrypt_password()
            self.file_encryptor.save_keys_and_ivs(key, IV)
            logger.info('Files are secured')
        
        """ Quando já estiverem cifrados """
        if init_type == 'loaded':
            print('Password to decrypt files...')
            key = self.encrypt_password()
            self.file_encryptor.load_keys_and_ivs(key, IV)
            logger.info('Ready to start')
        
        """ Para decriptar os ficheiros """
        if init_type == 'decrypt':
            print('Password to decrypt files...')
            key = self.encrypt_password()
            self.file_encryptor.load_keys_and_ivs(key, IV)
            self.file_encryptor.decrypt_catalog_chunks()
            self.file_encryptor.decrypt_files()
            print('Files decrypted. Soo bye bye...')
            exit(0)
        
        self.private_key = self.get_private_key()
        
    def encrypt_password(self):
        try:
            password = getpass.getpass(prompt='Enter Password: ')
        except Exception as err:
            print('ERROR:', err)

        return self.derive_shared_key(str.encode(password), hashes.SHA256(), 32, None, b'password')
            
    def get_private_key(self):
        return serialization.load_pem_private_key(
            self.file_encryptor.decrypt_file('./certificate/SIO_ServerPK.pem'), 
            password = None,
            backend = default_backend()
        )
    
    def do_get_protocols(self, request):
        logger.debug(f'Client asked for protocols')
        msg = json.dumps(
            {
                'algorithms': ALGORITHMS, 
                'modes': MODES, 
                'digests': DIGEST
            },indent=4
        ).encode('latin')
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'msg' : msg.decode('latin'), 'signature' : binascii.b2a_base64(self.sign(msg)).decode('latin').strip()}).encode('latin')
    
    def client_protocols(self, request, data):
                
        msg = data['msg'].encode('latin')
        if not self.verify(msg, binascii.a2b_base64(data['signature'].encode('latin')), request.getHeader('id')):
            logger.error('Signature failed when checking client protocols.')

        data = json.loads(msg.decode('latin'))
        
        self.clients[request.getHeader('id')]['client_algorithm'] = data['algorithm']
        self.clients[request.getHeader('id')]['client_mode'] = data['mode']
        self.clients[request.getHeader('id')]['client_digest'] = data['digest']
        self.clients[request.getHeader('id')]['tag'] = None

        self.set_hash_algo(request.getHeader('id'))
                
        logger.info(f'{request.getHeader("id")} protocols: Cipher:{data["algorithm"]}; Mode:{data["mode"]}; Digest:{data["digest"]}')
        
    def dh_public_key(self, request, data):
        msg = data['msg'].encode('latin')
        if not self.verify(msg, binascii.a2b_base64(data['signature'].encode('latin')), request.getHeader('id')):
            logger.error('Signature failed when checking client dh public key.')

        data = json.loads(msg.decode('latin'))
        
        params_numbers = dh.DHParameterNumbers(data['p'], data['g'])
        dh_parameters = params_numbers.parameters(default_backend())
        
        self.clients[request.getHeader('id')]['dh_parameters'] = dh_parameters
        
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
        self.clients[request.getHeader('id')]['key'] = self.get_key(shared_key, request.getHeader('id'))
        self.clients[request.getHeader('id')]['last_key'] = self.clients[request.getHeader('id')]['key']
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({"key" : binascii.b2a_base64(public_key_dh).decode('latin').strip()}, indent=4).encode('latin')
    
    def rotate_key(self, request, data):
        private_key = self.clients[request.getHeader('id')]['dh_parameters'].generate_private_key()
        
        client_pk_b = binascii.a2b_base64(data["pk"].encode('latin'))
        
        client_public_key = serialization.load_der_public_key(client_pk_b, backend=default_backend())
        
        public_key_dh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        shared_key = private_key.exchange(client_public_key)
        
        logger.debug(f'Succeded at rotating key')
        self.clients[request.getHeader('id')]['last_key'] = self.clients[request.getHeader('id')]['key']
        self.clients[request.getHeader('id')]['key'] = self.get_key(shared_key, request.getHeader('id'))
        return self.send_response(request, "rotate", {"key" : binascii.b2a_base64(public_key_dh).decode('latin').strip()})
        
        
    def get_key(self, shared_key, id_):
        if self.clients[id_]['client_algorithm'] == 'AES' or self.clients[id_]['client_algorithm'] == 'ChaCha20':
            return self.derive_shared_key(shared_key, self.clients[id_]['hash'], 32, None, b'handshake data')
        elif self.clients[id_]['client_algorithm'] == '3DES':
            return self.derive_shared_key(shared_key, self.clients[id_]['hash'], 24, None, b'handshake data')
        
    def derive_shared_key(self, shared_key, algorithm, length, salt, info):
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
        
    def set_hash_algo(self, id_):
        if self.clients[id_]['client_digest'] == 'SHA256':
            self.clients[id_]['hash'] = hashes.SHA256()
        elif self.clients[id_]['client_digest'] == 'SHA512':
            self.clients[id_]['hash'] = hashes.SHA512()
        elif self.clients[id_]['client_digest'] == 'BLAKE2b':
            self.clients[id_]['hash'] = hashes.BLAKE2b(64)
        elif self.clients[id_]['client_digest'] == 'SHA3_256':
            self.clients[id_]['hash'] = hashes.SHA3_256()
        elif self.clients[id_]['client_digest'] == 'SHA3_512':
            self.clients[id_]['hash'] = hashes.SHA3_512()
        
    def get_digest(self, id_):
        return hashes.Hash(self.clients[id_]['hash'])   
        
    def get_decryptor4msg(self, tag, nonce, iv, id_):
        mode = self.get_mode(self.clients[id_]['client_mode'], iv, tag)
        algorithm = self.get_algorithm(self.clients[id_]['client_algorithm'], self.clients[id_]['key'], nonce)
        return self.get_decryptor(algorithm, mode)
        
    def block_size(self, algo):
        if algo == '3DES':
            return 8
        return 16
        
    def decrypt_message(self, data, id_):
        tag = None
        nonce = None
        iv = None
        if "tag" in data:
            tag = binascii.a2b_base64(data["tag"].encode('latin'))
        if "nonce" in data:
            nonce = binascii.a2b_base64(data["nonce"].encode('latin'))
        if "iv" in data:
            iv = binascii.a2b_base64(data["iv"].encode('latin'))
            
        decryptor = self.get_decryptor4msg(tag, nonce, iv, id_)
        
        criptogram = binascii.a2b_base64(data["msg"].encode('latin'))

        if self.clients[id_]['client_algorithm'] == "ChaCha20":
            return json.loads(decryptor.update(criptogram).decode('latin'))

        block_size = self.block_size(self.clients[id_]['client_algorithm'])
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
    
    def encrypt_message(self, msg, id_):
        data = json.dumps(msg).encode('latin')
        
        client_algo = self.clients[id_]['client_algorithm']
        client_mode = self.clients[id_]['client_mode']        
        
        nonce = None
        tag = None
        if client_algo == "ChaCha20":
            nonce = os.urandom(16)
        
        mode = None
        iv = None
        if client_algo != 'Chacha20':
            iv = self.get_iv(client_algo)
            mode = self.get_mode(client_mode, iv, None)

        if self.clients[id_]['key'] == self.clients[id_]['last_key']:
            algorithm = self.get_algorithm(client_algo, self.clients[id_]['key'], nonce)
        else:
            algorithm = self.get_algorithm(client_algo, self.clients[id_]['last_key'], nonce)

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
    
    def check_integrity(self, msg, mac, id_):
        h = hmac.HMAC(self.clients[id_]['key'], self.clients[id_]['hash'], backend = default_backend())
        h.update(binascii.a2b_base64(msg.encode('latin')))

        try:
            h.verify(binascii.a2b_base64(mac.encode('latin')))
            logger.info("Integrity of message verified :)")
            return True

        except InvalidSignature:
            logger.error("Received corrupted message :(")
            return False        
    
    def send_response(self, request, type_, resp):         
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        id_ = request.getHeader('id')
        client_algo = self.clients[id_]['client_algorithm']
        
        cripto, iv, tag, nonce  = self.encrypt_message(resp, id_)
        
        if self.clients[id_]['key'] == self.clients[id_]['last_key']:
            h = hmac.HMAC(self.clients[id_]['key'], self.clients[id_]['hash'], backend = default_backend())
        else:
            h = hmac.HMAC(self.clients[id_]['last_key'], self.clients[id_]['hash'], backend = default_backend())
            self.clients[id_]['last_key'] = self.clients[id_]['key']

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
                
            if self.clients[id_]['client_mode'] == "GCM":
                json_message["tag"] = binascii.b2a_base64(tag).decode('latin').strip()
        
        return json.dumps(json_message).encode('latin')            

    def license(self, request):
        licenses = json.loads(self.file_encryptor.decrypt_file('./licenses.json').decode())
        id_ = request.getHeader('id')

        if id_ in licenses:
            diff = datetime.fromtimestamp(time.time()) - datetime.fromisoformat(licenses[id_]['timestamp'])
            
            # verificar se a licenca expirou
            if diff.seconds/60 <= 7:
                # tem uma licenca valida
                logger.info(f'Client {id_} has license')

                self.clients[id_]['code'] = os.urandom(16)
                return self.send_response(request, "sucess", binascii.b2a_base64(self.clients[id_]['code']).decode('latin').strip())
            
            return self.send_response(request, 'error', 'The license expired.')

        return self.send_response(request, 'error', 'No license associated with this user.')
    
    def new_license(self, request):
        id_ = request.getHeader('id')

        # verificar se o user já está autenticado
        if not id_ in self.clients or not self.clients[id_]['authenticated']:
            logger.error(f'Client with id {id_} trying to get license is not authenticated.')
            return self.send_response(request, 'error', 'Unauthorized to get license. Authenticate first')
        
        # emitir uma nova licenca
        licenses = json.loads(self.file_encryptor.decrypt_file('./licenses.json').decode())
        
        licenses[id_] = {'timestamp' : datetime.fromtimestamp(time.time()).__str__()}
        logger.info(f'New license created for client {id_}')
            
        self.file_encryptor.encrypt_file('./licenses.json', json.dumps(licenses).encode())

        self.clients[id_]['code'] = os.urandom(16)
        return self.send_response(request, "sucess", binascii.b2a_base64(self.clients[id_]['code']).decode('latin').strip())
    
    
    """ Proj3 """
    def cert(self, request):
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        
        return json.dumps({'cert' : binascii.b2a_base64(self.file_encryptor.decrypt_file('./certificate/SIO_Server.crt')).decode('latin').strip(), 'server_name' : self.name}, indent=4).encode('latin')
        
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
    
    def code_verify(self, code, id_):
        h = hmac.HMAC(self.clients[id_]['key'], self.clients[id_]['hash'], backend=default_backend())
        h.update(self.clients[id_]['code'])
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
                    if self.cert_is_valid(client_chain_certs[0]):
                        logger.info(f'Valid certificate.')
                        self.clients[request.getHeader('id')] = {'cert' : client_chain_certs[0], 'authenticated' : False}
                        return json.dumps({'msg': 'Valid certificate'}).encode('latin')

    	request.setResponseCode(406)

    	logger.info('Invalid certificate.')
    	return json.dumps({'msg': 'Invalid certificate'}).encode('latin')
 
    def cert_is_valid(self, certificate):
        now = datetime.now()
        logger.info(f'Certificate validity: valid not before {certificate.not_valid_before} and not after {certificate.not_valid_after}')
        if certificate.not_valid_before < now and now < certificate.not_valid_after:
            logger.info('Valid certificate')
            return True
        return False
    
    def verify(self, msg, signature, id_):
        try:
            result = self.clients[id_]['cert'].public_key().verify(
                signature,
                msg,
                PKCS1v15(),
                hashes.SHA1(),
            )
            logger.info('Valid signature.')
        except InvalidSignature:
            logger.error('ERROR: Invalid signature.')
            return False

        return True
        
    def challenge(self, request, data):
        id_ = request.getHeader('id')
        request.requestHeaders.addRawHeader(b'content-type', b'application/json')

        msg = binascii.a2b_base64(data['msg'].encode('latin'))
                
        if not self.verify(msg, binascii.a2b_base64(data['signature'].encode('latin')), id_):
            request.setResponseCode(400)
            return json.dumps({'msg' : 'Signature failed'}).encode('latin')

        sign_challenge = self.sign(msg)
        
        server_challenge = os.urandom(16)
        self.clients[id_]['server_challenge'] = server_challenge
        
        msg = {'signed_challenge' : binascii.b2a_base64(sign_challenge).decode('latin').strip(), 'server_challenge' : binascii.b2a_base64(server_challenge).decode('latin').strip()}
        msg = json.dumps(msg).encode('latin')
                
        return json.dumps({'msg' : binascii.b2a_base64(msg).decode('latin').strip(), 'signature' : binascii.b2a_base64(self.sign(msg)).decode('latin').strip()}).encode('latin')

    def authenticate(self, request, data):
        id_ = request.getHeader('id')

        signed_challenge = binascii.a2b_base64(data['signed_challenge'].encode('latin'))
        if not self.verify(signed_challenge, binascii.a2b_base64(data['signature'].encode('latin')), id_):
            return
        
        if self.verify(self.clients[id_]['server_challenge'], signed_challenge, id_):
            logger.info('Client signed correctly the challenge.')
            self.clients[id_]['authenticated'] = True
        else:
            logger.info('The verification of the signed challenge failed.')    
   
    # Send the list of media files to clients
    def do_list(self, request):
    
        data = request.getHeader('Authorization')
        data = json.loads(data)
        
        code = self.decrypt_message(data, request.getHeader('id'))
        code = binascii.a2b_base64(code.encode('latin'))
        
        if not self.code_verify(code, request.getHeader('id')):
           request.setResponseCode(401)
           return self.send_response(request, "error", {'error': 'Not authorized'})

        self.can_download.add(request.getHeader('id'))

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
        if not request.getHeader('id') in self.can_download:
            request.setResponseCode(401)
            logger.error(f'{request.getHeader("id")} is not authorized to do download.')
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
            self.can_download.remove(request.getHeader('id'))

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
        if not request.getHeader('id') in self.clients:
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
                data = json.loads(content.decode('latin'))
                self.client_protocols(request, data)
            elif request.path == b'/api/dh_client_public_key':
                data = json.loads(content.decode('latin'))
                return self.dh_public_key(request, data)
            elif request.path == b'/api/license':
                data = json.loads(content.decode('latin'))
                return self.license(request)
            elif request.path == b'/api/rotatekey':
                data = json.loads(content.decode('latin'))
                if not self.check_integrity(data['msg'], data['mac'], request.getHeader('id')):
                    return self.send_response(request, "error", {'error': 'Corrupted Message'})
                data = self.decrypt_message(data, request.getHeader('id'))
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