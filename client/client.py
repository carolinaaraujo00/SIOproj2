import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import random

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

ALGORITHMS = ['AES', 'ChaCha20', '3DES']
MODES = ['CBC', 'OFB', 'CFB', 'GCM']
DIGEST = ['SHA256', 'SHA512', 'BLAKE2b', 'SHA3_256', 'SHA3_512']

class Client():
    def __init__(self):
        
        self.ip = f'{random.randrange(256)}.{random.randrange(256)}.{random.randrange(256)}.{random.randrange(256)}'
        
        if not self.trust_server():
            logger.error('Certificate of http server is not trusted')
            sys.exit(1)
            
        logger.info('Certificate of http server is trusted')
                
        self.tag = None
        self.chosen_mode = None
        self.server_protocols = self.get_protocols_from_server()
        chosen_protocols = self.choose_protocol()
        
        # enviar para o servidor os protocolos escolhidos
        self.send_to_server(f'{SERVER_URL}/api/protocol_choice', chosen_protocols)
        
        self.set_hash_algo()
        
        # criar a chave publica dh para enviar ao servidor
        self.dhe() 
        
        # derivar a chave partilhada de acordo com cifra utilizada
        self.get_key()
        
        data = self.authn()
        self.code = binascii.a2b_base64(self.decrypt_message(data).encode('latin'))
        
    
    # TODO alterar
    def authn(self):
        username = input('\nusername: ')
        return self.send_msg('auth', f'{SERVER_URL}/api/authn', username)

    def get_protocols_from_server(self):
        req_protocols = requests.get(f'{SERVER_URL}/api/protocols')
        if req_protocols.status_code == 200:
            logger.info('Got Protocols List')

        protocols_avail = req_protocols.json()
        logger.info(f'Available protocols in the server:\n\Algorithms: {protocols_avail["algorithms"]}\n\tModes: {protocols_avail["modes"]}\n\tDigests: {protocols_avail["digests"]}')

        return protocols_avail
    
    def choose_protocol(self):
        matching_algorithms = [alg for alg in self.server_protocols['algorithms'] if alg in ALGORITHMS]
        matching_modes = [mode for mode in self.server_protocols['modes'] if mode in MODES]
        matching_digests = [dig for dig in self.server_protocols['digests'] if dig in DIGEST]
        
        self.chosen_algorithm = self.choose_cycle('What algorithm would you like to use? ', matching_algorithms)
        
        if self.chosen_algorithm != 'ChaCha20':
            if self.chosen_algorithm == '3DES':
                if 'GCM' in matching_modes:
                    matching_modes.remove('GCM')
            self.chosen_mode = self.choose_cycle('What mode would you like to use? ', matching_modes)
        
        self.chosen_digest = self.choose_cycle('What digest would you like to use? ', matching_digests)
                
        logger.info(f'Protocols chosen:\n\tAlgorithm: {self.chosen_algorithm}\n\tMode: {self.chosen_mode}\n\tDigest: {self.chosen_digest}')
        return {'algorithm' : self.chosen_algorithm, 'mode' : self.chosen_mode, 'digest' : self.chosen_digest}
    
    def choose_cycle(self, msg, list_):
        print('###############################')
        
        for i in range(len(list_)):
            print(f'{i} -- {list_[i]}')
        print('..............................')
        selection = None
        while True:
            selection = input(msg)

            if not selection.isdigit():
                continue
            
            selection = int(selection)
            if 0 <= selection < len(list_):
                break
        print('###############################')            
        return list_[selection]
        
    def send_to_server(self, uri, msg, bytes_=False, encript=True):
        
        if bytes_:
            data = msg
        else:
            data = json.dumps(msg, indent=4).encode('latin')
        
        print(data)
        if encript:
            data = self.cert.public_key().encrypt(data, 
                        padding = padding.OAEP(
                            mgf=padding.MGF1(algorithm=self.cert.signature_hash_algorithm),
                            algorithm=self.cert.signature_hash_algorithm,
                            label=None
                        )
                    )        
        return requests.post(uri, data = data, headers={'ip' : self.ip})
        
    def dhe(self):
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2

        params_numbers = dh.DHParameterNumbers(p,g)
        self.dh_parameters = params_numbers.parameters(default_backend())
        
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        
        data = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        msg = {
            "p" : p,
            "g" : g,
            "pk" : binascii.b2a_base64(data).decode('latin').strip()
        }
        # enviar chave publica dh para o servidor        
        request = self.send_to_server(f'{SERVER_URL}/api/dh_client_public_key', msg, False, False)
        server_public_key = binascii.a2b_base64(request.json()['key'].encode('latin'))
        
        server_public_key = serialization.load_der_public_key(server_public_key, backend=default_backend())
        
        self.shared_key = private_key.exchange(server_public_key)

        logger.info('Shared Key created sucessfully')
        
    def rotate_key(self):
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        
        data = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        msg = {"pk" : binascii.b2a_base64(data).decode('latin').strip()}
        request = self.send_to_server(f'{SERVER_URL}/api/rotatekey', msg, False, False)
        
        server_public_key = binascii.a2b_base64(request.json()['key'].encode('latin'))
        server_public_key = serialization.load_der_public_key(server_public_key, backend=default_backend())
        
        self.shared_key = private_key.exchange(server_public_key)
        logger.info('Succeded at rotating key')
        
        self.get_key()
        
    def get_key(self):
        if self.chosen_algorithm == 'AES' or self.chosen_algorithm == 'ChaCha20':
            self.key = self.derive_shared_key(self.hash_, 32, None, b'handshake data')
        elif self.chosen_algorithm == '3DES':
            self.key = self.derive_shared_key(self.hash_, 24, None, b'handshake data')
        
    def derive_shared_key(self, algorithm, length, salt, info):
        # TODO utilizar PBKDF2HMAC talvez seja mais seguro
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
        if self.chosen_algorithm == 'ChaCha20':
            self.mode = None
            return
        if make_iv:
            if self.chosen_algorithm == 'AES':
                self.get_iv()
            elif self.chosen_algorithm == '3DES':
                self.get_iv(8)
                
        if self.chosen_mode == 'CBC':
            self.mode = modes.CBC(self.iv)
        elif self.chosen_mode == 'OFB':
            self.mode = modes.OFB(self.iv)
        elif self.chosen_mode == 'CFB':
            self.mode = modes.CFB(self.iv)
        elif self.chosen_mode == 'GCM':
            self.mode = modes.GCM(self.iv, self.tag)
    
    def get_algorithm(self):
        if self.chosen_algorithm == 'AES':
            self.algorithm = algorithms.AES(self.key)
        elif self.chosen_algorithm == 'ChaCha20':
            if not self.nonce:
                self.nonce = os.urandom(16)
            self.algorithm = algorithms.ChaCha20(self.key, self.nonce)
        elif self.chosen_algorithm == '3DES':
            self.algorithm = algorithms.TripleDES(self.key)
            
    def get_cipher(self):
        if self.chosen_algorithm == 'ChaCha20':
            pass
        self.cipher = Cipher(self.algorithm, self.mode, default_backend())
        
    def get_encryptor(self):
        self.encryptor = self.cipher.encryptor()
        
    def get_decryptor(self):
        self.decryptor = self.cipher.decryptor()
        
    def set_hash_algo(self):
        if self.chosen_digest == 'SHA256':
            self.hash_ = hashes.SHA256()
        elif self.chosen_digest == 'SHA512':
            self.hash_ = hashes.SHA512()
        elif self.chosen_digest == 'BLAKE2b':
            self.hash_ = hashes.BLAKE2b(64)
        elif self.chosen_digest == 'SHA3_256':
            self.hash_ = hashes.SHA3_256()
        elif self.chosen_digest == 'SHA3_512':
            self.hash_ = hashes.SHA3_512()
            
    def get_digest(self):
        self.digest = hashes.Hash(self.hash_)
    
    def get_decryptor4msg(self):
        self.get_mode()
        self.get_algorithm()
        self.get_cipher()
        self.get_decryptor()
        
    def block_size(self):
        if self.chosen_algorithm == '3DES':
            return 8
        return 16
            
    def encrypt_message(self, msg):
        data = json.dumps(msg).encode('latin')
        
        if self.chosen_mode == "GCM":
            self.tag = None
            
        if self.chosen_algorithm == "ChaCha20":
            self.nonce = None
        
        self.get_mode(True)
        self.get_algorithm()
        self.get_cipher()
        self.get_encryptor()
        blocksize = self.block_size()
        
        if self.chosen_algorithm == "ChaCha20":
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
            
            # se o modo for GCM
        if self.chosen_mode == "GCM":
            return cripto, self.encryptor.tag
        
        
        return cripto, ""
    
    def decrypt_message(self, data):
        if "tag" in data:
            self.tag = binascii.a2b_base64(data["tag"].encode('latin'))
        if "nonce" in data:
            self.nonce = binascii.a2b_base64(data["nonce"].encode('latin'))
        if "iv" in data:
            self.iv = binascii.a2b_base64(data["iv"].encode('latin'))
        
        
        self.get_decryptor4msg()     
        
        criptogram = binascii.a2b_base64(data["msg"].encode('latin'))

        if self.chosen_algorithm == "ChaCha20":
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
        
        
    # TODO mudar nome da funcao para ficar em conformidade com o facto de encriptar headers
    def send_msg(self, type_, url, msg):
        logger.info(f'A enviar mensagem para servidor: {msg}')
        criptogram, tag = self.encrypt_message(msg)
        
        h = hmac.HMAC(self.key, self.hash_, backend = default_backend())
        h.update(criptogram)
        
        json_message = {
            "type" : type_,
            "msg" : binascii.b2a_base64(criptogram).decode('latin').strip(),
            "mac" : binascii.b2a_base64(h.finalize()).decode('latin').strip()
        }
        
        if self.chosen_algorithm == "ChaCha20":
            json_message["nonce"] = binascii.b2a_base64(self.nonce).decode('latin').strip()
        else:
            json_message["iv"] = binascii.b2a_base64(self.iv).decode('latin').strip()
                
            if self.chosen_mode == "GCM":
                json_message["tag"] = binascii.b2a_base64(tag).decode('latin').strip()
                
        # retornar o dicionario caso se trate de encriptar um param do header http
        if type_ == "header":
            return json.dumps(json_message)
                    
        req = self.send_to_server(url, json_message, False, False)
        
        if req.status_code == 200:
            return req.json()
        else:
            logger.error('A resposta do servidor na foi ok')
            
    def check_integrity(self, msg, mac):
        h = hmac.HMAC(self.key, self.hash_, backend = default_backend())
        h.update(binascii.a2b_base64(msg.encode('latin')))

        try:
            h.verify(binascii.a2b_base64(mac.encode('latin')))
            logger.info("A mensagem chegou sem problemas :)")
            return True

        except InvalidSignature:
            logger.error("A mensagem foi corrompida a meio do caminho.")
            return False
            
    def msg_received(self, data):        
        if not self.check_integrity(data['msg'], data['mac']):
            return None
        
        if data['type'] == "data_list":
            return self.decrypt_message(data)
        elif data['type'] == 'data_download':
            data = self.decrypt_message(data)
            
            # verificar a assinatura
            if not self.verify_chunk(binascii.a2b_base64(data['data'].encode('latin')), binascii.a2b_base64(data['signature'].encode('latin'))):
                return None
            return data
        elif data['type'] == "error":
            return self.decrypt_message(data)['error']
        else:
            return f'Recebi um tipo de dados desconhecido: {data}'
        
    """ Proj3 """
    def trust_server(self):
        response = requests.get(f'{SERVER_URL}/api/cert')
        cert = binascii.a2b_base64(response.json()['cert'].encode('latin'))
        self.cert = x509.load_pem_x509_certificate(cert, backend = default_backend())

        # TODO fazer corrente de CA's
        for c in self.trusted_ca():
            if self.cert.issuer == c.subject:
                return True
        
        return False

    def trusted_ca(self):
        ret = []
        for f in os.scandir('./trusted_ca'):
            with open(f.path, 'rb') as file_:
                ret.append(x509.load_pem_x509_certificate(file_.read(), backend = default_backend()))
                
        return ret
    
    def verify_chunk(self, data, signature):
        try:
            self.cert.public_key().verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            logger.error('Signature of chunk not valid')
            return False
        
        return True
        
        
    
def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session "11.28.242.121"
    client = Client()

    # TODO encriptar o codigo client.code
    req = requests.get(f'{SERVER_URL}/api/list', headers={'ip' : client.ip, 'Authorization' : client.send_msg("header", None, binascii.b2a_base64(client.code).decode('latin').strip())})
    if req.status_code == 200:
        print("Got Server List")
    
    media_list = client.msg_received(req.json())
    

    # Present a simple selection menu    
    print("MEDIA CATALOG\n")
        
    if not media_list:
        return 
    for i, item in enumerate(media_list):
        print(f'{i} - {item["name"]}')
    print("----")


    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    
    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        # rodar chave a cada 10 chunks
        if chunk%10 == 0:
            client.rotate_key()
        
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}', headers={'ip' : client.ip, 'Authorization' : client.send_msg("header", None, binascii.b2a_base64(client.code).decode('latin').strip())})
        # req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}', headers={'Authorization' : client.send_msg("header", None, binascii.b2a_base64(b'error').decode('latin').strip())})

        if req.status_code == 401:
            logger.error('License was not accepted')
            proc.kill()
            break
        
        chunk = client.msg_received(req.json())
        
        try:
            data = binascii.a2b_base64(chunk['data'].encode('latin'))
            proc.stdin.write(data)
        except:
            logger.info('Ending client session...')
            proc.kill()
            break
    
def continue_():
    ret = None
    while True:
        choice = input("You desire to continue(y/n)? ")
        if choice.strip().lower() == 'y':
            ret = True
            break
        elif choice.strip().lower() == 'n':
            ret = False
            break
        else:
            print(f'Invalid choice ({choice}), please choose between y/n.')
    return ret

if __name__ == '__main__':
    # app = Client()
    while True:
        main()
        time.sleep(1)
        if not continue_():
            print('Bye')
            break