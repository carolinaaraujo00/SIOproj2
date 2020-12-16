import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

ALGORITHMS = ['AES', 'ChaCha20', '3DES']
MODES = ['CBC', 'OFB', 'CFB', 'GCM']
DIGEST = ['SHA256', 'SHA512', 'SHA1', 'MD5']

class Client():
    def __init__(self):
        self.server_protocols = self.get_protocols_from_server()
        self.chosen_protocols = self.choose_protocol()
        
        # enviar para o servidor os protocolos escolhidos
        self.send_to_server(f'{SERVER_URL}/api/protocol_choice', self.chosen_protocols)
        
        # criar a chave publica dh para enviar ao servidor
        self.dhe() 
        
        # derivar a chave partilhada de acordo com cifra utilizada
        
        self.get_key()
        
        response = self.send_msg("msg", {"carolina" : "ola orlando espero que esteja tudo bem obrigada por teres feito o trabalho todo", 
                              "orlando" : "ser ou n ser eis a questao"})
        
        text = self.decrypt_message(response['msg'], response['iv'])
        logger.info(f'Resposta recebida do servidor: {text}')
        
        # GCM(iv)
        # associated_data = autor
        # encryptor.authenticate_additional_data(associated_data)
        # encryptor.tag
        # GCM(iv, tag)
        # decryptor.authenticate_additional_data(associated_data)        
        
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
        # self.chosen_algorithm = 'AES'
        # ret['algorithms'] = self.chosen_algorithm
        self.chosen_mode = self.choose_cycle('What mode would you like to use? ', matching_modes)
        # self.chosen_mode = 'CBC'
        # ret['modes'] = self.chosen_mode
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
        
    def send_to_server(self, uri ,msg, bytes_=False):
        if bytes_:
            return requests.post(uri, data = msg)
        return requests.post(uri, data = json.dumps(msg, indent=4).encode('latin'))
        
    def dhe(self):
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2

        params_numbers = dh.DHParameterNumbers(p,g)
        parameters = params_numbers.parameters(default_backend())
        
        # parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        data = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # enviar chave publica dh para o servidor        
        request = self.send_to_server(f'{SERVER_URL}/api/dh_client_public_key', data, True)
        server_public_key = binascii.a2b_base64(request.json()['key'].encode('latin'))
        
        server_public_key = serialization.load_der_public_key(server_public_key, backend=default_backend())
        
        self.shared_key = private_key.exchange(server_public_key)

        logger.info('Shared Key created sucessfully')
        
    def get_key(self):
        if self.chosen_algorithm == 'AES' or self.chosen_algorithm == 'ChaCha20':
            self.key = self.derive_shared_key(hashes.SHA256(), 32, None, b'handshake data')
        elif self.chosen_algorithm == '3DES':
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
    
    def get_mode(self, iv=False, tag=None):
        if self.chosen_algorithm == 'ChaCha20':
            self.mode = None
        if not iv:
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
            self.mode = modes.GCM(self.iv, tag)
    
    def get_algorithm(self):
        if self.chosen_algorithm == 'AES':
            self.algorithm = algorithms.AES(self.key)
        elif self.chosen_algorithm == 'ChaCha20':
            self.nonce = os.urandom(16)
            self.algorithm = algorithms.ChaCha20(self.key, self.nonce)
        elif self.chosen_algorithm == '3DES':
            self.algorithm = algorithms.TripleDES(self.key)
            
    def get_cipher(self):
        if self.chosen_algorithm == 'ChaCha20':
            self.cipher = Cip
        self.cipher = Cipher(self.algorithm, self.mode, default_backend())
        
    def get_encryptor(self):
        self.encryptor = self.cipher.encryptor()
        
    def get_decryptor(self):
        self.decryptor = self.cipher.decryptor()
    
    def get_decryptor_w_iv(self, iv):
        self.iv = iv
        self.get_mode(iv=True)
        self.get_algorithm()
        self.get_cipher()
        self.get_decryptor()
        
    def block_size(self):
        if self.chosen_algorithm == '3DES':
            return 8
        return 16
            
    def encrypt_message(self, msg):
        data = json.dumps(msg)
        self.get_mode()
        self.get_algorithm()
        self.get_cipher()
        self.get_encryptor()
        blocksize = self.block_size()

        cripto = b''
        while True:
            portion = data[:blocksize]
            if len(portion) != blocksize:
                portion = str.encode(portion) + bytes([blocksize - len(portion)] * (blocksize - len(portion)))
                cripto += self.encryptor.update(portion) + self.encryptor.finalize()
                break
            
            cripto += self.encryptor.update(str.encode(portion))
            data = data[blocksize:]
        
        return cripto
    
    def decrypt_message(self, msg, iv=None):
        if iv:
            self.get_decryptor_w_iv(binascii.a2b_base64(iv.encode('latin')))
        
        criptogram = binascii.a2b_base64(msg.encode('latin'))
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
            
        text = json.loads(text)
        return text
        
    def send_msg(self, type_, msg):
        logger.info(f'A enviar mensagem para servidor: {msg}')
        criptogram = self.encrypt_message(msg)
        req = self.send_to_server(f'{SERVER_URL}/api/msg',
                            {"type" : type_,"msg": binascii.b2a_base64(criptogram).decode('latin').strip(), "iv": binascii.b2a_base64(self.iv).decode('latin').strip()})
        
        if req.status_code == 200:
            return req.json()
        else:
            logger.error('Não houve json de resposta por parte do servidor')
            
            
            
            
            
            
            
        
def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session

    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")
        
    media_list = req.json()

    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
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
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break
        
if __name__ == '__main__':
    client = Client()
    # while True:
    #     main()
    #     time.sleep(1)