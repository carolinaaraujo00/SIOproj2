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

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

CIPHERS = ['AES', 'ChaCha20', '3DES']
MODES = ['CBC', 'OFB', 'CFB', 'GCM']
DIGEST = ['SHA256', 'SHA512', 'SHA1', 'MD5']

class Client():
    def __init__(self):
        self.server_protocols = self.get_protocols_from_server()
        self.chosen_protocols = self.choose_protocol()
        
        # enviar para o servidor os protocolos escolhidos
        self.send_to_server(f'{SERVER_URL}/api/protocol_choice', self.chosen_protocols)
        
        self.dhe() # criar a chave publica dh para enviar ao servidor
        
        # derivar a chave partilhada de acordo com cifra utilizada
        self.get_key()
        print(len(self.key))
        
        # inicializar o modo
        self.get_mode()
        
        self.get_cipher()
        
        
    def get_protocols_from_server(self):
        req_protocols = requests.get(f'{SERVER_URL}/api/protocols')
        if req_protocols.status_code == 200:
            logger.info('Got Protocols List')

        protocols_avail = req_protocols.json()
        # print("\nAvailable protocols in the server:\n   Ciphers: " + str(protocols_avail['ciphers'])+"\n   Modes: " + str(protocols_avail['modes']) + "\n   Digests: " + str(protocols_avail['digests']) +"\n" )
        logger.info(f'Available protocols in the server:\n\tCiphers: {protocols_avail["ciphers"]}\n\tModes: {protocols_avail["modes"]}\n\tDigests: {protocols_avail["digests"]}')

        return protocols_avail
    
    def choose_protocol(self):
        ret = { k: op[random.randint(0, len(op)-1)] for k, op in self.server_protocols.items() }
        self.cipher = ret['ciphers']        
        self.mode = ret['modes']
        self.digest = ret['digests']
        logger.info(f'Protocols chosen:\n\tCipher: {ret["ciphers"]}\n\tMode: {ret["modes"]}\n\tDigest: {ret["digests"]}')
        return ret

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
        
        req = requests.get(f'{SERVER_URL}/api/get_public_key_dh')
        chunk = req.json()
        server_public_key = binascii.a2b_base64(chunk.encode('latin'))

        server_public_key = serialization.load_der_public_key(server_public_key, backend=default_backend())
        
        self.shared_key = private_key.exchange(server_public_key)
        # print(self.shared_key)

        # logger.debug(f'chave partilhada: {self.shared_key}')
        
    def get_key(self):
        if self.cipher == 'AES' or self.cipher == 'ChaCha20':
            self.key = self.derive_shared_key(hashes.SHA256(), 32, None, b'handshake data')
        elif self.cipher == '3DES':
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
    
    def get_mode(self):
        pass
    
    def get_cipher(self):
        pass
        
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