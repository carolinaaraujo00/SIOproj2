import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

SIMETRIC_CIPHERS = ['AES', 'ChaCha20', '3DES']
MODES = ['CBC', 'OFB', 'CFB', 'GCM']
ASYMMETRIC = ['RSA', 'EC']

class Client():
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        
    def dhe(self):
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.private_key = parameters.generate_private_key()
        
        # esta chave tem de ser enviada para o servido
        self.public_key = self.private_key.public_key()
        
        # depois de receber a chave privada do servidor
        peer_public_key = 0 # tem de receber a info do servidor
        
        self.shared_key = self.private_key.exchange(peer_public_key)
        
        # criptograma - cifra simetrica 
        # digest()
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        private_key_2 = parameters.generate_private_key()
        peer_public_key_2 = parameters.generate_private_key().public_key()
        shared_key_2 = private_key_2.exchange(peer_public_key_2)
        derived_key_2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key_2)
def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session
    req_protocols = requests.get(f'{SERVER_URL}/api/protocols')
    if req_protocols.status_code == 200:
        print("Got Protocols List")

    # o orlando é merda
    protocols_avail = req_protocols.json()
    print("protocols: " + str(protocols_avail['symmetric_ciphers']))
    
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
    while True:
        main()
        time.sleep(1)