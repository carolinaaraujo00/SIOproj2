from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import scandir, urandom, remove, mkdir
from math import ceil
import json
import binascii

BASEDIR = './catalog/chunks/'
CHUNK_SIZE = 1024

class DirEncript:
    def __init__(self, keysAndIvs=None):
        self.keysAndIvs = dict()
                
    @property
    def get_keysAndIvs(self):
        return self.keysAndIvs
    
    # salvar localmente as chaves
    def save_keys_and_ivs(self, key, iv):
        self.key = key
        self.iv = iv
        save = {f:{'key':binascii.b2a_base64(v['key']).decode('latin').strip(),
                   'iv':binascii.b2a_base64(v['iv']).decode('latin').strip()}
                for f, v in self.keysAndIvs.items()}
        with open('./static/infos', 'wb') as f:
            f.write(self.encrypt(json.dumps(save).encode()))

    # dar load das chaves salvas
    def load_keys_and_ivs(self, key, iv):
        self.key = key
        self.iv = iv
        with open('./static/infos', 'rb') as f:
            load = json.loads(self.decrypt(f.read()).decode())

        self.keysAndIvs = {f:{'key':binascii.a2b_base64(v['key'].encode('latin')),
                   'iv':binascii.a2b_base64(v['iv'].encode('latin'))}
                for f, v in load.items()}
                        
    def new_encryptor(self):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        self.encryptor = cipher.encryptor()
        
    def new_decryptor(self):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        self.decryptor = cipher.decryptor()

    # encriptar todos os ficheiros
    def encrypt_files(self):
        files = [f.path for f in scandir('./certificate/')]
        files.extend([f.path for f in scandir('./trusted_cas')])
        files.append('./licenses.json')
        for f in files:
            self.key = urandom(32)
            self.iv = urandom(16)
            
            self.keysAndIvs[f] = {'key' : self.key, 'iv' : self.iv}
            
            print(f'Encrypting {f}.')
            with open(f, 'rb') as file_:
                enc_data = self.encrypt(file_.read())
                
            with open(f, 'wb') as file_:
                file_.write(enc_data)
                
    def encrypt_catalog_chunks(self):
        try:
            mkdir(BASEDIR)
        except FileExistsError:
            print(f'{BASEDIR} already exists')
            
        for f in scandir('./catalog'):
            if f.is_dir():
                continue
            
            file_n = f'{BASEDIR}{f.path.split("/")[-1].split(".")[0]}'
            
            self.key = urandom(32)
            self.iv = urandom(16)
            
            self.keysAndIvs[file_n] = {'key' : self.key, 'iv' : self.iv}
            
            chunks = ceil(f.stat().st_size / CHUNK_SIZE)
            
            offset = 0
            with open(f.path, 'rb') as file_:
                print(f'Encrypting {f.path} with {chunks} chunks.')
                for i in range(chunks + 1):
                    with open(f'{BASEDIR}{f.path.split("/")[-1].split(".")[0]}#{offset}', 'wb') as fwr:
                        fwr.write(self.encrypt(file_.read(CHUNK_SIZE)))
                        
                    offset += CHUNK_SIZE

            remove(f.path)

    def decrypt_catalog_chunks(self):
        files = []
        for f in scandir(BASEDIR):
            file_n = f.path.split('/')[-1].split('#')[0]
            if not file_n in files:
                files.append(file_n)
                
        for file in files:
            offset = 0
            b = b''
            
            print(f'Decrypting {file}...')
            self.key = self.keysAndIvs[f'./catalog/chunks/{file}']['key']
            self.iv = self.keysAndIvs[f'./catalog/chunks/{file}']['iv']
            while True:
                try:
                    file_path = f'{BASEDIR}{file}#{offset}'
                    with open(file_path, 'rb') as f:
                        b += self.decrypt(f.read())
                except FileNotFoundError:
                    break
                remove(file_path)

                offset += CHUNK_SIZE
                
            with open(f'./catalog/{file}.mp3', 'wb') as fwr:
                fwr.write(b)
            
    def decrypt_files(self):
        files = [f.path for f in scandir('./certificate/')]
        files.extend([f.path for f in scandir('./trusted_cas')])
        files.append('./licenses.json')
        for f in files:
            print(f'Decrypting {f}...')
            self.key = self.keysAndIvs[f]['key']
            self.iv = self.keysAndIvs[f]['iv']
            
            with open(f, 'rb') as file_:
                dec_data = self.decrypt(file_.read())
                
            with open(f, 'wb') as file_:
                file_.write(dec_data)
                                
    def decrypt_file(self, file_name):
        if 'chunks' in file_name:
            self.key = self.keysAndIvs[file_name.split('#')[0]]['key']
            self.iv = self.keysAndIvs[file_name.split('#')[0]]['iv']
        else:
            self.key = self.keysAndIvs[file_name]['key']
            self.iv = self.keysAndIvs[file_name]['iv']

        with open(file_name, 'rb') as f:
            return self.decrypt(f.read())
        
    def encrypt_file(self, file_name, text):
        self.key = self.keysAndIvs[file_name]['key']
        self.iv = self.keysAndIvs[file_name]['iv']

        with open(file_name, 'wb') as f:
            f.write(self.encrypt(text))
        

    def encrypt(self, data):
        self.new_encryptor()
        blocksize = 16
        cripto = b''
        while True:
            portion = data[:blocksize]
            if len(portion) != blocksize:
                portion = portion + bytes([blocksize - len(portion)] * (blocksize - len(portion)))
                cripto += self.encryptor.update(portion) + self.encryptor.finalize()
                break
            
            cripto += self.encryptor.update(portion)
            data = data[blocksize:]
                
        return cripto
    
    def decrypt(self, criptogram):
        self.new_decryptor()
        block_size = 16
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
            
        return text
    
if __name__ == '__main__':

    app = DirEncript()
    # app.encrypt_catalog_chunks()
    # app.encrypt_files()
    app.decrypt_catalog_chunks()
