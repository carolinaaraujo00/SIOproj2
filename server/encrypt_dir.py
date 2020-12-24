from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import scandir

class DirEncript:
    def __init__(self, key, iv):
        # self.key = key 32 bytes
        # self.iv = iv 16
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

        self.encrypt_files()
        
    # encriptar todos os ficheiros
    def encrypt_files(self):
        files = [f.path for f in scandir('./catalog/')]
        files.extend([f.path for f in scandir('./certificate/')])
        files.append('./licenses.json')
        for f in files:
            with open(f, 'rb') as file_:
                enc_data = self.encrypt(file_.read())
                
            with open(f, 'wb') as file_:
                file_.write(enc_data)
                
    # decrypt de todos os ficheiros
    def decrypt_files(self):
        files = [f.path for f in scandir('./catalog/')]
        files.extend([f.path for f in scandir('./certificate/')])
        files.append('./licenses.json')
        for f in files:
            with open(f, 'rb') as file_:
                dec_data = self.decrypt(file_.read())
                
            with open(f, 'wb') as file_:
                file_.write(dec_data)
                
    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as f:
            return self.decrypt(f.read())
        
    def encrypt_file(self, file_name, text):
        with open(file_name, 'wb') as f:
            f.write(text)
        

    def encrypt(self, data):
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
    
# from os import urandom
# if __name__ == '__main__':
#     app = DirEncript(urandom(32), urandom(16))