import PyKCS11
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

lib = '/usr/local/lib/libpteidpkcs11.so'

class HardwareToken:
    def __init__(self):
        self.session = self.open_session(self.load_card_interface_mod(lib))
        self.get_priv_key_and_mechanism()

    def close(self):
        self.session.closeSession()

    def get_priv_key_and_mechanism(self):
        self.private_key = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0]

        self.mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

    def sign(self, msg):
        return self.session.sign(self.private_key, msg, self.mechanism)

    def get_chain_certs(self):
        certs = ['CITIZEN AUTHENTICATION CERTIFICATE', 'AUTHENTICATION SUB CA', 'ROOT CA']
        return [self.get_cert(l) for l in certs]

    def get_cert(self, label):
        cert_obj = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_LABEL, label)])[0]
        return binascii.b2a_base64(bytes(self.session.getAttributeValue(cert_obj, [PyKCS11.CKA['CKA_VALUE']])[0])).decode('latin').strip()


    def load_card_interface_mod(self, lib):
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        return pkcs11

    def open_session(self, pkcs11):
        slots = pkcs11.getSlotList()
        if slots:
            return pkcs11.openSession(slots[0])
        
        print("No citizen card was provided.")
        exit(1)
        
if __name__ == '__main__':
    token = HardwareToken()

    b_cert = token.get_chain_certs()[0]

    cert = x509.load_der_x509_certificate(b_cert, backend=default_backend())

    content = b'ola            '

    signature = token.sign(content)

    try:
        result = cert.public_key().verify(
            bytes(signature),
            content,
            PKCS1v15(),
            hashes.SHA1(),
        )
        print('Assinatura válida.')
    except InvalidSignature:
        print('ERRO: Conteúdo e/ou assinatura falharam na verificação.')
    

    token.close()