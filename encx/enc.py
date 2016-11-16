from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto import Random

from getpass import getpass
import base64
import io
import os

def generate_secret_key(length=128):
    random = os.urandom(length)
    key = b64encode(random).decode('utf-8')
    return key

def generate_random_bytes(size=64):
    the_bytes = Random.new().read(size)
    return the_bytes

def to_b64_str(the_bytes, encoding='utf-8'):
    return base64.b64encode(the_bytes).decode(encoding)

def from_b64_str(string, encoding='utf-8'):
    return base64.b64decode(string.encode(encoding))

class AESScheme():
    name = 'AES'
    default_key_size = 16 # In bytes; so 16 is a 128-bit key

    @classmethod
    def generate_key(cls, key_size=None):
        if key_size is None:
            key_size = cls.default_key_size
        key = generate_random_bytes(key_size)
        return base64.b64encode(key)

    def __init__(self, metadata, key=None):
        self.metadata = metadata
        if key is None:
            key = self.generate_key()
        self.set_key(key)

    def set_key(self, key):
        if isinstance(key, str):
            self.key = from_b64_str(key)
        else:
            self.key = key

    def get_key(self):
        return to_b64_str(self.key)

    def encrypt(self, payload):
        iv = generate_random_bytes(AES.block_size)
        self.metadata['scheme'] = self.name
        self.metadata['iv'] = to_b64_str(iv)
        self.metadata['mode'] = 'CFB'
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv)
        ciphertext = self.cipher.encrypt(payload.read())
        return io.BytesIO(ciphertext)

    def decrypt(self, ciphertext):
        iv = from_b64_str(self.metadata['iv'])
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv)
        payload = self.cipher.decrypt(iv + ciphertext.read())
        payload = payload[AES.block_size:]
        return io.BytesIO(payload)

class RSAScheme():
    name = 'RSA-AES'
    cipher_name = 'PKCS#1 v1.5 OAEP'
    default_key_size = 2048

    def __init__(self, metadata, key=None):
        self.metadata = metadata
        if not key:
            key = self.generate_key()
        self._set_key(key)
        self.cipher = PKCS1_OAEP.new(self.key)

    @classmethod
    def generate_key(cls, size=None):
        if not size:
            size = cls.key_size
        new_key = RSA.generate(size)
        exported_obj = new_key.exportKey("PEM")
        return io.BytesIO(exported_obj)

    def get_key(self):
        exported_key = self.key.exportKey("PEM")
        return io.BytesIO(exported_key)

    def _set_key(self, key):
        # Get the raw key from file or file obj
        if isinstance(key, str):
            with open(key) as f:
                key_bytes = f.read()
        else:
            key_bytes = key.read()

        if 'ENCRYPTED' in key_bytes:
            passphrase = getpass('Enter the passphrase for the key: ')
        else:
            passphrase = None
        self.key = RSA.importKey(key_bytes, passphrase=passphrase)

    def encrypt(self, payload):
        aes_key = AESScheme.generate_key()
        encrypted_key = self.cipher.encrypt(aes_key)
        aes = AESScheme({}, key=aes_key)
        self.payload = aes.encrypt(payload)
        self.metadata['scheme'] = self.name
        self.metadata['cipher'] = self.cipher_name
        self.metadata['aes-mode'] = aes.metadata['mode']
        self.metadata['aes-iv'] = aes.metadata['iv']
        self.metadata['aes-key'] = to_b64_str(encrypted_key)
        return self.payload

    def decrypt(self, ciphertext):
        aes_metadata = {
            'mode': self.metadata['aes-mode'],
            'iv': self.metadata['aes-iv']
        }
        encrypted_key = from_b64_str(self.metadata['aes-key'])
        aes_key = self.cipher.decrypt(encrypted_key)
        aes = AESScheme(aes_metadata, key=aes_key)
        self.payload = aes.decrypt(ciphertext)
        return self.payload

all_schemes = [AESScheme, RSAScheme]
schemes = {scheme.name: scheme for scheme in all_schemes}
