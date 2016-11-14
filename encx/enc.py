from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto import Random

import base64
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
        ciphertext = self.cipher.encrypt(payload)
        return ciphertext

    def decrypt(self, ciphertext):
        iv = from_b64_str(self.metadata['iv'])
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv)
        payload = self.cipher.decrypt(iv + ciphertext)
        payload = payload[AES.block_size:]
        return payload

all_schemes = [AESScheme]
schemes = {scheme.name: scheme for scheme in all_schemes}
