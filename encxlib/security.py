from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.exceptions import InvalidSignature


from getpass import getpass
from uuid import uuid4
import binascii
import logging
import base64
import stat
import sys
import io
import os


class SecurityError(ValueError):
    pass

def load_rsa_key(source, path=True, passphrase=None):
    if path:
        key_contents = read_private_path(source)
    else:
        key_contents = source
    if 'ENCRYPTED' in key_contents:
        if passphrase is None:
            passphrase = getpass('Enter the passphrase for "{}": '.format(source))
    
    return RSA(key_contents, passphrase).get_private_key()

def generate_uuid():
    return str(uuid4())

def hasher(data, raw=False):
    if isinstance(data, str):
        data = data.encode('utf-8')

    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(data)
    digest = hasher.finalize()
    if raw:
        return digest
    else:
        return binascii.hexlify(digest).decode('utf-8')

def generate_random_bytes(size=64):
    return os.urandom(size)

def generate_int(start=0, end=sys.maxsize):
    """ inclusive to exclusive """
    delta = end - start
    random_int = int.from_bytes(generate_random_bytes(20), byteorder="big")
    number = (random_int % delta) + start
    return number

def random_choice(items):
    index = generate_int(end=len(items))
    return items[index]

def generate_secret_key(length=128):
    random = generate_random_bytes(length)
    key = b64encode(random).decode('utf-8')
    return key

def to_b64_str(the_bytes, encoding='utf-8'):
    return base64.b64encode(the_bytes).decode(encoding)

def from_b64_str(string, encoding='utf-8'):
    return base64.b64decode(string.encode(encoding))

class AES():
    name = 'AES'
    cipher_name = 'AES::CFB'
    block_size = 16 # In bytes; so 16 is a 128-bit key
    default_key_size = block_size

    @classmethod
    def generate_key(cls, key_size=None):
        if key_size is None:
            key_size = cls.default_key_size
        key = generate_random_bytes(key_size)
        return to_b64_str(key)

    def __init__(self, key=None):
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

    def _cipher(self, iv):
        return ciphers.Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend()
        )

    def encrypt(self, payload):
        iv = generate_random_bytes(self.block_size)
        cipher = ciphers.Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        metadata = {}
        metadata['cipher'] = self.name
        metadata['key_size'] = len(self.key) * 8
        metadata['iv'] = to_b64_str(iv)
        metadata['mode'] = 'CFB'
        return ciphertext, metadata

    def decrypt(self, ciphertext, iv):
        iv = from_b64_str(iv)
        cipher = self._cipher(iv)
        decryptor = cipher.decryptor()
        payload = decryptor.update(ciphertext) + decryptor.finalize()
        return payload

class RSA():
    name = 'RSA'
    cipher_name = 'RSAES-OAEP::SHA256'
    default_key_size = 2048
    public_exponent = 65537

    def __init__(self, key=None, passphrase=None):
        self._private = None
        self._public = None
        self._set_key(key, passphrase=passphrase)

    @classmethod
    def generate_key(cls, size=None):
        if not size:
            size = cls.default_key_size
        private_key = rsa.generate_private_key(
            public_exponent=cls.public_exponent,
            key_size=size,
            backend=default_backend(),
        )
        exported = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')
        return exported

    def _set_key(self, key, passphrase=None):
        key = key.encode('utf-8')
        if b'PUBLIC' in key: # Is there a better test? pro detection for sure
            self._public = serialization.load_pem_public_key(
                key,
                backend=default_backend(),
            )
        else:
            if passphrase:
                passphrase = passphrase.encode('utf-8')
            self._private = serialization.load_pem_private_key(
                key,
                password=passphrase,
                backend=default_backend(),
            )

    def _get_public_key(self):
        if not self._public:
            if not self._private:
                raise ValueError('Unable to get a public key, no key information')
            self._public = self._private.public_key()
        return self._public

    def _get_private_key(self):
        if not self._private:
            raise ValueError('Private key information unavailable')
        return self._private

    def get_private_key(self, passphrase=None):
        options = {
            'encoding': serialization.Encoding.PEM,
            'format': serialization.PrivateFormat.PKCS8,
        }
        if passphrase:
            options['encryption_algorithm'] = serialization.BestAvailableEncryption(
                passphrase.encode('utf-8'),
            )
        else:
            options['encryption_algorithm'] = serialization.NoEncryption()
        exported = self._get_private_key().private_bytes(**options).decode('utf-8')
        return exported

    def get_public_key(self):
        public_key = self._get_public_key()
        exported = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return exported

    def get_fingerprint(self, size=32):
        public_key = self._get_public_key()
        exported = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hasher(exported)[:size]
        parts = [digest[i * 2:i * 2 + 2] for i in range(size // 2)] 
        fingerprint = ':'.join(parts)
        return fingerprint

    def sign(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        signer = self._get_private_key().signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signer.update(data)
        signature = signer.finalize()
        return to_b64_str(signature)

    def verify(self, data, signature):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(signature, str):
            signature = from_b64_str(signature)
        public_key = self._get_public_key()
        verifier = public_key.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verifier.update(data)
        try:
            verifier.verify()
        except InvalidSignature:
            return False
        return True

    def encrypt(self, payload):
        public_key = self._get_public_key()
        ciphertext = public_key.encrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        metadata = {}
        metadata['cipher'] = self.cipher_name
        metadata['padding'] = 'OAEP'
        return ciphertext, metadata

    def decrypt(self, ciphertext, metadata=None):
        plaintext = self._get_private_key().decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

PRIVATE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # This is 0o600 in octal
PRIVATE_DIR_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR  # This is 0o700 in octal

def make_private_dir(path):
    os.makedirs(path, mode=PRIVATE_DIR_MODE, exist_ok=False)

def remove_path(path, is_dir=False):
    path = os.path.expanduser(path)
    if is_dir:
        shutil.rmtree(path)
    else:
        os.remove(path)

def write_private_path(path, contents, mode='w', makedirs=True):
    path = os.path.expanduser(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL  # Refer to "man 2 open".
    if makedirs:
        directory = os.path.dirname(path)
        try:
            make_private_dir(directory)
        except FileExistsError:
            pass

    # For security, remove file with potentially elevated mode
    try:
        remove_path(path)
    except OSError:
        pass

    # Open file descriptor
    umask_original = os.umask(0)
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    finally:
        os.umask(umask_original)

    # Open file handle and write to file
    with os.fdopen(descriptor, mode) as file_writer:
        file_writer.write(contents)

def read_private_path(path, open_mode='r'):
    """
        Technically there is a race condition here between
        when im checking the mode and when I'm opening the file
        that I'm not sure I can get rid of. But it is private
        at the time of checking it, presumably it would require
        the authorization of the user to change it before being
        read.
    """
    path = os.path.expanduser(path)
    file_mode = stat.S_IMODE(os.stat(path).st_mode)
    link_mode = stat.S_IMODE(os.lstat(path).st_mode)
    if file_mode != PRIVATE_FILE_MODE or link_mode != PRIVATE_FILE_MODE: 
        logging.error('File has mode {} and needs {} to be considered private'.format(
            oct(file_mode), oct(PRIVATE_FILE_MODE)
        ))
        raise SecurityError('SECURITY ERROR: Unable to load file: {}. Insecure file permissions!'.format(path))
    with open(path, open_mode) as f:
        data = f.read()
    return data
