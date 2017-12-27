from . import security

def find(items, f):
    for item in items:
        if f(item):
            return item
    return None

class BaseScheme():
    """
        This allows us to toggle the loading from file because I plan on 
        expanding the list of schemes to include variations on 
        padding and/or key size and im not sure if thatll be part of the scheme's
        options or if it should be a separate scheme (perhaps subclass?)

        This class could be used as an "interface" as anything that implements these
        method signatures and returns metadata with a "scheme" property is a valid encx
        scheme.
    """    
    KEY_TYPE_RSA = 'rsa'
    KEY_TYPE_BYTES = 'bytes'

    # Everything but RSA should use the below. We don't need to differentiate them based
    # on size because they're loaded the same and the security classes or scheme classes
    # can validate them later
    key_type = KEY_TYPE_BYTES
    multi_key = False

    def __init__(self, keys, options=None):
        if not keys:
            raise ValueError('All encx encryption schemes require a key!')
        self.keys = keys
        self.options = options 

        if not self.multi_key:
            if len(keys) > 1:
                raise ValueError('Scheme {} does not support multiple keys'.format(
                    self.name,
                ))
            self.key = keys[0]
         
    def encrypt(self, payload):
        raise NotImplemented()

    def decrypt(self, ciphertext, meta):
        raise NotImplemented()

class AESScheme(BaseScheme):
    name = 'AES'
    default_key_size = 16 # In bytes; so 16 is a 128-bit key

    @classmethod
    def generate_key(cls):
        return security.AES.generate_key()

    def encrypt(self, payload):
        encryptor = security.AES(self.key)
        ciphertext, metadata = encryptor.encrypt(payload)
        metadata['scheme'] = self.name
        return ciphertext, metadata

    def decrypt(self, ciphertext, meta):
        iv = meta.get('iv', None)
        if not iv:
            raise ValueError('The AES Security scheme requires an initialization vector')
        decryptor = security.AES(self.key)
        decrypted_payload = decryptor.decrypt(ciphertext, iv)
        return decrypted_payload

class RSAScheme(BaseScheme):
    """
        I'm expecting multiple variations of this, and leaving open the possibility
        of having a single-key scheme that is backwards compatible with my original
        logic. Throwing the core logic in the original class and extending it with
        the needs of the multi-key scheme.
    """
    name = None
    key_type = BaseScheme.KEY_TYPE_RSA

    note_message = 'The payload is encrypted with AES, and the key used is encrypted using RSA'

    @classmethod
    def generate_key(cls):
        return security.RSA(security.RSA.generate_key())

    def _do_encrypt(self, payload, include_aes_key=False):
        # Start by generating an AES key and encrypting the payload
        aes_encryptor = security.AES()
        aes_ciphertext, aes_metadata = aes_encryptor.encrypt(payload)
        aes_key = aes_encryptor.get_key()

        rsa_meta_entries = []
        # Now we use the rsa keys given to encrypt the key we generated to 
        # package with the payload
        for rsa_encryptor in self.keys:
            rsa_ciphertext, rsa_metadata = rsa_encryptor.encrypt(aes_encryptor.key)
            encrypted_key = security.to_b64_str(rsa_ciphertext)
            rsa_meta_entries.append({
                'rsa_meta': rsa_metadata,
                'public_key': rsa_encryptor.export_public_key('openssh'),
                'encrypted_key': encrypted_key,
            })

        meta = {
            'aes': aes_metadata,
            'rsa_entries': rsa_meta_entries,
            'note': self.note_message,
        }
        if include_aes_key:
            return aes_ciphertext, meta, aes_key
        else:
            return aes_ciphertext, meta 

    def _do_decrypt(self, ciphertext, meta):
        rsa_meta_entries = meta.get('rsa_entries', {})
        aes_meta = meta.get('aes', {})

        key = self.keys[0]
        # In-reverse of the encrypt, first we extract the encrypted key from the metadata
        exported_public_key = key.export_public_key('openssh')
        rsa_entry = find(rsa_meta_entries, lambda x: x['public_key'] == exported_public_key)
        if not rsa_entry:
            print('Given key:', exported_public_key)
            print('keys:', rsa_meta_entries)
            raise ValueError('No matching RSA key found for decryption')
        encrypted_key_str = rsa_entry.get('encrypted_key', None)
        if not encrypted_key_str:
            raise ValueError('The RSA security scheme requires an encrypted key packaged with payload')
        encrypted_key = security.from_b64_str(encrypted_key_str)

        # Decrypt the AES key that was used on the payload
        rsa_decryptor = key
        aes_key = rsa_decryptor.decrypt(encrypted_key)

        # Now do the decryption of the actual payload
        iv = aes_meta.get('iv', None)
        if not iv:
            raise ValueError('The AES Security scheme requires an initialization vector')
        aes_decryptor = security.AES(aes_key)
        payload = aes_decryptor.decrypt(ciphertext, iv)
        return payload

class RSAMultiKeyScheme(RSAScheme):
    name = 'RSA-AES-mk'
    multi_key = True

    def encrypt(self, payload, include_aes_key=False):
        return self._do_encrypt(payload, include_aes_key=include_aes_key)

    def decrypt(self, ciphertext, meta):
        if len(self.keys) > 1:
            raise ValueError('Decryption operations expect to receive only one key')
        return self._do_decrypt(ciphertext, meta)

all_schemes = [AESScheme, RSAMultiKeyScheme]
schemes = {scheme.name: scheme for scheme in all_schemes}
DEFAULT_SCHEME = RSAMultiKeyScheme

def get_scheme(meta):
    """
        Determine which scheme to use for decryption based on scheme name.
        The complexity of this function should increase as I intend to 
        make variations of schemes based on padding / key types. Im
        not sure how i'll break up the logic, but putting a layer here for
        easy refactoring.
    """
    scheme_name = meta.get('scheme', None)
    if not scheme_name:
        raise ValueError('"scheme" property was not specified. Invalid encx metadata.')
    scheme = schemes.get(scheme_name, None)
    if not scheme:
        raise ValueError('Scheme "{}" is unsupported by this implementation of encx'.format(scheme_name))
    return scheme
