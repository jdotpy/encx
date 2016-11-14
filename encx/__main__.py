from .spec import ENCX
from .enc import schemes, AESScheme
import sys
import io

DEFAULT_SCHEME = AESScheme

def create_file(metadata, payload, Scheme, file_obj, key=None):
    scheme = Scheme(metadata, key=key)
    encrypted_payload = scheme.encrypt(payload)
    encx_file = ENCX(metadata, payload)
    encx_file.to_file(file_obj)

def read_file(file_obj, key=None):
    encx_file = ENCX.from_file(file_obj)
    scheme_name = encx.metadata.get('scheme', None)
    if scheme_name not in schemes:
        print('Scheme not found!')
        sys.exit(1)
    scheme = schemes[scheme_name](metadata, key=key)
    encrypted_payload = scheme.encrypt(payload)
    encx_file = ENCX(metadata, payload)
    encx_file.to_file(file_obj)

def main():
    pass

if __name__ == '__main__':
    main()
