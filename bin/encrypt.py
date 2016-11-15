#!/usr/bin/env python3

from encx.spec import ENCX
from encx.enc import schemes, AESScheme
from encx.utils import read_data
import argparse
import sys
import io

DEFAULT_SCHEME = AESScheme

def create_file(metadata=None, payload=None, Scheme=DEFAULT_SCHEME, file_obj=None, key=None):
    if metadata is None:
        metadata = {}
    if file_obj is None:
        file_obj = io.BytesIO()
    scheme = Scheme(metadata, key=key)
    encrypted_payload = scheme.encrypt(io.BytesIO(payload))
    encx_file = ENCX(metadata, encrypted_payload)
    return encx_file.to_file(file_obj)

def encrypt_command():
    parser = argparse.ArgumentParser(description='Encrypt into encx format.')
    parser.add_argument('source', nargs="?", help='A file source')
    parser.add_argument('-s', '--scheme', dest='scheme', help='Scheme to use to encrypt', default=DEFAULT_SCHEME.name)
    parser.add_argument('-k', '--key', dest='key', help='Key to use to decrypt', default=None)
    args = parser.parse_args()

    source_data = read_data(args.source)
    scheme = schemes.get(args.scheme)
    output = create_file(payload=source_data, Scheme=scheme, key=args.key)
    output.seek(0)
    sys.stdout.buffer.write(output.read())

if __name__ == '__main__':
    encrypt_command()
