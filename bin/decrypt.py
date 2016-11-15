#!/usr/bin/env python3

from encx.spec import ENCX
from encx.enc import schemes
from encx.utils import read_data
import argparse
import sys
import io

def read_file(file_obj, key=None):
    encx_file = ENCX.from_file(file_obj)
    scheme_name = encx.metadata.get('scheme', None)
    if scheme_name not in schemes:
        print('Scheme not found!')
        sys.exit(1)
    scheme = schemes[scheme_name](metadata, key=key)
    encrypted_payload = scheme.encrypt(payload)
    encx_file = ENCX(metadata, payload)
    return encx_file.to_file(file_obj)

def decrypt_command():
    parser = argparse.ArgumentParser(description='Decrypt encx file.')
    parser.add_argument('source', nargs="?", help='A file source')
    parser.add_argument('-k', '--key', dest='key', help='Key to use to decrypt')
    parser.add_argument('-d', '--decode', dest='decode', action='store_true', help='Decode data')
    args = parser.parse_args()

    source_data = read_data(args.source)
    encx_file = ENCX.from_file(io.BytesIO(source_data))
    scheme_name = encx_file.metadata.get('scheme')
    if scheme_name not in schemes:
        print('Scheme {} is not supported by this implementation'.format(scheme_name))
        sys.exit(1)
    scheme = schemes[scheme_name](encx_file.metadata, key=args.key)
    decrypted_data = scheme.decrypt(encx_file.payload)
    if args.decode:
        print(decrypted_data.decode('utf-8'))
    else:
        sys.stdout.buffer.write(decrypted_data)

if __name__ == '__main__':
    decrypt_command()
