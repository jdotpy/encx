#!/usr/bin/env python3

from encx.spec import ENCX
from encx.enc import schemes
from encx.utils import read_data
import argparse
import sys

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
    args = parser.parse_args()

if __name__ == '__main__':
    decrypt_command()
