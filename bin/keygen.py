#!/usr/bin/env python3

from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import RSA
from getpass import getpass
import argparse
import base64
import string
import random
import uuid
import sys
import os

def random_bytes(size):
    return Random.new().read(size)

def to_b64_str(the_bytes, encoding='utf-8'):
    return base64.b64encode(the_bytes).decode(encoding)

def from_b64_str(string, encoding='utf-8'):
    return base64.b64decode(string.encode(encoding))

#############
### Commands

def generate_byte_key(args):
    key_bytes = random_bytes(args.length)
    if args.raw:
        sys.stdout.buffer.write(key_bytes)
    else:
        print(to_b64_str(key_bytes))

def generate_uuid(args):
    print(uuid.UUID(bytes=random_bytes(16)))

def generate_random_string(args):
    sys_random = random.SystemRandom()
    selections = [sys_random.choice(args.source) for i in range(args.length)]
    print(''.join(selections))

def generate_rsa_key(args):
    rsa_key = RSA.generate(args.size)

    if args.askpass:
        passphrase = getpass('Enter passphrase for new key:')
    else:
        passphrase = args.passphrase
    
    private_key = rsa_key.exportKey('PEM', passphrase=passphrase)
    
    if args.public:
        rsa_pub = rsa_key.publickey()
        with open(args.public, 'wb') as pub_file:
            pub_file.write(rsa_pub.exportKey('PEM'))

    if args.key:
        with open(args.key, 'wb') as priv_file:
            priv_file.write(private_key)
    else:
        print(private_key.decode('utf-8'))

#############
### Parser

def main():
    main_parser = argparse.ArgumentParser(prog='Key Generator (Sourced by urandom)')
    subparsers = main_parser.add_subparsers()

    byte_key_gen = subparsers.add_parser('key', help='Random bytes generated for a key')
    byte_key_gen.add_argument(
        '-l', '--length', 
        dest='length', 
        type=int, 
        help='length of key in bytes', 
        default=16
    )
    byte_key_gen.add_argument(
        '-r', '--raw', 
        dest='raw',
        action='store_true',
        help='Dont encode bytes into base64 string',
        default=False
    )
    byte_key_gen.set_defaults(func=generate_byte_key)


    rsa_key_gen = subparsers.add_parser(
        'rsa', help='Generate an RSA key in PEM format'
    )
    rsa_key_gen.add_argument(
        '-s', '--size', 
        type=int, 
        help='length of key in bytes', 
        default=2048
    )
    rsa_key_gen.add_argument(
        '-k', '--key',
        help='Output key to file'
    )
    rsa_key_gen.add_argument(
        '-a', '--askpass',
        action='store_true',
        help='Prompt for passphrase',
        default=False
    )
    rsa_key_gen.add_argument(
        '-w', '--passphrase',
        help='Give private key a passphrase',
        default=None
    )
    rsa_key_gen.add_argument(
        '-p', '--public',
        help='Output public key to file '
    )
    rsa_key_gen.set_defaults(func=generate_rsa_key)


    uuid_parser = subparsers.add_parser('uuid', help='Random UUID')
    uuid_parser.set_defaults(func=generate_uuid)


    random_str_parser = subparsers.add_parser('string', help='Random string')
    random_str_parser.add_argument(
        '-s',
        '--source',
        help='Characters to select from (defaults to alpha-numeric)',
        default=string.ascii_letters + string.digits
    )
    random_str_parser.add_argument(
        '-l',
        '--length', 
        type=int, 
        help='Length of string', 
        default=20
    )
    random_str_parser.set_defaults(func=generate_random_string)

    args = main_parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
