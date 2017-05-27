from .utils import read_data
from .schemes import DEFAULT_SCHEME, get_scheme, schemes
from .spec import ENCX
from . import security

from uuid import uuid4
import string
import sys
import io

class BasePlugin():
    pass

class CoreOperations(BasePlugin):
    name = 'core'
    commands = {
        'encrypt': {
            'parser': 'parse_encrypt',
            'run': 'encrypt',
            'help': 'Encrypt into encx format.'
        },
        'decrypt': {
            'parser': 'parse_decrypt',
            'run': 'decrypt',
            'help': 'Decrypt from encx format.'
        },
    }

    def parse_encrypt(self, parser):
        parser.add_argument('source', nargs="?", help='A file source')
        parser.add_argument('-s', '--scheme', dest='scheme', help='Scheme to use to encrypt', default=DEFAULT_SCHEME.name)
        parser.add_argument('-k', '--key', dest='key', help='Key to use to decrypt', default=None)

    def parse_decrypt(self, parser):
        parser.add_argument('source', nargs="?", help='A file source')
        parser.add_argument('-k', '--key', dest='key', help='Key to use to decrypt')
        parser.add_argument('-d', '--decode', dest='decode', action='store_true', help='Decode data')

    def decrypt(self, args):
        source_data = read_data(args.source)
        encx_file = ENCX.from_file(io.BytesIO(source_data))
        Scheme = get_scheme(encx_file.metadata)
        scheme = Scheme(key=args.key)

        decrypted_data = scheme.decrypt(encx_file.payload.read(), encx_file.metadata)
        if args.decode:
            print(decrypted_data.decode('utf-8'))
        else:
            sys.stdout.buffer.write(decrypted_data)

    def encrypt(self, args):
        source_data = read_data(args.source)
        scheme = schemes.get(args.scheme)
        output = self._create_file(payload=source_data, Scheme=scheme, key=args.key)
        output.seek(0)
        sys.stdout.buffer.write(output.read())

    def _create_file(self, payload=None, Scheme=DEFAULT_SCHEME, file_obj=None, key=None):
        if file_obj is None:
            file_obj = io.BytesIO()
        scheme = Scheme(key=key)
        encrypted_payload, metadata = scheme.encrypt(payload)
        encx_file = ENCX(metadata, io.BytesIO(encrypted_payload))
        return encx_file.to_file(file_obj)

    def _read_file(file_obj, key=None):
        encx_file = ENCX.from_file(file_obj)
        scheme_name = encx.metadata.get('scheme', None)
        if scheme_name not in schemes:
            print('Scheme not found!')
            sys.exit(1)
        scheme = schemes[scheme_name](metadata, key=key)
        encrypted_payload = scheme.encrypt(payload)
        encx_file = ENCX(metadata, payload)
        return encx_file.to_file(file_obj)

class Keygen(BasePlugin):
    name = 'keygen'
    commands = {
        'keygen': {
            'parser': 'parse_keygen',
            'run': 'keygen',
            'help': 'Generate new encryption keys/passwords/IDs (Sourced by urandom)'
        },
    }

    def parse_keygen(self, parser):
        subparsers = parser.add_subparsers(dest='key_type')
        subparsers.required = True
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
        byte_key_gen.set_defaults(func=self.generate_byte_key)


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
            help='Output public key to file'
        )
        rsa_key_gen.set_defaults(func=self.generate_rsa_key)


        uuid_parser = subparsers.add_parser('uuid', help='Random UUID')
        uuid_parser.set_defaults(func=self.generate_uuid)


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
        random_str_parser.set_defaults(func=self.generate_random_string)

    def keygen(self, args):
        args.func(args)

    def generate_byte_key(self, args):
        key_bytes = security.generate_random_bytes(args.length)
        if args.raw:
            sys.stdout.buffer.write(key_bytes)
        else:
            print(security.to_b64_str(key_bytes))

    def generate_uuid(self, args):
        print(security.generate_uuid())

    def generate_random_string(self, args):
        selections = [security.random_choice(args.source) for i in range(args.length)]
        print(''.join(selections))

    def generate_rsa_key(self, args):
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
