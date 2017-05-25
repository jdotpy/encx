from .utils import read_data
from .schemes import DEFAULT_SCHEME, get_scheme, schemes
from .spec import ENCX

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
