from .schemes import DEFAULT_SCHEME, get_scheme, schemes
from .spec import ENCX
from . import security

import yaml

from getpass import getpass
from uuid import uuid4
import logging
import string
import json
import sys
import os
import io

class BasePlugin():
    file_loaders = {}
    filetype_validators = {}
    commands = {}

    def __init__(self, client):
        self.client = client

    def get_config(self, local=True):
        global_config = self.client.get_config()
        if local:
            return global_config.get('plugins', {}).get(self.name, {})
        else:
            return global_config

    def set_config(self, new_configuration, local=True):
        if local:
            config = self.client.get_config()
            if not config.get('plugins', None):
                config['plugins'] = {}
            config['plugins'][self.name] = new_configuration
            self.client.set_config(config)
        else:
            config = new_configuration
            self.client.set_config(config)
        return config

    def finish(self):
        """ Hook to allow post-operation processing (config-saves, etc) """
        pass

class SimpleFileLoaders(BasePlugin):
    name = 'simple_file_loaders'
    file_loaders = {
        '.*': {
            'loader': 'load', # We want to match everything as a fallback
            'writer': 'write', # We want to match everything as a fallback
        }
    }
    filetype_validators = {
        'json': 'json_validator',
        'yaml': 'yaml_validator',
        'yml': 'yaml_validator',
    }

    validation_success_message = 'Everything looks good!'

    def json_validator(self, data):
        try:
            deserialized = json.loads(data.decode('utf-8'))
            return True, self.validation_success_message
        except Exception as e:
            return False, 'Invalid JSON:' + str(e)

    def yaml_validator(self, data):
        try:
            deserialized = yaml.load(data.decode('utf-8'))
            return True, self.validation_success_message
        except Exception as e:
            return False, 'Invalid YAML:' + str(e)

    def load(self, path):
        if not path or path == '-':
            return sys.stdin.buffer.read()
        with open(os.path.expanduser(path), 'rb') as f:
            content = f.read()
        return content

    def write(self, path, data, overwrite=False):
        if path == '-':
            sys.stdout.buffer.write(data)
            return True
        if not overwrite and os.path.exists(path):
            raise FileExistsError()
        with open(os.path.expanduser(path), 'wb') as f:
            f.write(data)

class PluginManagement(BasePlugin):
    name = 'plugin_management'
    commands = {
        'plugin:install': {
            'parser': 'parse_install',
            'run': 'install',
            'help': 'Install a plugin',
        },
        'plugin:list': {
            'run': 'list_plugins',
            'help': 'Show plugins',
        },
        'plugin:uninstall': {
            'parser': 'parse_uninstall',
            'run': 'uninstall',
            'help': 'Uninstall a plugin',
        },
    }

    def _installed_plugin_list(self):
        config = self.get_config(local=False)
        installed_plugins = config.get('installed_plugins', [])
        return installed_plugins

    def parse_install(self, parser):
        parser.add_argument('path', nargs=1, help='Python path to plugin class (e.g. my_module.MyPlugin)')
        parser.add_argument('-f', '--force', action='store_true', help='Uninstall without attempting to load')

    def install(self, args):
        plugin_to_install = args.path.pop()
        if not args.force:
            success, result = self.client.load_plugin(plugin_to_install)
            if not success:
                logging.error('Failed to load plugin {}:'.format(plugin_to_install))
                logging.error(str(result))
                return False
            print('Installing plugin {} ({})'.format(result.name, plugin_to_install))
        else:
            print('Installing plugin {}'.format(result.name))


        installed_plugins = self._installed_plugin_list()
        installed_plugins.append(plugin_to_install)

        config = self.get_config(local=False)
        config['installed_plugins'] = installed_plugins
        self.set_config(config, local=False)
        print('Done')

    def parse_uninstall(self, parser):
        parser.add_argument('name', nargs=1, help='Name of plugin to remove')

    def uninstall(self, args):
        plugin_to_remove = args.name.pop()
        print('Uninstalling plugin {}'.format(plugin_to_remove))
        for plugin_path, plugin in self.client.plugins.items():
            if plugin.name == plugin_to_remove:
                if plugin_path in self.client.base_plugins:
                    print('\tPlugin is a core plugin and cannot be uninstalled!')
                    return False

                # Do removal
                installed_plugins = self._installed_plugin_list()
                installed_plugins.remove(plugin_path)
                config = self.get_config(local=False)
                config['installed_plugins'] = installed_plugins
                self.set_config(config, local=False)
                return True

        print('Plugin not found!')
        return False

    def list_plugins(self, args):
        for plugin_path, plugin in self.client.plugins.items():
            print('{} :: {}'.format(plugin.name, plugin_path))
            for cmd, cmd_info in plugin.commands.items():
                print('\t{}: {}'.format(cmd, cmd_info.get('help', 'No documentation available')))
            print('\n')

class Encryption(BasePlugin):
    name = 'encryption'
    commands = {
        'set_default_key': {
            'parser': 'parse_set_default_key',
            'run': 'set_default_key',
            'help': 'Set an RSA private key as your default key path',
        },
        'encrypt': {
            'parser': 'parse_encrypt',
            'run': 'encrypt',
            'help': 'Encrypt into encx format.',
        },
        'decrypt': {
            'parser': 'parse_decrypt',
            'run': 'decrypt',
            'help': 'Decrypt from encx format.',
        },
        'edit': {
            'parser': 'parse_edit',
            'run': 'edit',
            'help': 'Edit a file in encx format. (uses a plaintext tmp file)',
        },
    }

    def parse_set_default_key(self, parser):
        parser.add_argument('key', nargs="?", help='RSA private key')

    def set_default_key(self, args):
        config = self.get_config(local=False)
        if args.key:
            print('Setting default key to {}'.format(args.key))
            config['default_key_path'] = args.key
        else:
            print('Clearing default key')
            config.pop('default_key_path', None)
        self.set_config(config, local=False)

    def parse_decrypt(self, parser):
        parser.add_argument('source', nargs="?", help='A file source')
        parser.add_argument('-k', '--key', dest='key', help='Key to use to decrypt')
        parser.add_argument('-d', '--decode', dest='decode', action='store_true', help='Decode data')

    def decrypt(self, args):
        data, metadata = self.client.decrypt_file(args.source, args.key)
        if args.decode:
            print(data.decode('utf-8'))
        else:
            sys.stdout.buffer.write(data)

    def parse_encrypt(self, parser):
        parser.add_argument('source', nargs="?", default='-', help='A file source')
        parser.add_argument('-s', '--scheme', dest='scheme', help='Scheme to use to encrypt', default=DEFAULT_SCHEME.name)
        parser.add_argument('-k', '--key', dest='key', help='Key for encryption', default=None)
        parser.add_argument('-t', '--target', default='-', help='Target path for output (default is "-" for stdout')
        parser.add_argument('-f', '--force', action='store_true', help='Overwrite any existing file')

    def encrypt(self, args):
        source_data = self.client.load_file(args.source)
        if args.scheme not in schemes:
            print('Scheme not found!')
            sys.exit(1)
        scheme = schemes.get(args.scheme)
        self.client.encrypt_file(
            args.target,
            source_data,
            scheme=scheme,
            key=args.key,
            overwrite=args.force,
        )

    def parse_edit(self, parser):
        parser.add_argument('source', nargs="?", help='A file source')
        parser.add_argument('-i', '--initialize',
            action='store_true',
            help='Start a new file, or replace existing.',
        )
        parser.add_argument('-f', '--force',
            action='store_true',
            help='Okay to overwrite existing file (when initializing)',
        )
        parser.add_argument('-s', '--scheme',
            help='Scheme to use to encrypt',
            default=DEFAULT_SCHEME.name
        )
        parser.add_argument('-k', '--key', help='Key for encryption')
        parser.add_argument('-r', '--validator', help='Validator to use')

    def edit(self, args):
        # Load from source
        if args.initialize:
            data, metadata = bytes(), {} 
        else:
            data, metadata = self.client.decrypt_file(args.source, args.key)

        # Do edit funtionality
        validator_name, validator = self.client.get_filetype_validator(
            args.validator,
            path=args.source,
        )
        success, result = self.client.edit_data(
            data,
            validator=validator,
            extension=validator_name
        )

        if not success:
            print('Edit failed, no modifications to {} were made'.format(args.source))
            return success

        # Ok write back out to source
        scheme = schemes.get(args.scheme)
        if args.initialize:
            overwrite = bool(args.force) # When initializing you need that extra check
        else:
            overwrite = True # Always overwrite when editing
        self.client.encrypt_file(
            args.source,
            result,
            scheme=scheme,
            key=args.key,
            overwrite=overwrite,
        )

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
        rsa = security.RSA(security.RSA.generate_key())

        if args.askpass:
            passphrase = getpass('Enter passphrase for new key:')
        else:
            passphrase = args.passphrase
        
        private_key = rsa.get_private_key(passphrase=passphrase)
        
        if args.public:
            rsa_pub = rsa.get_public_key()
            with open(args.public, 'wb') as pub_file:
                pub_file.write(rsa_pub)

        if args.key:
            with open(args.key, 'wb') as priv_file:
                priv_file.write(private_key)
        else:
            print(private_key)
