import yaml

from . import security
from .spec import ENCX
from .schemes import get_scheme, DEFAULT_SCHEME

from importlib import import_module
from collections import OrderedDict
from .commands import BasePlugin
from pprint import pprint
import subprocess
import logging
import argparse
import time
import sys
import io
import os
import re

class FileLoaderInvalidPath(ValueError):
    pass

class CustomArgParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)

def import_class(path):
    parts = path.split('.')
    module_path = '.'.join(parts[:-1])
    class_name = parts[-1]
    m = import_module(module_path)
    obj = getattr(m, class_name)
    return obj

class EncxClient():
    """ Implements the core of the CLI. Extendable with plugins """

    default_config_dir = os.path.expanduser('~/encx')
    default_config_file = 'encx.yaml'
    base_plugins = [
        'encxlib.commands.SimpleFileLoaders',
        'encxlib.commands.PluginManagement',
        'encxlib.commands.Encryption',
        'encxlib.commands.Keygen',
    ]

    def __init__(self, config_path=None):
        self.config_path = config_path
        self._load_configuration()
        self._load_plugins()
        self.parser = self._build_cli()

    def _load_configuration(self):
        # self.config_path is also a flag to determine whether our
        # config needs to be saved out. So if its falsey i want to
        # keep it that way until i can prove that the default config
        # exists. This prevents the default config path from being
        # created unless explicitly asked for by the user.
        path = self.get_config_file_path()

        # This flag will indicate whether we've made any changes and
        # thus whether we need to save out the file
        self._config_changed = False
        try:
            contents = security.read_private_path(path)
        except FileNotFoundError as e:
            if self.config_path:
                # They specified this file explicitly, warn the user
                logging.warning('Specified config file doesnt exist.')
            # They didnt specify file and  default doesnt exist
            # assume they haven't created it
            self._config = {}
        else:
            # We loaded the file, set the config_path
            self.config_path = path
            self._config = yaml.load(contents)
        return self._config

    def _save_configuration(self, force=False):
        if not self._config_changed:
            return False
        path = self.get_config_file_path()
        if not os.path.exists(path):
            create_config = input('Create new config at location "{}" (yes/no)?'.format(path))
            if create_config in 'no':
                return False
        dumped_config = yaml.dump(self._config)
        security.write_private_path(path, dumped_config)
        self._config_changed = False # Reset the flag in case this was forced

    def _load_plugins(self):
        self.plugins = OrderedDict()
        self.plugins_by_name = OrderedDict()

        # Start with the base plugins
        plugin_paths = self.base_plugins.copy()
        plugin_paths.extend(self.get_config().get('installed_plugins', []))
        for path in plugin_paths:
            success, result = self.load_plugin(path)
            if not success:
                logging.error('Failed to load plugin {}:'.format(path))
                logging.error(str(result))
                continue
            plugin = result(self)

            # Add to client mappings
            self.plugins[path] = plugin
            self.plugins_by_name[result.name] = plugin

    def _build_cli(self):
        self.parser = CustomArgParser(description='encx :: An encryption tool')
        # The following argument will never be used as the global parser consumes
        # it before the arguments get here. However, i still want it in the help
        # message
        self.parser.add_argument('-c', '--config', help="Path to configuration file")

        #############
        ## Commands not in plugins
        subparsers = self.parser.add_subparsers(dest='cmd', parser_class=CustomArgParser)
        subparsers.required = True

        self.commands = {
            'config': self.cmd_show_config
        }
        subparser = subparsers.add_parser('config', help='View configuration')

        ##############
        ## Pull in all commands from plugins
        for plugin_name, plugin in self.plugins.items():
            for command, cmd_options in plugin.commands.items():
                cmd_help = cmd_options.get('help', None)
                parser_name = cmd_options.get('parser', None)
                if parser_name:
                    cmd_parser = getattr(plugin, parser_name)
                else:
                    cmd_parser = None
                cmd_runner = getattr(plugin, cmd_options['run'])
                subparser = subparsers.add_parser(command, help=cmd_help)
                if cmd_parser:
                    cmd_parser(subparser)
                self.commands[command] = cmd_runner

        return self.parser

    def _finish(self):
        """ This is a hook that i'm using to trigger configuration changes """
        self._save_configuration()

        for plugin in self.iterate_plugin_objects():
            if hasattr(plugin, 'finish'):
                plugin.finish()

    ###################
    ### Basic commands
    def cmd_show_config(self, args):
        print(yaml.dump(self.get_config()))

    ### Entry Point ###
    def run_command(self, source):
        args = self.parser.parse_args(source)
        command = args.cmd
        if command is None:
           self.parser.print_help() 
           sys.exit(0)
            
        runner = self.commands.get(command)
        runner(args)
        self._finish()

    ### Plugin API ###
    def force_config_save(self):
        self._save_configuration

    def load_plugin(self, path):
        if path in self.plugins:
            return False, 'Specified plugin is already installed'
        try:
            Plugin = import_class(path)
        except (ImportError, ValueError) as e:
            return False, e
        if not issubclass(Plugin, BasePlugin):

            return False, 'Specified plugin is not a subclass of the encxlib.commands.BasePlugin'
        if Plugin.name in self.plugins_by_name:
            return False, 'Specified plugin name "{}" is already taken'.format(plugin.name)
        return True, Plugin

    def get_config(self):
        return self._config

    def set_config(self, new_config):
        self._config = new_config
        self._config_changed = True

    def default_rsa_key(self):
        return self.get_config().get('default_key_path', None)

    def get_config_file_path(self):
        if self.config_path:
            if '.' in self.config_path:
                path = self.config_path
            else:
                path = os.path.join(self.config_path, self.default_config_file)
        else:
            path = os.path.join(self.get_config_dir(), self.default_config_file)
        return path

    def get_config_dir(self):
        if self.config_path:
            return os.path.dirname(self.config_path)
        else:
            return self.default_config_dir

    def get_tmp_dir(self):
        if self.config_path:
            return os.path.dirname(self.config_path)
        else:
            return os.path.abspath('.')

    def iterate_plugin_objects(self):
        plugin_list = list(self.plugins.values())
        for plugin in plugin_list[::-1]: # Reverse
            yield plugin

    def load_file(self, path):
        if path is None:
            path = ''
        for plugin in self.iterate_plugin_objects():
            for pattern, loader in plugin.file_loaders.items():
                if re.match(pattern, path):
                    loader = getattr(plugin, loader['loader'])
                    try:
                        return loader(path)
                    except (FileNotFoundError, FileLoaderInvalidPath) as e:
                        continue
        raise FileNotFoundError('Could not find file: {}'.format(path))

    def write_file(self, path, data, overwrite=False):
        for plugin in self.iterate_plugin_objects():
            for pattern, loader in plugin.file_loaders.items():
                writer = getattr(plugin, loader['writer'])
                if re.match(pattern, path):
                    try:
                        return writer(path, data, overwrite=overwrite)
                    except (FileLoaderInvalidPath) as e:
                        continue
        raise ValueError('Could not find a writer for file: {}'.format(path))

    def decrypt_file(self, path, key=None):
        if key is None:
            key = self.default_rsa_key()

        source = self.load_file(path)
        encx_file = ENCX.from_file(io.BytesIO(source))
        Scheme = get_scheme(encx_file.metadata)
        scheme = Scheme(key=key)
        payload = scheme.decrypt(encx_file.payload.read(), encx_file.metadata)
        return payload, encx_file.metadata

    def encrypt_file(self, path, data, scheme=DEFAULT_SCHEME, key=None, overwrite=False):
        if key is None:
            key = self.default_rsa_key()

        scheme_instance = scheme(key=key)
        encrypted_payload, metadata = scheme_instance.encrypt(data)
        encx_file = ENCX(metadata, io.BytesIO(encrypted_payload))
        output_stream = encx_file.to_file(io.BytesIO())
        output_stream.seek(0)
        return self.write_file(path, output_stream.read(), overwrite=overwrite)

    def get_filetype_validator(self, name, path=None):
        if not name and not path:
            return None, None
        elif not name:
            # Exclude the encx extension
            parts = path.split('.')
            if parts[-1] == 'encx':
                parts.pop()
            
            # We didnt have a valid extension
            if len(parts) == 1:
                return None, None
            name = parts[-1].lower()

        validator = None
        for plugin in self.iterate_plugin_objects():
            validator_attr = plugin.filetype_validators.get(name, None)
            if validator_attr:
                validator = getattr(plugin, validator_attr)
                break
        return name, validator

    def edit_data(self, data, extension=None, validator=None, timeout=None):
        """
            Create a temporary file to edit the content.  If a valiator
            is given then content is not returned until it passes the validator.

            Polling is used to check for changes to the tmp file which isnt
            ideal but its a minimal delay and is an easy cross-platform check
            that doesn't require a big dependency.
        """
        poll_time = 1
        error_view_time = 2
        success = False
        new_data = None
        if extension is None:
            extension = 'encx-tmp'
        tmp_path = os.path.join(
            self.get_tmp_dir(),
            '{}.{}'.format(security.generate_uuid(), extension),
        )
        tmp_path = os.path.expanduser(tmp_path)
        security.write_private_path(tmp_path, data, mode='wb')
        creation_time = os.path.getmtime(tmp_path)

        while not success:
            try:
                # Launch editor
                subprocess.call(["vim", "-n", tmp_path])

                # Poll FS for change
                if timeout:
                    expire = time.time() + timeout
                else:
                    expire = sys.maxsize # Arbitrarily large number that won't be reached
                modified = False
                print('Waiting for changes to tmp file...(Ctrl + C to cancel)')
                while time.time() < expire:
                    modified_time = os.path.getmtime(tmp_path)
                    if modified_time > creation_time:
                        modified = True
                        break
                    time.sleep(poll_time)

                if not modified:
                    logging.error('Edit timed out! Going to clean up')
                    break

                new_data = security.read_private_path(tmp_path, 'rb')
                if validator:
                    passes, message = validator(new_data)
                    if not passes:
                        logging.error(message)
                        time.sleep(error_view_time)
                        continue # Restart editor, try again
                    else:
                        success = True
                else:
                    success = True

            except KeyboardInterrupt as e:
                logging.error('Cancelling file edit')
                break
            except Exception as e:
                logging.error('Failed to edit file!')
                logging.error(str(e))
                break

        security.remove_path(tmp_path)
        return success, new_data;
