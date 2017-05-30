import yaml

from . import security

from importlib import import_module
from collections import OrderedDict
from .commands import BasePlugin
import logging
import argparse
import sys


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

    default_config_path = '~/encx/encx.conf'
    base_plugins = [
        'encxlib.commands.PluginManagement',
        'encxlib.commands.Encryption',
        'encxlib.commands.Keygen',
    ]

    def __init__(self, config_path=None):
        self.config_path = config_path
        self._load_configuration()
        self.plugins = self._load_plugins()
        self.parser = self._build_cli()

    def _load_configuration(self):
        # self.config_path is also a flag to determine whether our
        # config needs to be saved out. So if its falsey i want to
        # keep it that way until i can prove that the default config
        # exists. This prevents the default config path from being
        # created unless explicitly asked for by the user.
        path = self.config_path or self.default_config_path
        # This flag will indicate whether we've made any changes and
        # thus whether we need to save out the file
        self._config_changed = False
        try:
            contents = security.read_private_path(path)
        except FileNotFoundError as e:
            if self.config_path:
                # They specified this file explicitly, continue freaking out
                raise e
            else:
                # They didnt specify file and  default doesnt exist
                # assume they haven't created it
                self._config = {}
        else:
            self._config = yaml.load(contents)
        return self._config

    def _save_configuration(self):
        path = self.config_path or self.default_config_path
        if not self.config_path:
            create_config = input('Create new config at default location "{}" (yes/no)?'.format(path))
            if create_config in 'no':
                return False
        dumped_config = yaml.dump(self._config)
        write_private_path(path, dumped_config)



    def _load_plugins(self):
        plugins = OrderedDict()
        # Start with the base plugins
        plugin_paths = self.base_plugins.copy()
        plugin_paths.extend(self.get_config().get('plugins', []))
        for path in plugin_paths:
            success, result = self.load_plugin(path)
            if not success:
                logging.error('Failed to load plugin {}:'.format(path))
                logging.error(str(result))
                continue
            plugins[result.name] = result(self)
        return plugins

    def _build_cli(self):
        self.parser = CustomArgParser(description='encx :: An encryption tool')
        # The following argument will never be used as the global parser consumes
        # it before the arguments get here. However, i still want it in the help
        # message
        self.parser.add_argument('-c', '--config', help="Path to configuration file")

        ##############
        ## Pull in all commands from plugins
        subparsers = self.parser.add_subparsers(dest='cmd', parser_class=CustomArgParser)
        subparsers.required = True
        self.commands = {}
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
        if self._config_changed:
            self._save_configuration()


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
    def load_plugin(self, path):
        #TODO: Validation
        try:
            Plugin = import_class(path)
        except ImportError as e:
            return False, e
        if not issubclass(Plugin, BasePlugin):
            return False, 'Specified plugin is not a subclass of the encxlib.commands.BasePlugin'
        return True, Plugin

    def get_config(self):
        return self._config

    def set_config(self, new_config):
        self._config = new_config
        self._config_changed = True

