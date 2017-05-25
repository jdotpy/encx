from importlib import import_module
import logging
import argparse
import sys

def import_class(path):
    parts = path.split('.')
    module_path = '.'.join(parts[:-1])
    class_name = parts[-1]
    m = import_module(module_path)
    obj = getattr(m, class_name)
    return obj

class EncxClient():
    """ Implements the core of the CLI. Extendable with plugins """

    base_plugins = ['encxlib.cli.CoreOperations']

    def __init__(self):
        self._load_configuration()
        self.plugins = self._load_plugins()
        self.parser = self._build_cli()

    def _load_configuration(self):
        """ i'm thinking a ~/.encx.conf ??!? """
        pass

    def _load_plugins(self, user_plugins=None):
        if user_plugins is None:
            user_plugins = []
        plugins = []
        # Start with the base plugins
        plugin_paths = self.base_plugins.copy()
        plugin_paths.extend(user_plugins)
        for path in plugin_paths:
            try:
                Plugin = import_class(path)
            except ImportError as e:
                logging.error('Failed to load plugin {}:'.format(path))
                logging.error(str(e))
                continue
            plugins.append(Plugin())
        return plugins

    def _build_cli(self):
        self.parser = argparse.ArgumentParser(description='encx :: An encryption tool')
        subparsers = self.parser.add_subparsers(dest='cmd')
        self.commands = {}
        for plugin in self.plugins:
            for command, cmd_options in plugin.commands.items():
                cmd_help = cmd_options.get('help', None)
                cmd_parser = getattr(plugin, cmd_options['parser'])
                cmd_runner = getattr(plugin, cmd_options['run'])
                subparser = subparsers.add_parser(command, help=cmd_help)
                cmd_parser(subparser)
                self.commands[command] = cmd_runner
        return self.parser

    def command(self, source):
        args = self.parser.parse_args(source)
        command = args.cmd
        if command is None:
           self.parser.print_usage() 
           sys.exit(0)
            
        runner = self.commands.get(command)
        runner(args)
