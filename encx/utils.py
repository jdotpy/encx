import sys
import os

def read_data(source_file):
    if not source_file or source_file == '-':
        source = sys.stdin
        data = source.read().encode('utf-8')
    else:
        try:
            with open(os.path.expanduser(source_file), 'rb') as source:
                data = source.read()
        except (OSError, IOError, ValueError):
            print('Failed to read file!')
            sys.exit(1)
    return data
