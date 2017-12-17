from . import security

class KeyAliasNotFoundError(KeyError):
    pass

class MultipleKeysFoundError(KeyError):
    pass

class IncorrectKeyTypeError(ValueError):
    pass

class KeyStore():
    """
        Stores private key paths (no actual data), Aliases public
        and private keys.
    """
    def __init__(self, data={}):
        self.load_data(data)
        self._changed = False

    def load_data(self, data):
        if not data:
            data = {}
        self.data = data

    def has_changed(self):
        return self._changed

    def mark_changed(self):
        self._changed = True

    def export(self):
        return self.data

    def key_exists(self, name):
        if name in self.data:
            return True
        return False

    def delete_key(self, name):
        self.data.pop(name, None)

    def add_private_key(self, name, path, validate=True):
        if validate:
            key = security.load_rsa_key(path)
        self.mark_changed()
        self.data[name] = {
            'type': 'private',
            'value': path,
        }

    def add_public_key(self, name, key):
        self.mark_changed()
        self.data[name] = {
            'type': 'public',
            'value': key.export_public_key('openssh'),
        }

    def add_alias(self, alias, names):
        self.mark_changed()
        self.data[name] = {
            'type': 'alias',
            'value': [],
        }

    def resolve_alias(self, root_alias):
        matches = []
        aliases = [root_alias]
        seen_aliases = {root_alias: True}
        while aliases:
            # Map to valeus
            next_aliases = []
            for a in aliases:
                value = self.data.get(a, None)
                if not value:
                    logging.warn('Key alias "{}" does not exist.'.format(a))
                    continue

                if value['type'] == 'alias':
                    for new_alias in value['value']:
                        if new_alias in seen_aliases:
                            # Skip any we've already come across
                            # This prevents infinite looping
                            continue
                        next_aliases.append(new_alias)
                        seen_aliases[new_alias] = True
                        
                else:
                    matches.append(value)
                values.append(value)
            aliases = next_aliases
        return matches

    def get_private_key(self, alias):
        matches = self.resolve_alias(alias)
        if not matches:
            raise KeyAliasNotFoundError('Alias {} not found!'.format(alias))
        if len(matches) > 1:
            raise MultipleKeysFoundError('Alias {} returned multiple entries!'.format(alias))
        entry = matches[0]
        if entry['type'] != 'private_key':
            raise IncorrectKeyTypeError('Alias {} returned a public key!'.format(alias))

        return security.load_rsa_key(entry['value'])
