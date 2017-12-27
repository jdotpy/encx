from . import security

class KeyAliasNotFoundError(KeyError):
    pass

class MultipleKeysFoundError(KeyError):
    pass

class IncorrectKeyTypeError(ValueError):
    pass

class InvalidAliasError(ValueError):
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

    def has_key(self, name):
        if name in self.data:
            return True
        return False

    def delete_key(self, name):
        self.data.pop(name, None)
        self.mark_changed()

    def add_private_key(self, name, path, validate=True):
        key = security.load_rsa_key(path)
        assert key.has_private_portion()
        self.mark_changed()
        self.data[name] = {
            'type': 'private_key',
            'value': path,
            'public_key': key.export_public_key('openssh'),
        }

    def add_public_key(self, name, key):
        self.mark_changed()
        self.data[name] = {
            'type': 'public_key',
            'value': key.export_public_key('openssh'),
        }

    def add_alias(self, alias, names):
        self.mark_changed()
        self.data[alias] = {
            'type': 'alias',
            'value': names,
        }

    def add_to_alias(self, alias, names):
        entry = self.data.get(alias, None)
        if not entry or entry['type'] != 'alias':
            raise InvalidAliasError('Cannot add to an alias that doesnt exist')
        self.mark_changed()
        entry['value'].extend(names)

    def resolve_alias(self, root_alias):
        matches = []
        aliases = [root_alias]
        seen_aliases = {root_alias: True}
        while aliases:
            # Map to values
            next_aliases = []
            for a in aliases:
                entry = self.data.get(a, None)
                if not entry:
                    logging.warn('Key alias "{}" does not exist.'.format(a))
                    continue

                value = entry['value']
                if entry['type'] == 'alias':
                    for new_alias in value:
                        if new_alias in seen_aliases:
                            # Skip any we've already come across
                            # This prevents infinite looping
                            continue
                        next_aliases.append(new_alias)
                        seen_aliases[new_alias] = True
                else:
                    matches.append(entry)
            aliases = next_aliases
        return matches

    def get_private_key(self, alias, require_match=True):
        matches = self.resolve_alias(alias)
        if not matches and require_match:
            raise KeyAliasNotFoundError('Alias {} not found!'.format(alias))
        if len(matches) > 1:
            raise MultipleKeysFoundError('Alias {} returned multiple entries!'.format(alias))
        entry = matches[0]
        if not entry:
            return None
        if entry['type'] != 'private_key':
            raise IncorrectKeyTypeError('Alias {} returned a public key!'.format(alias))

        return security.load_rsa_key(entry['value'])

    def get_public_keys(self, alias, require_match=True):
        matches = self.resolve_alias(alias)
        if not matches and require_match:
            raise KeyAliasNotFoundError('Alias {} not found!'.format(alias))
        return [security.RSA(match['value']) for match in matches]

    def get_public_key(self, alias, require_match=True):
        matches = self.get_public_keys(alias, require_match=require_match)
        if not len(matches) == 1:
            raise MultipleKeysFoundError('Alias {} returned multiple entries!'.format(alias))
        return matches[0]

    def get_entries(self, alias):
        return self.resolve_alias(alias)
