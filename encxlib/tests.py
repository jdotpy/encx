import unittest
from unittest import mock

import base64
import yaml
import json

import io


from .spec import ENCX
from .security import (
    generate_random_bytes,
    to_b64_str, from_b64_str,
    AES, RSA
)
from . import security
from .keystore import KeyStore
from .schemes import all_schemes
from . import commands

class UtilityTests(unittest.TestCase):
    def test_random_bytes(self):
        bytes_1 = generate_random_bytes(16)
        self.assertEqual(len(bytes_1), 16)

        bytes_2 = generate_random_bytes(32)
        self.assertEqual(len(bytes_2), 32)

        bytes_3 = generate_random_bytes(32)
        self.assertEqual(len(bytes_3), 32)

        self.assertNotEqual(bytes_2, bytes_3)

    def test_b64_strings(self):
        value = generate_random_bytes(16)

        str_value = to_b64_str(value)
        there_and_back_again = from_b64_str(str_value)
        self.assertEqual(value, there_and_back_again)

class EncryptionSchemeTests(unittest.TestCase):
    def test_schemes(self):
        for Scheme in all_schemes:
            my_value = generate_random_bytes(100)

            metadata = {}

            # Encrypt our value
            key = Scheme.generate_key()
            enc_scheme = Scheme([key])
            ciphertext, meta = enc_scheme.encrypt(my_value)

            # ... and back again
            dec_scheme = Scheme([key])
            payload = dec_scheme.decrypt(ciphertext, meta)

            self.assertEqual(payload, my_value)

class FileFormatTest(unittest.TestCase):
    def test_basic(self):
        metadata = {'foo': 'bar', 'dataz': 42}
        my_bytes = generate_random_bytes(100)

        my_fake_file = io.BytesIO()

        ex = ENCX(metadata, io.BytesIO(my_bytes))
        ex.to_file(my_fake_file)

        my_fake_file.seek(0)

        reloaded = ENCX.from_file(my_fake_file)

        assert reloaded.metadata == metadata
        assert reloaded.payload.read() == my_bytes

class KeyStoreTests(unittest.TestCase):
    def test_add_private_key(self):
        path = '/tmp/encx-tests-1.pem'
        pem_private_1 = RSA.generate_key()
        with mock.patch.object(
            security,
            'read_private_path',
            return_value=pem_private_1
        ):
            key_store = KeyStore()
            key_store.add_private_key('john', path)
            reloaded_key = key_store.get_private_key('john')
            self.assertTrue(reloaded_key.export_private_key() == pem_private_1)

    def test_save(self):
        first_store = KeyStore()
        path = '/tmp/encx-tests-1.pem'
        pem_private_1 = RSA.generate_key()
        with mock.patch.object(
            security,
            'read_private_path',
            return_value=pem_private_1
        ):
            self.assertFalse(first_store.has_changed())
            first_store.add_private_key('john', path)
            self.assertTrue(first_store.has_changed())

            # Save and reload
            save = first_store.export()
            reloaded = KeyStore(save)
            reloaded_key = reloaded.get_private_key('john')
            self.assertTrue(reloaded_key.export_private_key() == pem_private_1)

    def test_add_public_key(self):
        generated_key = RSA(RSA.generate_key())
        generated_pub = generated_key.export_public_key('openssh')

        key_store = KeyStore()
        key_store.add_public_key('john', generated_key)
        match = key_store.get_public_key('john')
        self.assertTrue(generated_pub == match.export_public_key('openssh'))

    def test_aliases(self):
        generated_key = RSA(RSA.generate_key())
        generated_pub = generated_key.export_public_key('openssh')

        key_store = KeyStore()
        key_store.add_public_key('john', generated_key)
        key_store.add_alias('A_1', ['john'])
        key_store.add_alias('A_2', ['A_1'])
        key_store.add_alias('A_3', ['A_1', 'john'])

        for a in ('A_1', 'A_2', 'A_3'):
            match = key_store.get_public_key(a)
            self.assertTrue(generated_pub == match.export_public_key('openssh'))


#################
### Plugins

def validator_test(case, validator, good=[], bad=[]):
    for value in good:
        success, message = validator(value)
        case.assertTrue(success, msg='Validator "{}" should pass for value "{}" instead received: {}'.format(
            validator.__name__,
            value,
            message,
        ))
    for value in bad:
        success, message = validator(value)
        case.assertFalse(success, msg='Validator "{}" should fail for value "{}" instead received: {}'.format(
            validator.__name__,
            value,
            message,
        ))

class SimpleFileLoaderTests(unittest.TestCase):
    test_data = {'foo': 'bar', 'dataz': 42}

    def fake_client(self):
        return object()

    def test_validators(self):
        good_json = json.dumps(self.test_data)

        plugin = commands.SimpleFileLoaders(self.fake_client())
        validators = plugin.filetype_validators

        self.assertIn('json', validators)
        self.assertIn('yaml', validators)
        self.assertIn('yml', validators)
        self.assertEqual(validators['yaml'], validators['yml'])


    def test_json_validator(self):
        plugin = commands.SimpleFileLoaders(self.fake_client())
        json_validator = getattr(plugin, plugin.filetype_validators['json'])

        validator_test(
            self,
            json_validator,
            bad=[None, 'not json'.encode('utf-8'), b''],
            good=[json.dumps(self.test_data).encode('utf-8')],
        )

    def test_yaml_validator(self):
        plugin = commands.SimpleFileLoaders(self.fake_client())
        yaml_validator = getattr(plugin, plugin.filetype_validators['yaml'])

        validator_test(
            self,
            yaml_validator,
            bad=[None, '{not yaml'.encode('utf-8')],
            good=[yaml.dump(self.test_data).encode('utf-8')],
        )
