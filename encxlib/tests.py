import unittest
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
            enc_scheme = Scheme(key)
            ciphertext, meta = enc_scheme.encrypt(my_value)


            # ... and back again
            dec_scheme = Scheme(key)
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
