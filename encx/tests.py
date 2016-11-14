import unittest
import base64
import io

from .spec import ENCX
from .enc import (
    generate_random_bytes,
    to_b64_str, from_b64_str,
    all_schemes
)

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
            enc_scheme = Scheme(metadata)
            ciphertext = enc_scheme.encrypt(my_value)
            key = enc_scheme.get_key()


            # ... and back again
            dec_scheme = Scheme(metadata, key=key)
            payload = dec_scheme.decrypt(ciphertext)

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
