import unittest
from server import generate_secret_key, save_secret_key, load_secret_key

class TestServerFunctions(unittest.TestCase):
    def test_generate_secret_key(self):
        key = generate_secret_key()
        self.assertEqual(len(key), 32)

    def test_save_and_load_secret_key(self):
        key = generate_secret_key()
        save_secret_key(key, 'test_config.json')
        loaded_key = load_secret_key('test_config.json')
        self.assertEqual(key, loaded_key)

if __name__ == '__main__':
    unittest.main()