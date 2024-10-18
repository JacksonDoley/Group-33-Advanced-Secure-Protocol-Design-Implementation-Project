import unittest
import os
from file_transfer import upload_file, download_file

class TestFileTransfer(unittest.TestCase):
    def setUp(self):
        self.upload_folder = 'uploads'
        os.makedirs(self.upload_folder, exist_ok=True)
        self.test_file_path = os.path.join(self.upload_folder, 'test.txt')
        with open(self.test_file_path, 'w') as f:
            f.write('This is a test file.')

    def tearDown(self):
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        if os.path.exists(self.upload_folder):
            os.rmdir(self.upload_folder)

    def test_upload_file(self):
        response = upload_file(self.test_file_path)
        self.assertEqual(response, 'File uploaded successfully')

    def test_download_file(self):
        upload_file(self.test_file_path)
        download_path = 'downloaded_test.txt'
        response = download_file('test.txt', download_path)
        self.assertEqual(response, 'File downloaded successfully')
        self.assertTrue(os.path.exists(download_path))
        os.remove(download_path)

if __name__ == '__main__':
    unittest.main()