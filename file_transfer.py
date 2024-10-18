import os
import requests

def upload_file(file_path):
    url = 'http://localhost:5000/upload'
    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, files=files)
    return response.text

def download_file(file_name, save_path):
    url = f'http://localhost:5000/download/{file_name}'
    response = requests.get(url)
    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            file.write(response.content)
        return 'File downloaded successfully'
    else:
        return 'Failed to download file'