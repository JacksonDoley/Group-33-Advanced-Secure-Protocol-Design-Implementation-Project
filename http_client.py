import requests

def upload_file(file_path):
    url = 'http://localhost:5000/upload'
    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, files=files)
    print(response.text)

def download_file(file_name, save_path):
    url = f'http://localhost:5000/download/{file_name}'
    response = requests.get(url)
    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            file.write(response.content)
        print('File downloaded successfully')
    else:
        print('Failed to download file')

if __name__ == '__main__':
    action = input("Enter action (upload/download): ").strip().lower()
    if action == 'upload':
        file_path = input("Enter the path of the file to upload: ").strip()
        upload_file(file_path)
    elif action == 'download':
        file_name = input("Enter the name of the file to download: ").strip()
        save_path = input("Enter the path to save the downloaded file: ").strip()
        download_file(file_name, save_path)
    else:
        print("Unknown action")