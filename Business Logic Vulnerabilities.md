
### Lab: Excessive trust in client-side controls
This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter 

### Lab: High-level logic vulnerability

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter 

Solution: request a negative quantity in `POST /cart`

### Lab: Low-level logic flaw

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter 

In this challenge, if we send multiple request to get the item in the cart, eventually the price will go beyond the limit of the back-end number (2,147,483,647)

So, I use Intruder to send request to buy (2,147,483,647 \ 1337 \ 99 (max quantity) = 1606195.7) jackets

| Name                                | Price    | Quantity |
|-------------------------------------|---------|----------|
| Lightweight "l33t" Leather Jacket  | $1337.00 | 96371    |
| Com-Tool                           | $52.81  | 19       |
| **Total:**                         | **$11.51** |          |

### Lab: Inconsistent handling of exceptional input

This lab doesn't adequately validate user input. You can exploit a logic flaw in its account registration process to gain access to administrative functionality. To solve the lab, access the admin panel and delete the user carlos. 

The goal of this lab is to register an account of a `@dontwannacry.com` email address, so that we can access to `/admin` and solve the lab
```
admin interface only available if logged in as a DontWannaCry user
```

I register a new account with the email address as `0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffgggggggggghhhhhhhhhhiiiiiiiiiijjjjjjjjjjkkkkkkkkkkllllllllllmmmmmmmmmmnnnnnnnnnnooooooooooppppppppppqqqqqqqqqqrrrrrrrrrrssssssssssttttttttttuuuuuuuuuuvvvvvvvvvvwwwwwwwwwwxxxxxxxxxxyyyyyyyyyyzzzzzzzzzz@exploit-ID.exploit-server.net`

In the `My account` page, the web return my email as `Your email is: 0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffgggggggggghhhhhhhhhhiiiiiiiiiijjjjjjjjjjkkkkkkkkkkllllllllllmmmmmmmmmmnnnnnnnnnnooooooooooppppp`

Which indicate that my email address had been truncated to 255 characters. So I can reg a new account with the email address :
```
0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffgggggggggghhhhhhhhhhiiiiiiiiiijjjjjjjjjjkkkkkkkkkkllllllllllmmmmmmmmmmnnnnnnnnndontwannacry.com@exploit-0a5600d8044250e48179290e01e10061.exploit-server.net
```
and have access to admin page

### Lab: Inconsistent security controls

This lab's flawed logic allows arbitrary users to access administrative functionality that should only be available to company employees. To solve the lab, access the admin panel and delete the user carlos. 

The goal of this lab is to register an account of a `@dontwannacry.com` email address, so that we can access to `/admin` and solve the lab
```
admin interface only available if logged in as a DontWannaCry user
```

First, register a new account. Then, notice that you can change your email address. Modify it to `a@dontwannacry.com` to access the admin page and solve the lab.

### Lab: Weak isolation on dual-use endpoint
This lab makes a flawed assumption about the user's privilege level based on their input. As a result, you can exploit the logic of its account management features to gain access to arbitrary users' accounts. To solve the lab, access the administrator account and delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 

In `POST /my-account/change-password`, notice that if you remove the **current-password** parameter entirely, you are able to successfully change your password without providing your current one. 

```
csrf=...&username=administrato&new-password-1=a&new-password-2=a
```

Login as administrator with the new password and solve the lab

### Lab: Insufficient workflow validation

This lab makes flawed assumptions about the sequence of events in the purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter

When an item is successfully purchased, a request is sent regardless of the contents of the cart.

To solve the challenge, add the jacket to the cart and send the following request:
```
GET /cart/order-confirmation?order-confirmed=true
```

### Lab: Authentication bypass via flawed state machine

PRACTITIONER
LAB Not solved

This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 

Forward the `POST /login` request. The next request is `GET /role-selector`. Drop this request and then browse to the lab's home page. Observe that your role has defaulted to the administrator role and you have access to the admin panel. 
### Lab: Flawed enforcement of business rules

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter 

The challenge give us 2 code

Notice that if you enter the same code twice in a row, it is rejected because the coupon has already been applied. However, if you alternate between the two codes, you can bypass this control. 

### Lab: Infinite money logic flaw

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter

In this lab, when purchase the 10$ Gift card, you will have a code that give back 10$. We also have a code that reduce 30% the price of the purchased item, so when repeat buy and redeem, we get an additional 3\$. Repeat the process and get the jacket.

```
POST /cart

productId=2&redir=PRODUCT&quantity=1
```
```
POST /cart/coupon

csrf=...&coupon=SIGNUP30
```
```
POST /cart/checkout

csrf=...
```
```
GET /cart/order-confirmation?order-confirmed=true
```
```
POST /gift-card

csrf=...&gift-card=Y1Vj8uE0tU
```

### Lab: Authentication bypass via encryption oracle

This lab contains a logic flaw that exposes an encryption oracle to users. To solve the lab, exploit this flaw to gain access to the admin panel and delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 