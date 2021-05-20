# Pit 
#Linux #CTF #HTB
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
 
![[Pasted image 20210520181902.png]]

[seedms](https://www.seeddms.org/index.php?id=2)
It a free document management system for web based user interface. 
 
 The default cred of *admin* did not work. 
 
https://github.com/dheiland-r7/snmp
## Writeups 
![[HTB-PIT-Writeup-2.pdf]]

