# dynstr 
#HTB #CTF 

Rank: medium 
OS : Linux
IP : 10.10.10.244


## Recon 

### Nmap 
As always lets fire up a nmap scan 

```
nmap -sV -sC -T4 -p- 10.10.10.245
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)  
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)  
|\_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)  
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)  
| dns-nsid:    
|\_  bind.version: 9.16.1-Ubuntu  
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))  
|\_http-server-header: Apache/2.4.41 (Ubuntu)  
|\_http-title: Dyna DNS  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel
```


### HTTP 

![[Pasted image 20210614145523.png]]

Looking at the website we see there shared cred 
**Username**: dynadns
**Password**: sndanyd

Nothing of value from the source code. 

Lets use Gobuster 
```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.10.244/  
\===============================================================  
Gobuster v3.1.0  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
\===============================================================  
\[+\] Url:                     http://10.10.10.244/  
\[+\] Method:                  GET  
\[+\] Threads:                 10  
\[+\] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  
\[+\] Negative Status codes:   404  
\[+\] User Agent:              gobuster/3.1.0  
\[+\] Timeout:                 10s  
\===============================================================  
2021/06/14 15:27:11 Starting gobuster in directory enumeration mode  
\===============================================================  
/assets               (Status: 301) \[Size: 313\] \[--> http://10.10.10.244/assets/\]  
/nic                  (Status: 301) \[Size: 310\] \[--> http://10.10.10.244/nic/\]
```

We find two 
assets and nic 

assets give us 403 forbidden and nic give us a blank page, 

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.10.244/nic  
\===============================================================  
Gobuster v3.1.0  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
\===============================================================  
\[+\] Url:                     http://10.10.10.244/nic  
\[+\] Method:                  GET  
\[+\] Threads:                 10  
\[+\] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  
\[+\] Negative Status codes:   404  
\[+\] User Agent:              gobuster/3.1.0  
\[+\] Timeout:                 10s  
\===============================================================  
2021/06/14 15:30:52 Starting gobuster in directory enumeration mode  
\===============================================================  
/update               (Status: 200) \[Size: 8\]                (Status: 301) \[Size: 310\] \[--> http://10.10.10.244/nic/\]
```

nic/update give us a response with badauth, but we did not send any creds. lets look at the request in burp. 
The problem appears to be that we do not spend any creds. Lets try send the creds we got from the website both as GET and POST request and see if it react to any if it. 


### DNS
Get #dig into the dns service for more information. 
```
dig @10.10.10.244 -x 10.10.10.244  
  
; <<>> DiG 9.16.15-Debian <<>> @10.10.10.244 -x 10.10.10.244  
; (1 server found)  
;; global options: +cmd  
;; Got answer:  
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 19201  
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1  
;; WARNING: recursion requested but not available  
  
;; OPT PSEUDOSECTION:  
; EDNS: version: 0, flags:; udp: 4096  
; COOKIE: 982be53ee688aca00100000060c756e922156fa002c1e1b0 (good)  
;; QUESTION SECTION:  
;244.10.10.10.in-addr.arpa.     IN      PTR  
  
;; AUTHORITY SECTION:  
10.in-addr.arpa.        60      IN      SOA     dns1.dyna.htb. hostmaster.dyna.htb. 2021030304 21600 3600 604800 60  
  
;; Query time: 75 msec  
;; SERVER: 10.10.10.244#53(10.10.10.244)  
;; WHEN: mán jún 14 15:16:47 CEST 2021  
;; MSG SIZE  rcvd: 157
```