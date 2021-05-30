# Tentacle 
Rank : Hard
OS : Linux
IP : 10.10.10.224

Setup
```bash
echo "10.10.10.224 tentacle.htb" >> /etc/hosts
```


## Recon 

Let fire up nmap 

```bash
nmap -sV -sC -Pn tentacle.htb
22/tcp   open   ssh          OpenSSH 8.0 (protocol 2.0)  
| ssh-hostkey:    
|   3072 8d:dd:18:10:e5:7b:b0:da:a3:fa:14:37:a7:52:7a:9c (RSA)  
|   256 f6:a9:2e:57:f8:18:b6:f4:ee:03:41:27:1e:1f:93:99 (ECDSA)  
|\_  256 04:74:dd:68:79:f4:22:78:d8:ce:dd:8b:3e:8c:76:3b (ED25519)  
53/tcp   open   domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)  
| dns-nsid:    
|\_  bind.version: 9.11.20-RedHat-9.11.20-5.el8  
88/tcp   open   kerberos-sec MIT Kerberos (server time: 2021-05-23 07:24:03Z)  
3128/tcp open   http-proxy   Squid http proxy 4.11  
|\_http-server-header: squid/4.11  
|\_http-title: ERROR: The requested URL could not be retrieved  
9090/tcp closed zeus-admin  
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise\_linux:8
```

We are see there is a http page on port *3128* when we go there we are met with a error page. 

![[Pasted image 20210523093427.png]]

We learn about a admin account *j.nakazawa@realcorp.htb* and server *srv01.realcorp.htb* also not the *squid/4.11*

We know the target is hosting a DNS server on port 53

```bash
└──╼ $dnsenum --threads 64 --dnsserver 10.10.10.224 -f /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt  realcorp.htb  
  
ns.realcorp.htb.                         259200   IN    A        10.197.243.77  
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.  
ns.realcorp.htb.                         259200   IN    A        10.197.243.77  
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31

```

and we need to add that proxy in our conf file. Edit **/etc/proxychains4.conf** file
Here I’m using dynamic chain you can also use strict chain

```
http  10.10.10.224 3128
http  127.0.0.1 3128
http  10.197.243.77 3128
```

Spind up Proxychains and do a nmap scan against wpad server. We need to use -sT because we need to do full tcp scan because ofproxying 

```bash
proxychains4 nmap -sT -Pn 10.197.243.31
PORT STATE SERVICE
22/tcp open ssh
53/tcp open domain
80/tcp open http
88/tcp open kerberos-sec
464/tcp open kpasswd5
749/tcp open kerberos-adm
3128/tcp open squid-http
```

We can see there are a few ports open, let add wpad.realcorp.htb to the hosts file. 

```bash
echo “10.197.243.31 wpad.realcorp.htb” >> /etc/hosts
```




$6$2ZKaulGjQ1QUYQHO$OmVJBK0.VeikBcOsxyrLfPCEkrfo6S8SJmHd4FH7el9vHcduJrO7jHYEHjIN7Z4n1c3KBLNe5L9inXSgeBsNS. 
https://jopraveen.wordpress.com/2021/01/30/tentacle/