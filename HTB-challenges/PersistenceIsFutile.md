# PersistenceIsFutile
#Challenge #HTB #Forensics #Linux

Look at cron job running on the server. 
First list the cron task with *-l* and edit with *-e*
```bash
crontab -l  

crontab -e
```

What process is running 

```bash
ps auxf
```

What network connection do we have 

```bash
netstat -pant
```

Are there any authorized key at /root/.ssh/authorized_keys, remove all keys that are not suppose to be there.
```bash
vi /root/.ssh/authorized_keys
```


List services 
```bash
service --status-all
```