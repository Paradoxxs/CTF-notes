# PersistenceIsFutile
#Challenge #HTB #Forensics #Linux

Find 8 remote access and privilege esclation



Look at cron job running on the server. 
First list the cron task with *-l* and edit with *-e*
```bash
crontab -l  

crontab -e
```

Remove the cron job and one of the issues get remediated. 

What process is running 

```bash
ps auxf

USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND  
root         1  0.0  0.0   2612   608 ?        Ss   17:20   0:00 /bin/sh -c /usr/sbin/sshd -D -p 23  
root         7  0.0  0.0  12180  6832 ?        S    17:20   0:00 sshd: /usr/sbin/sshd -D -p 23 \[listener\] 0 of 10-100 startups  
root         8  0.0  0.1  13900  8768 ?        Ss   17:20   0:00  \\\_ sshd: user \[priv\]  
user        22  0.0  0.0  13900  5300 ?        S    17:20   0:00      \\\_ sshd: user@pts/0  
user        23  0.0  0.0   5996  3992 pts/0    Ss   17:20   0:00          \\\_ -bash  
root       159  0.0  0.0   8312  4636 pts/0    S    18:00   0:00              \\\_ sudo su root  
root       161  0.0  0.0   7020  3532 pts/0    S    18:00   0:00                  \\\_ su root  
root       162  0.0  0.0   5996  3936 pts/0    S    18:00   0:00                      \\\_ bash  
root       169  0.0  0.0   2592  1952 pts/0    S    18:00   0:00                          \\\_ alertd -e /bin/bash -lnp 4444  
root       186  0.0  0.0   4348  2152 pts/0    T    18:01   0:00                          \\\_ crontab -e  
root       187  0.0  0.0   2612   540 pts/0    T    18:01   0:00                          |   \\\_ /bin/sh -c /usr/bin/sensible-editor /tmp/crontab.kNznig/crontab  
root       188  0.0  0.0   2612   596 pts/0    T    18:01   0:00                          |       \\\_ /bin/sh /usr/bin/sensible-editor /tmp/crontab.kNznig/crontab  
root       195  0.0  0.1  20756  9904 pts/0    T    18:01   0:00                          |           \\\_ editor /tmp/crontab.kNznig/crontab  
root       200  0.0  0.0   8048  4544 pts/0    S    18:02   0:00                          \\\_ sudo su user  
root       201  0.0  0.0   7020  3728 pts/0    S    18:02   0:00                              \\\_ su user  
user       202  0.0  0.0   5996  3884 pts/0    S    18:02   0:00                                  \\\_ bash  
root       234  0.0  0.0   8048  4604 pts/0    S    18:03   0:00                                      \\\_ sudo su  
root       235  0.0  0.0   7020  3620 pts/0    S    18:03   0:00                                          \\\_ su  
root       236  0.0  0.0   5996  3980 pts/0    S    18:03   0:00                                              \\\_ bash  
root       243  0.0  0.0   2592  1948 pts/0    S    18:03   0:00                                                  \\\_ alertd -e /bin/bash -lnp 4444  
root       273  0.0  0.0   2512   660 pts/0    T    18:05   0:00                                                  \\\_ alertd  
root       305  0.0  0.0   7652  3280 pts/0    R+   18:11   0:00                                                  \\\_ ps auxf
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