# Ready
IP : 10.10.10.220

## Nmap
Command : 
nmap -A -oN ready.txt 10.10.10.220
Port: 
22/tp 	ssh
5080/tcp http nginx 1.14.2
OS: 
unknown.

## web application 
Version : 
GitLab Commuity Edition v 11.4.7
Vulnerability to RCE via SSRF
https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/