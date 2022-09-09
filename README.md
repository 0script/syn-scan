# syn-scan  
## Table of content  
* [About the project](#about-the-project)  
* [TCP Syn Scan](#tcp-syn-scan)
* [Technologies](#technologies)  
* [Setup](#setup)  
## About the project  
>TCP  SYN scan implementation in python . A TCP Syn scan on a given host consist in exploiting the 3 way handsake used by the protocol in order to detect open port : 
Some more detail about the syn scan with image sir .....

## TCP Syn Scan  
To detect which port are open we will send syn packet to initiate connection , if the host respond with ack or syn/ack packet we know that the port is open then we send a rst (reset) packet to trigger an error .  

## Technologies  
* the **python** programming language     
* the **scapy** library to manipulate network packet .  

## Setup  
```shell  
#setup shell cmd  
$git https://github.com/0script/syn-scan  
$cd syn-scan/
$sudo python3 synscan.py <target-ip> <target-port>
```  