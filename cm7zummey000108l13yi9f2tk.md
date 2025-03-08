---
title: "CVE-2024-9014: pgAdmin Unauthorized Access"
seoTitle: "pgAdmin Security Flaw: Unauthorized Access"
seoDescription: "Critical security flaw in pgAdmin4's OAuth2 allows unauthorized access. Assigned CVE-2024-9014 with a severity score of 9.9"
datePublished: Sat Mar 08 2025 06:54:06 GMT+0000 (Coordinated Universal Time)
cuid: cm7zummey000108l13yi9f2tk
slug: cve-2024-9014
tags: hacking, kali-linux, vulnerability, pgadmin, cve, cve-2024

---

`pgAdmin is the most popular and feature-rich Open Source administration and development platform for PostgreSQL, the world's most advanced Open Source database.`

`Reference: [`[`https://www.pgadmin.org`](https://www.pgadmin.org)`]`

`A flaw resides in pgAdmin4's OAuth2 authentication mechanism. It allows attackers to potentially obtain the client ID and secret, leading to unauthorized access to user data. This vulnerability has been assigned a critical severity score of 9.9.`

`Reference:` [`https://nvd.nist.gov/vuln/detail/CVE-2024-9014`](https://nvd.nist.gov/vuln/detail/CVE-2024-9014)

Let’s start with the nmap scan.

```apache
nmap -sC -sV demo.ine.local
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-08 11:59 IST
Nmap scan report for demo.ine.local (10.4.23.65)
Host is up (0.0096s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 89:c6:b3:40:24:38:42:0d:0f:52:4b:4e:c9:0c:cd:f1 (RSA)
|   256 6a:32:ae:b3:e5:51:cf:a6:a5:5c:3f:e7:f9:27:4d:cc (ECDSA)
|_  256 23:9b:25:1b:00:5a:b1:8a:f1:52:5b:0f:be:8a:b0:81 (ED25519)
80/tcp   open  http          gunicorn
|_http-server-header: gunicorn
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 500 INTERNAL SERVER ERROR
|     Server: gunicorn
|     Date: Sat, 08 Mar 2025 06:29:09 GMT
|     Connection: close
|     Cache-Control: no-cache, no-store, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     Content-Type: application/json
|     Content-Length: 109
|     Vary: Accept-Encoding
|     X-Frame-Options: SAMEORIGIN
|     Content-Security-Policy: default-src ws: http: data: blob: 'unsafe-inline' 'unsafe-eval';
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Set-Cookie: pga4_session=bfb89f00-73bd-45e6-9445-1bdc4af9e28f!AkURZTP6AB8EYiaM24uixDj2+V/M/RnJomjpNOvwP3E=; Expires=Sun, 09 Mar 2025 06:29:09 GMT; HttpOnly; Path=/; SameSite=Lax
|     {"success":0,"errormsg":"Port could not be cast to integer value as ':'","info":"","result":null,"data":null}
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 08 Mar 2025 06:29:09 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|     Vary: Accept-Encoding
|     X-Frame-Options: SAMEORIGIN
|     Content-Security-Policy: default-src ws: http: data: blob: 'unsafe-inline' 'unsafe-eval';
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Set-Cookie: pga4_session=02006866-9ed0-498d-ad1d-96cd32a9c7a8!noPAQDtLrMgwF0Kv/Y+212UoTMc7tPMYbYjLxFHGS5w=; Expires=Sun, 09 Mar 2025 06:29:09 GMT; HttpOnly; Path=/; SameSite=Lax
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
| http-title: pgAdmin 4
|_Requested resource was /login?next=/
3389/tcp open  ms-wbt-server xrdp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=3/8%Time=67CBE3B5%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,2E8,"HTTP/1\.0\x20500\x20INTERNAL\x20SERVER\x20ERROR\r\nServer
SF::\x20gunicorn\r\nDate:\x20Sat,\x2008\x20Mar\x202025\x2006:29:09\x20GMT\
SF:r\nConnection:\x20close\r\nCache-Control:\x20no-cache,\x20no-store,\x20
SF:must-revalidate\r\nPragma:\x20no-cache\r\nExpires:\x200\r\nContent-Type
SF::\x20application/json\r\nContent-Length:\x20109\r\nVary:\x20Accept-Enco
SF:ding\r\nX-Frame-Options:\x20SAMEORIGIN\r\nContent-Security-Policy:\x20d
SF:efault-src\x20ws:\x20http:\x20data:\x20blob:\x20'unsafe-inline'\x20'uns
SF:afe-eval';\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x
SF:201;\x20mode=block\r\nSet-Cookie:\x20pga4_session=bfb89f00-73bd-45e6-94
SF:45-1bdc4af9e28f!AkURZTP6AB8EYiaM24uixDj2\+V/M/RnJomjpNOvwP3E=;\x20Expir
SF:es=Sun,\x2009\x20Mar\x202025\x2006:29:09\x20GMT;\x20HttpOnly;\x20Path=/
SF:;\x20SameSite=Lax\r\n\r\n{\"success\":0,\"errormsg\":\"Port\x20could\x2
SF:0not\x20be\x20cast\x20to\x20integer\x20value\x20as\x20':'\",\"info\":\"
SF:\",\"result\":null,\"data\":null}")%r(HTTPOptions,237,"HTTP/1\.0\x20200
SF:\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Sat,\x2008\x20Mar\x202025\x20
SF:06:29:09\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20HEAD,\x20GET\r\nVary:\x20Acce
SF:pt-Encoding\r\nX-Frame-Options:\x20SAMEORIGIN\r\nContent-Security-Polic
SF:y:\x20default-src\x20ws:\x20http:\x20data:\x20blob:\x20'unsafe-inline'\
SF:x20'unsafe-eval';\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protec
SF:tion:\x201;\x20mode=block\r\nSet-Cookie:\x20pga4_session=02006866-9ed0-
SF:498d-ad1d-96cd32a9c7a8!noPAQDtLrMgwF0Kv/Y\+212UoTMc7tPMYbYjLxFHGS5w=;\x
SF:20Expires=Sun,\x2009\x20Mar\x202025\x2006:29:09\x20GMT;\x20HttpOnly;\x2
SF:0Path=/;\x20SameSite=Lax\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,121,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nCo
SF:ntent-Type:\x20text/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\
SF:x20<head>\n\x20\x20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</hea
SF:d>\n\x20\x20<body>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x2
SF:0\x20\x20\x20Invalid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Ver
SF:sion:\x20&#x27;RTSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.70 seconds
```

From the output we can see that it has `port 80 http` open which is running `gunicorn`. So, let’s visit that.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741415717256/14f296d2-3b36-4806-bf9a-4431086f62b0.png align="center")

We have a login page that is running pgAdmin.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741415867611/57c2bc17-f47c-4bc5-871d-ca5ec070f0c5.png align="center")

A quick Google search provides us with information that it has a CVE assigned to it which is related to `Authentication bypass`

The specific vulnerability CVE-2024-9014 is found, with links to details from trusted sources like:

* \[[https://nvd.nist.gov/vuln/detail/CVE-2024-9014](https://nvd.nist.gov/vuln/detail/CVE-2024-9014)\]
    
* \[[https://github.com/EQSTLab/CVE-2024-9014](https://github.com/EQSTLab/CVE-2024-9014)\]
    
* \[[https://github.com/pgadmin-org/pgadmin4/issues/7945](https://github.com/pgadmin-org/pgadmin4/issues/7945)\]
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741415964064/251b8237-38e1-4f82-8355-43b190bf2233.png align="center")

Additionally, a Nuclei template for this CVE is available:

* \[[https://github.com/projectdiscovery/nuclei-templates/blob/v10.0.3/http/cves/2024/CVE-2024-9014.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/v10.0.3/http/cves/2024/CVE-2024-9014.yaml)\]
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741415984630/c4318bb7-9f0b-408b-9da8-cec39f5de9eb.png align="center")

```yaml
id: CVE-2024-9014

info:
  name: pgAdmin 4 - Authentication Bypass
  author: s4e-io
  severity: critical
  description: |
    pgAdmin 4 versions 8.11 and earlier are vulnerable to a security flaw in OAuth2 authentication. This vulnerability allows an attacker to potentially obtain the client ID and secret, leading to unauthorized access to user data.
  reference:
    - https://github.com/EQSTLab/CVE-2024-9014
    - https://github.com/pgadmin-org/pgadmin4/issues/7945
    - https://nvd.nist.gov/vuln/detail/CVE-2024-9014
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 9.9
    cve-id: CVE-2024-9014
    cwe-id: CWE-522
    epss-score: 0.00043
    epss-percentile: 0.09595
  metadata:
    verified: true
    max-request: 1
    vendor: pgadmin-org
    product: pgadmin4
    fofa-query: "pgadmin4"
  tags: cve,cve2024,pgadmin,exposure,auth-bypass

http:
  - raw:
      - |
        GET /login?next=/ HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: regex
        part: body
        negative: true
        regex:
          - 'OAUTH2_CLIENT_SECRET": null'

      - type: word
        part: body
        words:
          - '<title>pgAdmin 4</title>'
          - 'OAUTH2_CLIENT_SECRET'
        condition: and

      - type: status
        status:
          - 200
# digest: 4b0a004830460221009c2ded269bf8e0dbb07418a79cf9f4af8cebfd7f1780bd5fe9f2d155058f7b68022100ea82fa3dfa85ff37352e5a7867378ef47e10b5c49290c84ef60e19709a6506b0:922c64590222798bb761d5b6d8e72950
```

So, from this research, we concluded that the affected version is 8.11 and earlier

Let’s first check the source code and see if any data is exposed in the source code or not.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741416226473/f4353288-2004-4212-8ad9-9bbe44ddb09b.png align="center")

Looking for `Client_ID` and `Client_Secret` we can see that we got our flag an attacker could use these credentials to gain unauthorized access.

Flag: ***Thi$i$th3flaGGG!***