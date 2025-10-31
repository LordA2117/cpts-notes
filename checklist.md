# CPTS Checklist

## Enumeration

- To show networks accessible via our vpn `netstat -nr`.
- Nmap: Run nmap using both TCP (-sT) and UDP (-sU) flags to enumerate the ports.
    - `nmap <host>`
    - nmap -sV
    - nmap -sC
    - nmap -p-
    - nmap --script=banner
    - nmap --script=smb-os-discovery.nse
- Netcat: Use it to grab the banner of the service. Usage: `nc <host> <port>`.
- Smbclient: Used to enumerate smb
    - `-N`: Suppresses password prompt
    - `-L`: Retreives list of available shares (usually stuff ending with a $ sign is a default share).
    - Examples: `smbclient -N -L \\\\10.129.42.253`, `smbclient \\\\10.129.42.253\\users` (users is the share we're accessing)
- SNMP: SNMP Community strings provide information and statistics about a router or device.
    - The manufacturer default Community strings of `public` and `private` are usually unchanged. In versions *1* and *2c*, access is controlled by a plaintext community string, discovery of which, gives us access to it.
    - Example Command: `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0`
    - Bruteforce: `onesixtyone -c dict.txt 10.129.42.254`

- Personal Enumeration flow: 
    - First use masscan: `sudo masscan <tgt> -e tun0 -p 1-65535,U:1-65535 --rate=1000` to get all the open ports.
    - Then run `nmap -sC -sV -A` on all the open ports.

### Website Enumeration

- Gobuster:
    - Directory Bruteforce: `gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt`
    - DNS Bruteforce: `gobuster dns -d domain.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt`

- cURL: 
    - Banner grabbing: `cURL -IL https://website.com`

- [EyeWitness](https://github.com/RedSiege/EyeWitness): Takes screenshots from the website, fingerprint it and identify possible default credentials.

- WhatWeb:
    - Normal Scan: `whatweb <ip>`
    - Network Scan: `whatweb 10.10.10.0/24`

- SSL/TLS Certificates
- Robots.txt
- Source Code of a webpage

- ffuf
- [SecLists](https://github.com/danielmiessler/SecLists): A collection of wordlists (highly useful)

## Metasploit Framework
- Start it: `msfconsole`
- Search for an Exploit: `search exploit <exploit_name>`
- Once you use an exploit, we can use a scanner to verify that the target is vulnerable

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > check

[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
```

- Use the `exploit` command to run the exploit

## Shells

- [RevShells.com](https://revshells.com/)
- [Payload All The Things](https://swisskyrepo.github.io/InternalAllTheThings/)

## Privilege Escalation

- SSH: Read local private keys or add our own public key.

## Pentest Report

- [Template](https://labs.hackthebox.com/storage/press/samplereport/sample-penetration-testing-report-template.pdf)
