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

- CeWL for generating wordlists by scraping the website, syntax: `cewl <url>`


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

### Full TTY from a reverse shell.

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```

```bash
script /dev/null -c /bin/bash
```

## Privilege Escalation

- SSH: Read local private keys or add our own public key.
- Checklists:
    - Windows: [HackTricks](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html), [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md).
    - Linux: [HackTricks](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html), [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- Scripts:
    - Linux: linpeas, LinEnum, linuxprivchecker
    - Windows: winpeas, seatbelt, jaws
- Searchsploit: Use it to find kernel exploits.
- Inspect Installed Software:
    - Check for installed software on linux using `dpkg -l`
    - Check for the same on windows in the `C:\Programs` folder
- Check user privileges
- Vulnerable Binaries:
    - Check for exploitable binaries on linux using [GTFOBins](https://gtfobins.github.io/)
    - For windows use [LOLBAS](https://lolbas-project.github.io/#)
- User Privileges:
    - Exploit based on the output obtained from `sudo -l`
- Scheduled Tasks:
    - In Linux, CRON jobs run things periodically, this can be used to create our own job and run things as root.
        - `/etc/crontab`
        - `/etc/cron.d`
        - `/var/spool/cron/crontabs/root`
- Exposed Credentials:
    - Check config, log or backup files. Usually the enumeration scripts find these for you.
- SSH Keys:
    - SSH Private keys can be used for privesc

## Pentest Report

- [Template](https://labs.hackthebox.com/storage/press/samplereport/sample-penetration-testing-report-template.pdf)
- [Report Creation Tool](https://docs.sysreptor.com/)
