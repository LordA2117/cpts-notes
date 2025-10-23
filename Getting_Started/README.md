# Getting Started

## Pentest Distro

Use any distro you like, I personally use kali or parrot os (if its on pwnbox).

## Staying Organized

While attacking a machine, we should be sure to setup a good filder structure to organize our findings. Sample folder Structure:

```
Projects/
└── Acme Company
    ├── EPT
    │   ├── evidence
    │   │   ├── credentials
    │   │   ├── data
    │   │   └── screenshots
    │   ├── logs
    │   ├── scans
    │   ├── scope
    │   └── tools
    └── IPT
        ├── evidence
        │   ├── credentials
        │   ├── data
        │   └── screenshots
        ├── logs
        ├── scans
        ├── scope
        └── tools
```

## Common Terms

- Shell: A shell is a program that takes user input and passes it to the operating system to perform a specific function.
- Port: A port is an access point on a system (denoted by a number) that runs a service. For example Port 80 runs http, 22 runs SSH etc. Ports can usually run TCP or UDP services so it's important to check both.
- Web Server: An application that runs on a back-end server. A web server can be affected by many types of vulnerabilities. The **OWASP Top 10** is one such list of the top 10 vulnerabilities affecting webapps.

## Basic tools

- SSH: Runs on port 22 and used to grant remote access to a system. It can either be configured to authenticate with a password or do public key authentication. Connect to SSH using something like `OpenSSH`. It is possible to read local private keys or add our public key to gain SSH access as a specific user.
- Netcat: Used to interact with any TCP service.
- Tmux: Terminal Multiplexer. Used to do create a split-screen on a terminal so that we can run multiple commands simultaneously.
- Vim: A modal text-editor used to edit files quickly and easily. It also relies entirely on the keyboard so no mouse is necessary.

### Question

Grab the banner of the above server (spawn the instance)

Ans: Use netcat to interact with the server, it will send you the banner. The answer was `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1`.


## Service Scanning

### Nmap

- Basic nmap scan: `nmap <host>`, it runs a TCP scan by default. This scan completes very quickly as it scans only the first 1000 ports by default.
    - Use `-sC` to use nmap scripts and `-sV` to perform a version scan. 
    - `-p-` enables a scan of all 65535 ports. Using these flags together takes a lot of time.
    - The script scan can cause nmap to report website headers on the scan results.
    - **Banner Grabbing using nmap**: We can use `nmap -sV --script=banner <tgt>` to get the service banner of the target. This is what we did when we used netcat to get the service banner in the previous exercise.
- **FTP**: FTP is a standard protocol and is usually hosted on port 21. Nmap scans can enumerate this, and if scripts are enabled, it can enumerate various aspects of the FTP server such as anonymous login and FTP directories.
- **SMB**: This is usually found on Windows machines. Sensitive data like Network file shares can be found in these. We can use the `smb-os-discovery.nse` script to get the OS version. Linux can also run smb, commonly using  **samba smbd**.
- SNMP: SNMP Community strings provide information and statistics about a router or device.
    - The manufacturer default Community strings of `public` and `private` are usually unchanged. In versions *1* and *2c*, access is controlled by a plaintext community string, discovery of which, gives us access to it.
    - Tools like `onesixtyone` can be used to bruteforce snmp.

### Exercise

- `masscan <tgt> -e tun0 -p 1-65535,U:1-65535`
- `sudo nmap -sC -sV -A <tgt> -p <open ports> -o nmap.txt`
- `ftp -p <tgt>` (anonymous login, download login.txt from pub directory)
- Credentials for bob are not given so I assume we just need to see them and login.
- `smbclient -N -L \\\\<tgt>`
- `smbclient -U bob \\\\<tgt>\\users`, password is *Welcome1*, `cd flag`, `get flag.txt`

Submit all solutions as per the questions.

## Web Enumeration

### Gobuster

- Gobuster can be used to bruteforce directories using the command `gobuster dir -u http://<address>/ -w <wordlist>`. Try using the **dirb common.txt** wordlist or the **seclists** wordlists.
- DNS Bruteforce: Gobuster can also be used to discover subdomains `gobuster dns -d domain.com -w <wordlist>`. This helps us find interesting subdomains for further enumeration.

### Web Enumeration Tips

- Banner Grabbing/ Web Server Headers: cURL can be used to get the web framework, the auth options, and whether the server is missing essential security options or has been misconfigured. 
    - Command: `cURL -IL https://website.com`

- Whatweb: Extract the version of web servers, supporting frameworks, and applications. 
    - Command: `whatweb <ip>`
    - Network enumeration: `whatweb 10.10.10.0/24`

- Certificates: 
    - SSL/TLS are a valuable source of information while using https. Infomation gathered can inclue company name, email addresses etc. These can be used for phishing attacks

- Robots.txt: Used to instruct search engines, which resource can and can't be used for indexing. Obviously, these can contain private pages and stuff.

- Source Code: Examining source code of a webpage (using the view source or inspect option of the browser) can also reveal valuable information, such as developer comments, etc.


### Exercise Solution

- Run gobuster directory bruteforce to find robots.txt
- Go to this page and look into the source code.
- Enter the credentials.
