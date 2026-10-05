# Information Gathering - Web Edition

## Introduction

- Goals:
    - Identifying Assets
    - Discovering Hidden Information
    - Analysing the Attack Surface
    - Gathering Intelligence
- Types of Reconnaissance:
    - Active: Direct interaction with the target
    - Passive: no direct interaction

### Active Reconnaissance

| Technique | Description | Example | Tools | Risk of Detection |
| --- | --- | --- | --- | --- |
| **Port Scanning** | Identifying open ports and services running on the target. | Using Nmap to scan a web server for open ports like 80 (HTTP) and 443 (HTTPS). | Nmap, Masscan, Unicornscan | **High:** Direct interaction with the target can trigger intrusion detection systems (IDS) and firewalls. |
| **Vulnerability Scanning** | Probing the target for known vulnerabilities, such as outdated software or misconfigurations. | Running Nessus against a web application to check for SQL injection flaws or cross-site scripting (XSS) vulnerabilities. | Nessus, OpenVAS, Nikto | **High:** Vulnerability scanners send exploit payloads that security solutions can detect. |
| **Network Mapping** | Mapping the target's network topology, including connected devices and their relationships. | Using traceroute to determine the path packets take to reach the target server, revealing potential network hops and infrastructure. | Traceroute, Nmap | **Medium to High:** Excessive or unusual network traffic can raise suspicion. |
| **Banner Grabbing** | Retrieving information from banners displayed by services running on the target. | Connecting to a web server on port 80 and examining the HTTP banner to identify the web server software and version. | Netcat, curl | **Low:** Banner grabbing typically involves minimal interaction but can still be logged. |
| **OS Fingerprinting** | Identifying the operating system running on the target. | Using Nmap's OS detection capabilities (`-O`) to determine if the target is running Windows, Linux, or another OS. | Nmap, Xprobe2 | **Low:** OS fingerprinting is usually passive, but some advanced techniques can be detected. |
| **Service Enumeration** | Determining the specific versions of services running on open ports. | Using Nmap's service version detection (`-sV`) to determine if a web server is running Apache 2.4.50 or Nginx 1.18.0. | Nmap | **Low:** Similar to banner grabbing, service enumeration can be logged but is less likely to trigger alerts. |
| **Web Spidering** | Crawling the target website to identify web pages, directories, and files. | Running a web crawler like Burp Suite Spider or OWASP ZAP Spider to map out the structure of a website and discover hidden resources. | Burp Suite Spider, OWASP ZAP Spider, Scrapy (customisable) | **Low to Medium:** Can be detected if the crawler's behaviour is not carefully configured to mimic legitimate traffic. |

### Passive Reconnaissance

| Technique | Description | Example | Tools | Risk of Detection |
| --- | --- | --- | --- | --- |
| **Search Engine Queries** | Utilising search engines to uncover information about the target, including websites, social media profiles, and news articles. | Searching Google for "\[Target Name\] employees" to find employee information or social media profiles. | Google, DuckDuckGo, Bing, specialised search engines (e.g., Shodan) | **Very Low:** Search engine queries are normal internet activity and unlikely to trigger alerts. |
| **WHOIS Lookups** | Querying WHOIS databases to retrieve domain registration details. | Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers. | `whois` command-line tool, online WHOIS lookup services | **Very Low:** WHOIS queries are legitimate and do not raise suspicion. |
| **DNS** | Analysing DNS records to identify subdomains, mail servers, and other infrastructure. | Using `dig` to enumerate subdomains of a target domain. | `dig`, `nslookup`, `host`, `dnsenum`, `fierce`, `dnsrecon` | **Very Low:** DNS queries are essential for internet browsing and are not typically flagged as suspicious. |
| **Web Archive Analysis** | Examining historical snapshots of the target's website to identify changes, vulnerabilities, or hidden information. | Using the Wayback Machine to view past versions of a target website to see how it has changed over time. | Wayback Machine | **Very Low:** Accessing archived versions of websites is a normal activity. |
| **Social Media Analysis** | Gathering information from social media platforms like LinkedIn, Twitter, or Facebook. | Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets. | LinkedIn, Twitter, Facebook, specialised OSINT tools | **Very Low:** Accessing public social media profiles is not considered intrusive. |
| **Code Repositories** | Analysing publicly accessible code repositories like GitHub for exposed credentials or vulnerabilities. | Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities. | GitHub, GitLab | **Very Low:** Code repositories are meant for public access, and searching them is not inherently intrusive. |

> NOTE: Passive Recon is usually considered stealthier and less likely to trigger alarms conpared to active recon.

## Whois

- Usage:

```
whois <domain_name>
```

- Information to look out for:
    - Domain Name: The domain name itself (e.g., example.com)
    - Registrar: The company where the domain was registered (e.g., GoDaddy, Namecheap)
    - Registrant Contact: The person or organization that registered the domain.
    - Administrative Contact: The person responsible for managing the domain.
    - Technical Contact: The person handling technical issues related to the domain.
    - Creation and Expiration Dates: When the domain was registered and when it's set to expire.
    - Name Servers: Servers that translate the domain name into an IP address.

- Why it matters:
    - **Identifying Key Personnel** via names, emails, and phone numbers.
    - **Discovering Network Infrastructure** via nameservers, IPs.
    - **Historical Data Analysis** by discovering historical whois records through services like [WhoisFreaks](https://whoisfreaks.com/).

## Utilising Whois

### Scenario 1: Phishing Investigation

- Suspicious email is flagged by a security gateway.
- A whois analysis on the domain of the email revealed the following:
    - Registration Date: Only a few days ago
    - Registrant: Hidden behind a privacy service
    - Nameservers: a known hosting providers for malicious services

### Scenario 2: Malware Analysis

- A malware communicates to a remote server to receive commands and exfiltrate stolen data.
- Whois record of the C2 (Command and Control) server reveals:
    - Registrant: individual using a free service known for anonymity
    - Location: Country with high prevalence of Cybercrime
    - Registrar: Malicious registrar with a history of policy abuse.

### Using Whois

```
LordA2117@htb[/htb]$ whois facebook.com

   Domain Name: FACEBOOK.COM
   Registry Domain ID: 2320948_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrarsafe.com
   Registrar URL: http://www.registrarsafe.com
   Updated Date: 2024-04-24T19:06:12Z
   Creation Date: 1997-03-29T05:00:00Z
   Registry Expiry Date: 2033-03-30T04:00:00Z
   Registrar: RegistrarSafe, LLC
   Registrar IANA ID: 3237
   Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
   Registrar Abuse Contact Phone: +1-650-308-7004
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: A.NS.FACEBOOK.COM
   Name Server: B.NS.FACEBOOK.COM
   Name Server: C.NS.FACEBOOK.COM
   Name Server: D.NS.FACEBOOK.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2024-06-01T11:24:10Z <<<

[...]
Registry Registrant ID:
Registrant Name: Domain Admin
Registrant Organization: Meta Platforms, Inc.
[...]
```

- Key Details Revealed:
    - Domain Registration
        - Registrar
        - Creation Date
        - Expiry Date

- Domain Owner:
    - Registrant/Admin/Tech Organization
    - Registrant/Admin/Tech Contact

- Domain Status:
    - clientDeleteProhibited, clientTransferProhibited, clientUpdateProhibited
    - serverDeleteProhibited, serverTransferProhibited, serverUpdateProhibited

> NOTE: These indicate that the domain is protected from unauthorized changes, transfers or deletions on both the client and server side, implying a high emphasis on security.

- Nameservers:
    - A.NS.FACEBOOK.COM, B.NS.FACEBOOK.COM, C.NS.FACEBOOK.COM, D.NS.FACEBOOK.COM

### Exercises

1. Use `https://www.whois.com/whois/paypal.com` (cuz I was too lazy to open my kali vm)
2. Use `whois tesla.com` (on a terminal :/)
