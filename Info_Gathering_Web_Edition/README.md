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

## DNS

| DNS Concept | Description | Example |
| --- | --- | --- |
| **Domain Name** | A human-readable label for a website or other internet resource. | `www.example.com` |
| **IP Address** | A unique numerical identifier assigned to each device connected to the internet. | `192.0.2.1` |
| **DNS Resolver** | A server that translates domain names into IP addresses. | Your ISP's DNS server or public resolvers like Google DNS (`8.8.8.8`) |
| **Root Name Server** | The top-level servers in the DNS hierarchy. | There are 13 root server identities worldwide, named A–M: `a.root-servers.net` |
| **TLD Name Server** | Servers responsible for specific top-level domains (e.g., `.com`, `.org`). | Verisign for `.com`, PIR for `.org` |
| **Authoritative Name Server** | The server that holds the actual DNS records for a domain. | Often managed by hosting providers or domain registrars. |
| **DNS Record Types** | Different types of information stored in DNS. | `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, etc. |


| Record Type | Full Name | Description | Zone File Example |
| --- | --- | --- | --- |
| **A** | Address Record | Maps a hostname to its IPv4 address. | `www.example.com. IN A 192.0.2.1` |
| **AAAA** | IPv6 Address Record | Maps a hostname to its IPv6 address. | `www.example.com. IN AAAA 2001:db8:85a3::8a2e:370:7334` |
| **CNAME** | Canonical Name Record | Creates an alias for a hostname, pointing it to another hostname. | `blog.example.com. IN CNAME webserver.example.net.` |
| **MX** | Mail Exchange Record | Specifies the mail server(s) responsible for handling email for the domain. | `example.com. IN MX 10 mail.example.com.` |
| **NS** | Name Server Record | Delegates a DNS zone to a specific authoritative name server. | `example.com. IN NS ns1.example.com.` |
| **TXT** | Text Record | Stores arbitrary text information, often used for domain verification or security policies. | `example.com. IN TXT "v=spf1 mx -all"` |
| **SOA** | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com. IN SOA ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
| **SRV** | Service Record | Defines the hostname and port number for specific services. | `_sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com.` |
| **PTR** | Pointer Record | Used for reverse DNS lookups, mapping an IP address to a hostname. | `1.2.0.192.in-addr.arpa. IN PTR www.example.com.` |

## Digging DNS

| Tool | Key Features | Use Cases |
| --- | --- | --- |
| `dig` | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records. |
| `nslookup` | Simpler DNS lookup tool, primarily for A, AAAA, and MX records. | Basic DNS queries, quick checks of domain resolution and mail server records. |
| `host` | Streamlined DNS lookup tool with concise output. | Quick checks of A, AAAA, and MX records. |
| `dnsenum` | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed). | Discovering subdomains and gathering DNS information efficiently. |
| `fierce` | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection. | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets. |
| `dnsrecon` | Combines multiple DNS reconnaissance techniques and supports various output formats. | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis. |
| `theHarvester` | OSINT tool that gathers information from various sources, including DNS records and email addresses. | Collecting email addresses, employee information, and other data associated with a domain from multiple sources. |
| Online DNS Lookup Services | User-friendly interfaces for performing DNS lookups. | Quick and easy DNS lookups when command-line tools are not available, including checking domain availability or basic information. |

### Domain Information Groper (dig)

- Common Commands:

| Command | Description |
| --- | --- |
| `dig domain.com` | Performs a default A record lookup for the domain. |
| `dig domain.com A` | Retrieves the IPv4 address (A record) associated with the domain. |
| `dig domain.com AAAA` | Retrieves the IPv6 address (AAAA record) associated with the domain. |
| `dig domain.com MX` | Finds the mail servers (MX records) responsible for the domain. |
| `dig domain.com NS` | Identifies the authoritative name servers for the domain. |
| `dig domain.com TXT` | Retrieves any TXT records associated with the domain. |
| `dig domain.com CNAME` | Retrieves the canonical name (CNAME) record for the domain. |
| `dig domain.com SOA` | Retrieves the Start of Authority (SOA) record for the domain. |
| `dig @1.1.1.1 domain.com` | Specifies a specific name server to query; in this case, `1.1.1.1`. |
| `dig +trace domain.com` | Shows the full path of DNS resolution. |
| `dig -x 192.168.1.1` | Performs a reverse lookup on the IP address `192.168.1.1` to find the associated hostname. You may need to specify a name server. |
| `dig +short domain.com` | Provides a short, concise answer to the query. |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output. |
| `dig domain.com ANY` | Requests all available DNS records for the domain. **Note:** Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as described in RFC 8482. |

### Using dig

```bash
LordA2117@htb[/htb]$ dig google.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```

1. `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449`:
    - Indicates the type of query, its success status and a unique id for this specific query
        - `;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`: 
            - `qr`: Query Response Flag
            - `rd`: Recursion Desired Flag
            - `ad`: Authentic Data flag
            - The remaining numbers indicate the number of entries in each section of the DNS response: 1 question, 1 answer, 0 authority records, and 0 additional records.
    - `;; WARNING: recursion requested but not available`

2. Footer
- `;; Query time: 0 msec`: This shows the time it took for the query to be processed and the response to be received (0 milliseconds).
- `;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)`: This identifies the DNS server that provided the answer and the protocol used (UDP).
- `;; WHEN: Thu Jun 13 10:45:58 SAST 2024`: This is the timestamp of when the query was made.
- `;; MSG SIZE rcvd: 54`: This indicates the size of the DNS message received (54 bytes).


### Exercises

1. `dig inlanefreight.com`
2. `dig -x 134.209.24.248`
3. `dig mx facebook.com`

## Subdomains

- Importance in Recon
    - `Development and Staging Environments`
    - `Hidden Login Portals`
    - `Legacy Applications`
    - `Sensitive Information`

- Active Enumeration:
    - Via `DNS Zone Transfers` (low success rate)
    - `Brute Force`: Using dnsenum, ffuf or gobuster

- Passive Enumeration:
    - `Certificate Transparency (CT) logs`
    - Public repositories of SSL/TLS certificates
    - Google or duckduckgo (methods like google dorking)

## Subdomain Enumeration

1. Wordlist Selection
    - General Purpose
    - Targeted
    - Custom
2. Interaction and Querying
3. DNS Lookup
4. Filtering and Validation

- Tools:

| Tool | Description |
| --- | --- |
| **dnsenum** | Comprehensive DNS enumeration tool supporting dictionary and brute-force attacks for discovering subdomains. |
| **fierce** | User-friendly tool for recursive subdomain discovery, with wildcard detection and an easy-to-use interface. |
| **dnsrecon** | Versatile DNS reconnaissance tool combining multiple techniques with customizable output formats. |
| **amass** | Actively maintained subdomain discovery tool with extensive integrations and data sources. |
| **assetfinder** | Simple and lightweight tool for finding subdomains using various discovery techniques. |
| **puredns** | Powerful DNS brute-forcing tool designed to resolve and filter discovered subdomains efficiently. |

### DNSEnum

- Capabilities:
    - DNS Record Enumeration
    - Zone Transfer Attempts
    - brute-forcing subdomains
    - Google Scraping
    - Reverse Lookup
    - WHOIS Lookups

```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```

### Exercise

1. `dnsenum --enum inlanefreight.com -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt`

## DNS Zone Transfers

- Zone: A wholesale copy of all DNS records within a zone. If not adequately secure unauthorized parties can download this file.

1. Zone Transfer Request (AXFR): The secondary DNS server initiates the process by sending a zone transfer request to the primary server. This request typically uses the AXFR (Full Zone Transfer) type.
2. SOA Record Transfer: Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record. The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.
3. DNS Records Transmission: The primary server then transfers all the DNS records in the zone to the secondary server, one by one. This includes records like A, AAAA, MX, CNAME, NS, and others that define the domain's subdomains, mail servers, name servers, and other configurations.
4. Zone Transfer Complete: Once all records have been transmitted, the primary server signals the end of the zone transfer. This notification informs the secondary server that it has received a complete copy of the zone data.
5. Acknowledgement (ACK): The secondary server sends an acknowledgement message to the primary server, confirming the successful receipt and processing of the zone data. This completes the zone transfer process.

- If access controls on those who can initiate a zone transfer are improperly managed, we get the zone transfer bug.
- Exploiting Zone transfers:

```bash
dig dig axfr @nsztm1.digi.ninja zonetransfer.me
```

### Exercises

- Just do `dig axfr @<ip> inlanefreight.htb`


## Virtual Hosts

- Access virtual hosts by modifying `/etc/hosts` if the virtual host doesn't have a DNS record associated with it.
- Example Configuration:

```
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

### Fuzzing vhosts

- Gobuster:

```bash
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

- Ffuf:

```bash
ffuf -u http://<target_ip> -w <wordlist> -H "Host: FUZZ.domain.htb" -ac
```

### Exercises

- Just use this command (cuz I like ffuf):

```bash
ffuf -u "http://154.57.164.77:40048" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.inlanefreight.htb" -ac
```

## Certificate Transparency Logs

- Record the issuance of SSL/TLS certificates.
- Purposes:
    - Early Detection of Rogue Certificates
    - Accountability for Certificate Authorities
    - Strengthening the Web PKI (Public Key Infrastructure)
- Uses in Web Recon: Unlike fuzzing they provide a definitive ledger on those certificates that are issued. Furthermore, CT logs can unveil subdomains associated with old or expired certificates. These subdomains might host outdated software or configurations, making them potentially vulnerable to exploitation. In essence, CT logs provide a reliable and efficient way to discover subdomains without the need for exhaustive brute-forcing or relying on the completeness of wordlists.

### Searching CT Logs

| Tool | Key Features | Use Cases | Pros | Cons |
|---|---|---|---|---|
| **crt.sh** | User-friendly web interface, simple search by domain, displays certificate details, SAN entries. | Quick and easy searches, identifying subdomains, checking certificate issuance history. | Free, easy to use, no registration required. | Limited filtering and analysis options. |
| **Censys** | Powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes. | In-depth analysis of certificates, identifying misconfigurations, finding related certificates and hosts. | Extensive data and filtering options, API access. | Requires registration (free tier available). |

### crt.sh lookup

```bash
LordA2117@htb[/htb]$ curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
 
*.dev.facebook.com
*.newdev.facebook.com
*.secure.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
facebook-amex-dev.facebook.com
facebook-amex-sign-enc-dev.facebook.com
newdev.facebook.com
secure.dev.facebook.com
```

## Fingerprinting

- Techniques:
    - Banner Grabbing
    - Analysing http headers
    - Probing for Specific Responses
    - Analysing Page Content

### Tools

| Tool | Description | Features |
| --- | --- | --- |
| **Wappalyzer** | Browser extension and online service for website technology profiling. | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| **BuiltWith** | Web technology profiler that provides detailed reports on a website's technology stack. | Offers both free and paid plans with varying levels of detail. |
| **WhatWeb** | Command-line tool for website fingerprinting. | Uses a vast database of signatures to identify various web technologies. |
| **Nmap** | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting. |
| **Netcraft** | Offers a range of web security services, including website fingerprinting and security reporting. | Provides detailed reports on a website's technology, hosting provider, and security posture. |
| **wafw00f** | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs). | Helps determine if a WAF is present and, if so, its type and configuration. |

### Fingerprinting inlanefreight.com

- Banner Grabbing:

```bash
LordA2117@htb[/htb]$ curl -I inlanefreight.com
```

- wafw00f: `wafw00f <domain>`. This is important as knowing the WAF allows us to figure out how to modify the requests in order to evade detection.

```bash
LordA2117@htb[/htb]$ pip3 install git+https://github.com/EnableSecurity/wafw00f # installation
LordA2117@htb[/htb]$ wafw00f inlanefreight.com
```

- Nikto: `-h` specifies the host and `-Tuning b` tells nikto to run only software identification modules.

```bash
LordA2117@htb[/htb]$ nikto -h inlanefreight.com -Tuning b
```

### Exercises

1. Run nikto
2. Use whatweb on the domain
3. Use whatweb and see the apache server. It also reveals the IP.
