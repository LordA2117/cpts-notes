# Footprinting

## Enumeration Principles

- Our goal is not to get at the systems but to find all the ways to get there.
- Tenets of Enumeration: 

1. There is more than meets the eye. Consider all points of view.
2. Distinguish between what we see and what we do not see.
3. There are always ways to gain more information. Understand the target.


## Enumeration Methodology

- 3 Levels:
    - Infrastructure-based
    - Host-based
    - OS-Based

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/112/enum-method33.png)

> The image is not a full list of items, just the main categories.

| Layer                      | Description                                                                                            | Information Categories                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| **1. Internet Presence**   | Identification of internet presence and externally accessible infrastructure.                          | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures             |
| **2. Gateway**             | Identify the possible security measures protecting the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare                         |
| **3. Accessible Services** | Identify accessible interfaces and services that are hosted externally or internally.                  | Service Type, Functionality, Configuration, Port, Version, Interface                                      |
| **4. Processes**           | Identify the internal processes, sources, and destinations associated with the services.               | PID, Processed Data, Tasks, Source, Destination                                                           |
| **5. Privileges**          | Identification of the internal permissions and privileges to the accessible services.                  | Groups, Users, Permissions, Restrictions, Environment                                                     |
| **6. OS Setup**            | Identification of the internal components and systems setup.                                           | OS Type, Patch Level, Network Configuration, OS Environment, Configuration Files, Sensitive Private Files |


- Internet presence: The goal of this layer is to identify all possible target systems and interfaces that can be tested.
- Gateway: The goal is to understand what we are dealing with and what we have to watch out for.
- Accessible Services: This layer aims to understand the reason and functionality of the target system and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively.
- Processes: The goal here is to understand these factors and identify the dependencies between them.
- Privileges: It is crucial to identify these and understand what is and is not possible with these privileges.
- OS Setup: The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.

## Domain Information

- Passive Enumeration:
    - Third Party services
    - Company Main Website

### Online Presence

- SSL Certificate: Same certificate could be used for multiple domains, revealing multiple subdomains
- [crt.sh](https://crt.sh/): Subdomain Enumeration
    - Example:

```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```

- Finding hosts directly accessible from the internet and not hosted by third-party hosts:

```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

- [Shodan](https://www.shodan.io/): Find devices and systems permanently connected to the internet.
    - Getting IP Lists from shodan:

```bash
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

- DNS Records: Use the `dig` command to discover DNS records.

```bash
dig any <domain>
```

### Cloud Resources

- AWS, GCP, Azure
- Even though companies may provide infra centrally, it doesn't mean it's secure, mainly due to the choices of configuration made by the respective administrators.
- Enumerating company-hosted servers:

```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

- Cloud storage can often be found in DNS lists, more so when used by other employees of the company.
- Google Dorks: `inurl:` and `intext:` google dorks can help with finding hidden resources that are indexed online.
- [domain.glass](https://domain.glass/): Does a DNS/Whois lookup and also provides info about the company infrastructure.
- [GrayHatWarfare](https://buckets.grayhatwarfare.com/): Does a similar thing to domain.glass, but also allows filtering based on AWS, GCP and other cloud providers.
- Leaked SSH Keys: Leaked public and private keys allow users to log on to machines without a password.

### Staff

- Look for employees on [LinkedIn](http://linkedin.com/) or [Xing](xing.com). Look at the job postings of the company to know the potential tech stack they use and/or the skillset of the staff. Look at employee profiles.

## FTP

- Application layer
- Control channel via **port 21** comms channel via **port 20**.
- Cleartext protocol so it can be sniffed if the network conditions are right.
- Anonymous FTP login
- TFTP: Trivial FTP, for file transfers. No auth, uses UDP. Can't list directories.

- Default Configuration:
    - vsFTPd
    - Config file: `cat /etc/vsftpd.conf | grep -v "#"`

| Setting                                                       | Description                                                                       |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `listen=NO`                                                   | Run from inetd or as a standalone daemon?                                         |
| `listen_ipv6=YES`                                             | Listen on IPv6?                                                                   |
| `anonymous_enable=NO`                                         | Enable anonymous access?                                                          |
| `local_enable=YES`                                            | Allow local users to log in?                                                      |
| `dirmessage_enable=YES`                                       | Display active directory messages when users go into certain directories?         |
| `use_localtime=YES`                                           | Use local time?                                                                   |
| `xferlog_enable=YES`                                          | Activate logging of uploads/downloads?                                            |
| `connect_from_port_20=YES`                                    | Connect from port 20?                                                             |
| `secure_chroot_dir=/var/run/vsftpd/empty`                     | Name of an empty directory.                                                       |
| `pam_service_name=vsftpd`                                     | This string is the name of the PAM service `vsftpd` will use.                     |
| `rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem`          | Specifies the location of the RSA certificate used for SSL-encrypted connections. |
| `rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key` | Specifies the location of the RSA private key used for SSL-encrypted connections. |
| `ssl_enable=NO`                                               | Enable SSL/TLS encrypted connections?                                             |


#### FTPusers

- `/etc/ftpusers` contains users that are denied FTP access, so pay attention to it.

#### Dangerous Settings

| Setting                        | Description                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| `anonymous_enable=YES`         | Allow anonymous login?                                                                                        |
| `anon_upload_enable=YES`       | Allow anonymous users to upload files?                                                                        |
| `anon_mkdir_write_enable=YES`  | Allow anonymous users to create new directories?                                                              |
| `no_anon_password=YES`         | Do not ask anonymous users for a password?                                                                    |
| `anon_root=/home/username/ftp` | Root directory for anonymous users.                                                                           |
| `write_enable=YES`             | Allow the use of FTP write commands such as `STOR`, `DELE`, `RNFR`, `RNTO`, `MKD`, `RMD`, `APPE`, and `SITE`. |


- Anonymous Login: Allows users to login without legitimate credentials.
- vsFTPd Status: Shows server Status
- vsFTPd detailed output: Gives detailed output

| Setting                   | Description                                                              |
| ------------------------- | ------------------------------------------------------------------------ |
| `dirmessage_enable=YES`   | Show a message when users first enter a new directory?                   |
| `chown_uploads=YES`       | Change ownership of anonymously uploaded files?                          |
| `chown_username=username` | User who is given ownership of anonymously uploaded files.               |
| `local_enable=YES`        | Enable local users to log in?                                            |
| `chroot_local_user=YES`   | Restrict local users to their home directory (chroot jail)?              |
| `chroot_list_enable=YES`  | Use a list of local users for chroot behavior exceptions/configuration?  |
| `hide_ids=YES`            | Display all user and group information in directory listings as `"ftp"`. |
| `ls_recurse_enable=YES`   | Allow recursive directory listings.                                      |


- Download a file: Use the `get` command
- Downloading all available ftp files:

```bash
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

- Uploading a file: Use the `put` command

### Footprinting FTP

- Nmap: The nmap scripting engine contains various scripts for footprinting FTP.
- Connecting with FTP which has SSL/TLS:

```bash
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

## SMB

- Regulates access to files and directories, and other network resources such as printers, routers or interfaces released for the network.

### Samba

- Implements CIFS (Common Internet File System), originally created

| SMB Version | Supported | Features |
|-------------|-----------|----------|
| CIFS | Windows NT 4.0 | Communication via NetBIOS interface |
| SMB 1.0 | Windows 2000 | Direct connection via TCP |
| SMB 2.0 | Windows Vista, Windows Server 2008 | Performance upgrades, improved message signing, caching feature |
| SMB 2.1 | Windows 7, Windows Server 2008 R2 | Locking mechanisms |
| SMB 3.0 | Windows 8, Windows Server 2012 | Multichannel connections, end-to-end encryption, remote storage access |
| SMB 3.0.2 | Windows 8.1, Windows Server 2012 R2 | — |
| SMB 3.1.1 | Windows 10, Windows Server 2016 | Integrity checking, AES-128 encryption |


### Default Configuration

```bash
LordA2117@htb[/htb]$ cat /etc/samba/smb.conf | grep -v "#\|\;" 

[global]
   workgroup = DEV.INFREIGHT.HTB
   server string = DEVSMB
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes

   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
```

### Default Settings

| Setting | Description |
|---------|-------------|
| `[sharename]` | The name of the network share. |
| `workgroup = WORKGROUP/DOMAIN` | Workgroup that will appear when clients query. |
| `path = /path/here/` | The directory to which the user is to be given access. |
| `server string = STRING` | The string that will show up when a connection is initiated. |
| `unix password sync = yes` | Synchronize the UNIX password with the SMB password. |
| `usershare allow guests = yes` | Allow non-authenticated users to access the defined share. |
| `map to guest = bad user` | Specifies what to do when a user login request doesn't match a valid UNIX user. |
| `browseable = yes` | Should this share be shown in the list of available shares? |
| `guest ok = yes` | Allow connecting to the service without using a password. |
| `read only = yes` | Allow users to read files only. |
| `create mask = 0700` | Specifies the permissions to set for newly created files. |

### Dangerous Settings

| Setting | Description |
|---------|-------------|
| `browseable = yes` | Allow listing available shares in the current share. |
| `read only = no` | Forbid the creation and modification of files. |
| `writable = yes` | Allow users to create and modify files. |
| `guest ok = yes` | Allow connecting to the service without using a password. |
| `enable privileges = yes` | Honor privileges assigned to a specific SID. |
| `create mask = 0777` | Specifies the permissions to assign to newly created files. |
| `directory mask = 0777` | Specifies the permissions to assign to newly created directories. |
| `logon script = script.sh` | Script to execute when the user logs in. |
| `magic script = script.sh` | Script to execute when the specified script is closed. |
| `magic output = script.out` | Location where the output of the magic script is stored. |

- NOTE: Look at the man pages for samba to get a better overview of the dangerous settings.


### SMBClient

- Connecting to a share: `smbclient -N -L //<ip>/sharename`
- Downloading a file: `get <file>`
- Check Status: `smbstatus`

### Footprinting SMB

- Nmap: `nmap 10.129.14.128 -sV -sC -p139,445`
- RPCClient: `rpcclient -U "" 10.129.14.128` (look at man page for more details)

| Query | Description |
|--------|-------------|
| `srvinfo` | Server information. |
| `enumdomains` | Enumerate all domains that are deployed in the network. |
| `querydominfo` | Provides domain, server, and user information of deployed domains. |
| `netshareenumall` | Enumerates all available shares. |
| `netsharegetinfo <share>` | Provides information about a specific share. |
| `enumdomusers` | Enumerates all domain users. |
| `queryuser <RID>` | Provides information about a specific user. |
| `querygroup <rid>` | Provides information about a specific group. |

- Bruteforcing user RIDs: 

```bash
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

- Impacket [samrdump.py](https://wadcoms.github.io/wadcoms/Impacket-SAMRDump/): `impacket_samrdump <ip>` (changes based on OS)
- SMBmap: `smbmap <ip>`
- CrackMapExec: `crackmapexec smb 10.129.14.128 --shares -u '' -p ''`
- enum4linux-ng: `./enum4linux-ng.py 10.129.14.128 -A`

## NFS

- Network File System
- Port 111 (tcp, udp)
- No authorization
- Common auth mechanism via unix uid/gid and group memberships.

### Default Configuration

- `/etc/exports` contains a table of physical filesystems on the server accessible by the clients.

```bash
LordA2117@htb[/htb]$ cat /etc/exports 

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)

```

- Options:

| Option             | Description                                                                                                                            |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `rw`               | Read and write permissions.                                                                                                            |
| `ro`               | Read-only permissions.                                                                                                                 |
| `sync`             | Synchronous data transfer (a bit slower).                                                                                              |
| `async`            | Asynchronous data transfer (a bit faster).                                                                                             |
| `secure`           | Ports above 1024 will not be used.                                                                                                     |
| `insecure`         | Ports above 1024 will be used.                                                                                                         |
| `no_subtree_check` | Disables checking of subdirectory trees.                                                                                               |
| `root_squash`      | Maps files created by the root user (UID/GID 0) to the anonymous UID/GID, preventing root from having root privileges on an NFS mount. |

- ExportFS: Shares the folder to a specified subnet

```bash
root@nfs:~# echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
root@nfs:~# systemctl restart nfs-kernel-server 
root@nfs:~# exportfs

/mnt/nfs        10.129.14.0/24
```

### Dangerous Settings

| Option           | Description                                                                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `rw`             | Read and write permissions.                                                                                                                |
| `insecure`       | Ports above 1024 will be used.                                                                                                             |
| `nohide`         | If another file system is mounted beneath an exported directory, it is also exported through its own export entry.                         |
| `no_root_squash` | Files created by the root user retain UID/GID 0, allowing the root user on the client to have root privileges on the exported file system. |


### Footprinting NFS

- TCP ports 111 and 2049 are essential.
- Nmap:
    - rpcinfo: Retrieves a list of all currently running RPC services, their names and descriptions, and the ports they use.

```
LordA2117@htb[/htb]$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:12 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00018s latency).

PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41982/udp6  mountd
|   100005  1,2,3      45837/tcp   mountd
|   100005  1,2,3      47217/tcp6  mountd
|   100005  1,2,3      58830/udp   mountd
|   100021  1,3,4      39542/udp   nlockmgr
|   100021  1,3,4      44629/tcp   nlockmgr
|   100021  1,3,4      45273/tcp6  nlockmgr
|   100021  1,3,4      47524/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.58 seconds
```

```bash
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

- Show available NFS shares:

```bash
LordA2117@htb[/htb]$ showmount -e 10.129.14.128

Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

- Mount an NFS share:

```bash
LordA2117@htb[/htb]$ mkdir target-NFS
LordA2117@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
LordA2117@htb[/htb]$ cd target-NFS
LordA2117@htb[/htb]$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

- List contents with usernames and group names:

```bash
ls -l mnt/nfs/ # Contents with usernames and group names
ls -n mnt/nfs/ # Contents with UIDs and GUIDs
```

- If root_squash is set, the files cannot be edited.
- Unmounting: `sudo umount ./target-NFS`

## DNS

- Full Form: Domain Name System

| **Server Type**                  | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DNS Root Server**              | The root servers of the DNS are responsible for the top-level domains (TLDs). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain names and IP addresses. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe.         |
| **Authoritative Nameserver**     | Authoritative name servers hold authority for a particular DNS zone. They only answer queries for their area of responsibility, and their information is considered authoritative. If an authoritative name server cannot answer a client's query, the root name server helps direct the request. Based on the domain, organization, or country, authoritative nameservers provide answers to recursive DNS nameservers, assisting in locating the correct web server(s). |
| **Non-authoritative Nameserver** | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they obtain information about DNS zones by performing recursive or iterative DNS queries and return cached or retrieved results to clients.                                                                                                                                                                                                                                        |
| **Caching DNS Server**           | Caching DNS servers temporarily store DNS information obtained from other name servers for a specified period, reducing lookup time for repeated requests. The authoritative name server determines the cache duration using the Time to Live (TTL) value.                                                                                                                                                                                                                |
| **Forwarding Server**            | Forwarding servers perform a single function: they forward DNS queries to another DNS server, typically a recursive resolver, instead of resolving the queries themselves.                                                                                                                                                                                                                                                                                                |
| **Resolver**                     | Resolvers are not authoritative DNS servers but perform domain name resolution locally on a computer, router, or operating system by sending DNS queries to appropriate DNS servers and returning the corresponding IP addresses.                                                                                                                                                                                                                                         |
- DNS is unencrypted
- DNS Records:

| **DNS Record** | **Description**                                                                                                                                                                                                                                        |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **A**          | Returns the IPv4 address associated with the requested domain name.                                                                                                                                                                                    |
| **AAAA**       | Returns the IPv6 address associated with the requested domain name.                                                                                                                                                                                    |
| **MX**         | Specifies the mail server(s) responsible for receiving email on behalf of the domain.                                                                                                                                                                  |
| **NS**         | Identifies the authoritative DNS name servers for the domain.                                                                                                                                                                                          |
| **TXT**        | Stores arbitrary text information. Common uses include domain ownership verification (e.g., Google Search Console), SSL certificate validation, and email authentication records such as SPF, DKIM, and DMARC to help prevent spam and email spoofing. |
| **CNAME**      | Creates an alias for another domain name. For example, if `www.example.com` should point to the same IP address as `example.com`, you create an **A** record for `example.com` and a **CNAME** record for `www.example.com`.                           |
| **PTR**        | Used for reverse DNS lookups by mapping an IP address back to its corresponding domain name.                                                                                                                                                           |
| **SOA**        | The **Start of Authority (SOA)** record provides administrative information about the DNS zone, including the primary nameserver, the email address of the administrator, the zone serial number, and DNS synchronization timers.                      |

### Default Configuration

- 3 types configuration files:
    - local DNS config files
    - zone files
    - reverse name resolution files
- Usually the DNS server Bind9 is used in linux distros.
- Usual configuration files are `named.conf`, `named.conf.local`, `named.conf.options`, `named.conf.log`.

```bash
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

- Reverse name resolution zone files

```bash
root@bind9:~# cat /etc/bind/db.10.129.14

;
; BIND reverse data file for local loopback interface
;
$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

5    IN     PTR    server1.domain.com.
7    IN     MX     mx.domain.com.
...SNIP...
```

### Dangerous Settings

- Look at [this resource](https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64) for a list of vulns targeting bind9.
- Look at [this archive](https://web.archive.org/web/20250329174745/https://securitytrails.com/blog/most-popular-types-dns-attacks) by SecurityTrails for the most popular attacks on DNS servers.


| **Option**          | **Description**                                                                                    |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| **allow-query**     | Specifies which hosts or networks are permitted to send DNS queries to the server.                 |
| **allow-recursion** | Specifies which hosts or networks are allowed to perform recursive DNS queries through the server. |
| **allow-transfer**  | Specifies which hosts or DNS servers are permitted to receive DNS zone transfers from the server.  |
| **zone-statistics** | Enables the collection of statistical data and performance metrics for DNS zones.                  |


### Footprinting DNS

- dig ns query:

```bash
dig ns inlanefreight.htb @10.129.14.128
```

- dig version query:

```bash
dig CH TXT version.bind 10.129.120.85
```

- dig any query:

```bash
dig any inlanefreight.htb @10.129.14.128
```

- Zone Transfer: Transfer of zones to another server in DNS, usually happens over port 53.

- dig axfr zone transfer:

```bash
dig axfr inlanefreight.htb @10.129.14.128
```

- Subdomain bruteforcing: Multiple ways

1. ffuf:

```bash
ffuf -u https://example.com -H "Host: FUZZ.example.com" -w wordlist.txt -ac
```

2. bash

```bash
LordA2117@htb[/htb]$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

3. DNSEnum

```bash
LordA2117@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb

dnsenum VERSION:1.2.6

-----   inlanefreight.htb   -----


Host's addresses:
__________________



Name Servers:
______________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: ns.inlanefreight.htb at /usr/bin/dnsenum line 900 thread 1.

Trying Zone Transfer for inlanefreight.htb on ns.inlanefreight.htb ...
AXFR record query failed: no nameservers


Brute forcing with /home/cry0l1t3/Pentesting/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:
_______________________________________________________________________________________________________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136
mail1.inlanefreight.htb.                 604800   IN    A        10.129.18.201
app.inlanefreight.htb.                   604800   IN    A        10.129.18.15
ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136

...SNIP...
done.
```

### Exercise Tips

- Perform all operations on every subdomain.
- A subdomain might have subdomains so fuzz out those as well.

## SMTP

- Sending emails in an IP network.
- Port 25 or Port 487
- Supports SSL/TLS
- SMTP Client: Mail User Agent (MUA)
- Mail Transfer Agent (MTA): Software to send ans receive emails
- Mail Submission Agent (MSA): Checks validity/origin of the mail
- Look up smtp [here](https://www.samlogic.net/articles/smtp-commands-reference.htm)

### Configuration

| **Command** | **Description** |
| --- | --- |
| **AUTH PLAIN** | AUTH is a service extension used to authenticate the client. |
| **HELO** | The client logs in with its computer name and thus starts the session. |
| **MAIL FROM** | The client names the email sender. |
| **RCPT TO** | The client names the email recipient. |
| **DATA** | The client initiates the transmission of the email. |
| **RSET** | The client aborts the initiated transmission but keeps the connection between client and server. |
| **VRFY** | The client checks if a mailbox is available for message transfer. |
| **EXPN** | The client also checks if a mailbox is available for messaging with this command. |
| **NOOP** | The client requests a response from the server to prevent disconnection due to time-out. |
| **QUIT** | The client terminates the session. |

- TELNET - ELHO/HELO:

```bash
LordA2117@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 


HELO mail1.inlanefreight.htb

250 mail1.inlanefreight.htb


EHLO mail1

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

- Telnet - VRFY: Verify users on the system

```bash
VRFY root

252 2.0.0 root


VRFY cry0l1t3

252 2.0.0 cry0l1t3


VRFY testuser

252 2.0.0 testuser
```

> Note: Sometimes we may have to work through a web proxy. We can also make this web proxy connect to the SMTP server. The command that we would send would then look something like this: CONNECT 10.129.14.128:25 HTTP/1.0

### Dangerous Settings

- Open Relay Configuration: `0.0.0.0/0`, this setting allows servers to send fake emails, also allows to spoof and read emails.

### Footprinting

- Default: `sudo nmap 10.129.14.128 -sC -sV -p25`
- Open Relay: `sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`

### Exercise Solution

1. Connect to port 25 using netcat and try running some command (I ran ELHO), the banner will show
2. Use smtp_enum in msfconsole, plus the provided wordlist in the resources.


## IMAP / POP3

- Imap: 143/993
- Pop3: 110/995

### IMAP Commands

| Command | Description |
| --- | --- |
| `1 LOGIN username password` | User's login. |
| `1 LIST "" *` | Lists all directories. |
| `1 CREATE "INBOX"` | Creates a mailbox with a specified name. |
| `1 DELETE "INBOX"` | Deletes a mailbox. |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox. |
| `1 LSUB "" *` | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| `1 SELECT INBOX` | Selects a mailbox so that messages in the mailbox can be accessed. |
| `1 UNSELECT INBOX` | Exits the selected mailbox. |
| `1 FETCH <ID> all` | Retrieves data associated with a message in the mailbox. |
| `1 CLOSE` | Removes all messages with the Deleted flag set. |
| `1 LOGOUT` | Closes the connection with the IMAP server. |


### POP3 Commands

| Command | Description |
| --- | --- |
| `USER username` | Identifies the user. |
| `PASS password` | Authentication of the user using its password. |
| `STAT` | Requests the number of saved emails from the server. |
| `LIST` | Requests from the server the number and size of all emails. |
| `RETR id` | Requests the server to deliver the requested email by ID. |
| `DELE id` | Requests the server to delete the requested email by ID. |
| `CAPA` | Requests the server to display the server capabilities. |
| `RSET` | Requests the server to reset the transmitted information. |
| `QUIT` | Closes the connection with the POP3 server. |

### Dangerous Settings

| Setting | Description |
| --- | --- |
| `auth_debug` | Enables all authentication debug logging. |
| `auth_debug_passwords` | This setting adjusts log verbosity; submitted passwords and the authentication scheme are logged. |
| `auth_verbose` | Logs unsuccessful authentication attempts and their reasons. |
| `auth_verbose_passwords` | Passwords used for authentication are logged and can also be truncated. |
| `auth_anonymous_username` | Specifies the username to be used when logging in with the `ANONYMOUS` SASL mechanism. |

### Footprinting

- Nmap: 

```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

- cURL:

```bash
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
```

- openSSL TLS POP3:

```bash
openssl s_client -connect 10.129.14.128:pop3s
```

- openSSL TLS IMAP:

```bash
openssl s_client -connect 10.129.14.128:imaps
```

### Exercise Solutions

1. see nmap results with `-sC -sV -A`
2. see nmap results with `-sC -sV -A`
3. `openssl s_client -connect <ip>:imaps`
4. `openssl s_client -connect <ip>:pop3s`
5. Steps:
    - Login to the mailbox
    - `A1 LIST "" *` -> List all mailboxes
    - `A1 SELECT DEV.DEPARTMENT.INT *` -> Select the *dev.department.int* mailbox
    - `A1 UID FETCH 1:*` -> check if mail of UID 1 exists
    - `A1 FETCH 1 all ` -> Fetch headers of mail of UID 1 (contains the email)
6. Follow all steps of question 4 and then do `A1 FETCH 1 body[text]`

## SNMP

- Port: UDP 161 (traps over port 162)
- MIB: Management Information Base, an independent format for storing device information. Written in ASN.1 (Abstract Sytax Notation One)
- OID: a unique sequence of numbers identifying the position of a node in the tree
- SNMPv1: 
    - No auth
    - no encryption
- SNMPv2: 
    - Security via community string
    - No encryption
- SNMPv3: 
    - Support auth
    - username and password transmission via encryption (via pre-shared key, PSK)
- Community Strings: A password-like mechanism used to determine authentication

### Default Configuration

```bash
LordA2117@htb[/htb]$ cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'

sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
master  agentx
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
```

> See the [manpage](http://www.net-snmp.org/docs/man/snmpd.conf.html) for more details

### Dangerous Settings

| Settings | Description |
| --- | --- |
| `rwuser noauth` | Provides access to the full OID tree without authentication. |
| `rwcommunity <community string> <IPv4 address>` | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6. |

### Footprinting the Service

- snmpwalk:

```bash
snmpwalk -v2c -c public 10.129.14.128
```

- onesixtyone:

```bash
LordA2117@htb[/htb]$ sudo apt install onesixtyone
LordA2117@htb[/htb]$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

- braa:

```bash
LordA2117@htb[/htb]$ sudo apt install braa
LordA2117@htb[/htb]$ braa <community string>@<IP>:.1.3.6.*   # Syntax
LordA2117@htb[/htb]$ braa public@10.129.14.128:.1.3.6.*
```

### Exercise
1. Connect to the snmp service snmpwalk.
2. Connect to the snmp service snmpwalk.
3. Connect to the snmp service snmpwalk and let it run for a while.


## MySQL

- Works according to the `client-server` model
- Primarily in `LAMP` stack


### Default Configuration

```
[client]
port        = 3306
socket      = /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
nice        = 0

[mysqld]
skip-host-cache
skip-name-resolve
user        = mysql
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
port        = 3306
basedir     = /usr
datadir     = /var/lib/mysql
tmpdir      = /tmp
lc-messages-dir = /usr/share/mysql
explicit_defaults_for_timestamp

symbolic-links=0

!includedir /etc/mysql/conf.d/
```

### Dangerous Settings

| Setting | Description |
| --- | --- |
| `user` | Sets which user the MySQL service will run as. |
| `password` | Sets the password for the MySQL user. |
| `admin_address` | The IP address on which to listen for TCP/IP connections on the administrative network interface. |
| `debug` | This variable indicates the current debugging settings. |
| `sql_warnings` | This variable controls whether single-row `INSERT` statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations. |


### Footprinting the Service

- nmap:

```bash
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

- Interact with MySQL Server:

```bash
$ mysql -u root -h 10.129.14.132
$ mysql -u root -pP4SSw0rd -h 10.129.14.128
```

### Exercise

1. run nmap on port 3306
2. Commands: 
    - `mysql -u robin -probin -h 10.129.223.234 --ssl-verify-server-cert=false`
    - `use customers;`
    - `select name,email from myTable;`

## MSSQL

- Microsoft's flavor of SQL
- Clients:
    - Use `impacket-mssqlclient`

### Default Databases

| Default System Database | Description |
| --- | --- |
| **master** | Tracks all system information for an SQL Server instance |
| **model** | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after the changes to the model database |
| **msdb** | The SQL Server Agent uses this database to schedule jobs & alerts |
| **tempdb** | Stores temporary objects |
| **resource** | Read-only database containing system objects included with SQL Server |

- [Source](https://docs.microsoft.com/en-us/sql/relational-databases/databases/system-databases?view=sql-server-ver15)


### Default Configuration

- Likely the service will run as `NT SERVICE\MSSQLSERVER`.
- Connection is usually possible via windows auth, but encryption is not enforced when attempting to connect.
- Windows auth means that it will either use the `SAM` database or the domain controller (the active directory host).

### Dangerous Settings

- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default sa credentials. Admins may forget to disable this account

### Footprinting

- nmap:

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-
```

- Metasploit:

```bash
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
```

- impacket:

```bash
impacket-mssqlclient Administrator@10.129.201.248 -windows-auth
```

### Exercise

1. Run nmap
2. Connect using impacket and then `EXEC sp_databases;`
