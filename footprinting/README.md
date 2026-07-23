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

### Foorprinting FTP

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

### Foorprinting SMB

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
