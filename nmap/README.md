# Enumeration

- The most important part of a pentest.
- Most ways in which we can gain access to a system can be narrowed down into 2 points:
    - Functions and/or resources that allow us to interact with the target and/or provide additional information.
    - Information that provides us with even more important information to access our target.
- Manual enumeration is **VERY IMPORTANT**
- Many scanning tools automate things, but they cannot always bypass security measures of services.


## Intro to Nmap

- Nmap = Network Mapper
- Features:
    - Host Discovery
    - Port scanning
    - Service Enumeration and detection
    - OS detection
    - Scriptable interaction with the target service (Nmap Scripting Engine)

- Basic Syntax: `nmap <scan types> <options> <target>`
- TCP Syn Scan: `nmap -sS <ip>`

## Host Discovery

- To scan a network range for hosts, we can use nmap in this way:

```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

- 10.129.2.0/24 is the network range
- -sn disables portscanning
- -oA tnet Stores results in all formats starting with the name tnet.
- Works only if the firewalls of the host allow it, if not we need to use some evasion techniques.

### Scanning IP lists

```bash
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

- -iL specifies a list for scanning

### Scanning Multiple IPs

```bash
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
```

If these are consecutive IPs we can specify a range also

```bash
sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5
```

### Scanning Single IP

```bash
sudo nmap 10.129.2.18 -sn -oA host
```

If we disable port scan (-sn), Nmap automatically ping scan with ICMP Echo Requests (-PE). Once such a request is sent, we usually expect an ICMP reply if the pinging host is alive.

```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace
```

- -PE: Performs the ping scan by using 'ICMP Echo requests' against the target.
- --packet-trace: Shows all packets sent and received.
- --reason: Displays the reason for specific result.
- --disable-arp-ping: To disable ARP requests and scan our target with the desired ICMP echo requests, we can disable ARP pings.

Check out more host discovert strategies [here](https://nmap.org/book/host-discovery-strategies.html).

### Exercise Solution

- The OS in this scan here is windows.
- This is because of the TTL value, which it sends back as 128. This actually refers to windows.
- [Check here](https://subinsb.com/default-device-ttl-values/) for the default ttl values.

## Host and Port Scanning

- Different states of ports:

| State | Description |
| :--- | :--- |
| **open** | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations. |
| **closed** | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |
| **filtered** | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target. |
| **unfiltered** | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed. |
| **open\|filtered** | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port. |
| **closed\|filtered** | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall. |

### Discovering Open TCP ports

- By default, nmap scans the top 1000 TCP ports with the Syn Scan flag.

```bash
sudo nmap 10.129.2.28 --top-ports=10
```

### Nmap - Trace the packets

```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```

- -p Scans a specified port
- --packet-trace Shows all packets sent and received.
- -n Disable DNS resolution
- --disable-arp-ping Disables ARP ping

- Requests and Responses

Requests

| Message            | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| SENT (0.0429s)     | Indicates the SENT operation of Nmap, which sends a packet to the target. |
| TCP                | Shows the protocol that is being used to interact with the target port.   |
| 10.10.14.2:63090 > | Represents our IPv4 address and the source port used by Nmap to send packets. |
| 10.129.2.28:21     | Shows the target IPv4 address and the target port.                        |
| S                  | SYN flag of the sent TCP packet.                                           |
| ttl=56 id=57322 iplen=44 seq=1699105818 win=1024 mss 1460 | Additional TCP header parameters. |


Responses

| Message                 | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| RCVD (0.0573s)          | Indicates a received packet from the target.                               |
| TCP                     | Shows the protocol that is being used.                                     |
| 10.129.2.28:21 >        | Represents the target's IPv4 address and the source port used to reply.    |
| 10.10.14.2:63090        | Shows our IPv4 address and the port that will receive the reply.           |
| RA                      | RST and ACK flags of the sent TCP packet.                                  |
| ttl=64 id=0 iplen=40 seq=0 win=0 | Additional TCP header parameters.                                  |

### Connect Scan on tcp 443

```bash
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

### Filtered Ports

```bash
sudo nmap 10.129.2.28 -p 139 --packet-trace -n --disable-arp-ping -Pn
```

- When a port is shown as filtered, it can have several reasons. In most cases, firewalls have certain rules set to handle specific connections.

### Discovering Open UDP Ports

```bash
sudo nmap 10.129.2.28 -F -sU
```

- -sU: Performs UDP scan
- -F: Scans top 100 ports

- A major disadvantage of UDP is that we often don't get a response back because `Nmap` sends empty datagrams to the scanned UDP ports, so no responses are sent.
- Other flags as shown in the previous scans also work with UDP scans.

### Version Scan

```bash
sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason  -sV
```

- -sV: 	Performs a service scan.

### Exercises

- I found 12 open ports, but htb says 7. So whatever 
- Again, the target is chopped so idk.

## Saving the results

- Saving results is always important after any scan.
- Formats:
    - Normal output (-oN) with the .nmap file extension
    - Grepable output (-oG) with the .gnmap file extension
    - XML output (-oX) with the .xml file extension
    - -oA to save in all formats

- We can convert XML results to html results using `xsltproc`.

```bash
xsltproc result.xml -o result.html
```

### Exercise

- I just used `masscan` to get all the open ports (see checklist.md)


## Service Enumeration

- Perform a quick portscan to get the open ports and then perform service enum on those.
- This can be time-consuming which is why we use masscan (easier and faster).
- Consider this command:

```bash
sudo nmap 10.129.2.28 -p- -sV --stats-every=5s
```

- Here, the `--stats-every=5s` displays the progress and scan stats every 5 seconds.
- Use the `-v` and `-vv` flags to increase verbosity levels.
- Use the `-sV` flag to perform banner grabbing.

### Banner grabbing using tcpdump and netcat

```bash
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
nc -nv 10.129.2.28 25 # Do this in another terminal
```

### Exercise solution

- Get ports using masscan
- Use nmap service enumeration to get the banners.
- If that doesn't happen use the tcpdump netcat method (I didn't do this).
- After getting all the flags, I saw port 31337 open which was FTP. So I used ftp to connect to it and get the flag (it just sends it over).

## Nmap Scripting Engine

- Create scripts with lua to do more stuff. Script categories are shown in the below table.

| Category | Description |
| :--- | :--- |
| **auth** | Determination of authentication credentials. |
| **broadcast** | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| **brute** | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| **default** | Default scripts executed by using the `-sC` option. |
| **discovery** | Evaluation of accessible services. |
| **dos** | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| **exploit** | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| **external** | Scripts that use external services for further processing. |
| **fuzzer** | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| **intrusive** | Intrusive scripts that could negatively affect the target system. |
| **malware** | Checks if some malware infects the target system. |
| **safe** | Defensive scripts that do not perform intrusive and destructive access. |
| **version** | Extension for service detection. |
| **vuln** | Identification of specific vulnerabilities. |


- Different nmap functions are here:

| Function | Flag |
| :---: | :--- |
| Default Scripts | -sC |
| Specific Script Category | --script category |
| Defined Scripts | --script script1,script2 |
| Aggressive Scan | -A |
| vuln script for checking common vulnerabilities | --script vuln |

### Exercise solution

- Use my flow (see cheatsheet or previous sections to get that) to get all open ports.
- Do some fuzzing on the webserver (port 80) and flag will be in robots.txt


## Performance

| Function | Flag | Description |
| :---: | :---: | :---: |
| Optimized RTT | --initial-rtt-timeout init_time_in_ms --max-rtt-timeout max_time_in_ms | When Nmap sends a packet, it takes some time (Round-Trip-Time - RTT) to receive a response from the scanned port. Generally, Nmap starts with a high timeout (--min-RTT-timeout) of 100ms. |
| Max Retries | --max-retries max_retries_count | Another way to increase scan speed is by specifying the retry rate of sent packets (--max-retries). The default value is 10, but we can reduce it to 0. This means if Nmap does not receive a response for a port, it won't send any more packets to that port and will skip it. |
| Rates | --min-rate rate_limit_min | Limits the rate of packets sent to meet any possible constraints, either while pentesting or other environmental conditions like bandwidth |
| Timings | -T 0-5 | Nmap offers 5 different timing templates to use. It starts from 0 (paranoid) to 5 (insane). |
