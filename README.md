# Network Traffic Analysis Using Wireshark
### Lab 1: Hunting Cleartext Credentials | Lab 2: Detecting Malicious ICMP & DNS Traffic

---

## Objective
This lab demonstrates two core network forensics techniques used daily in 
SOC environments. In Lab 1, Wireshark's built-in credential extraction 
feature is used to recover FTP plaintext credentials from a packet capture. 
In Lab 2, custom display filters are used to identify malicious ICMP 
tunneling and DNS exfiltration traffic - two techniques commonly used 
by attackers to hide C2 communication and data theft inside trusted 
protocols that most firewalls allow through by default.

---

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|---|---|---|
| Credential Access | T1040 | Network Sniffing |
| Command & Control | T1095 | Non-Application Layer Protocol (ICMP Tunneling) |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| Command & Control | T1071.004 | Application Layer Protocol: DNS |

---

## Tools & Technologies

- **Wireshark** - Network protocol analyzer and packet capture tool
- **Display Filters** - `data.len > 64 and icmp`, `dns.qry.name.len > 15 and !mdns`
- **Tools → Credentials** - Wireshark's built-in plaintext credential parser
- **PCAP Files** - Pre-captured network traffic files for forensic analysis

---

## Lab 1: Hunting Cleartext Credentials

### Background
Many legacy and misconfigured systems still transmit credentials over 
unencrypted protocols such as FTP, Telnet, and HTTP. A SOC analyst must 
be able to rapidly identify and extract these credentials from packet 
captures during incident investigations - whether investigating a data 
breach, an insider threat case, or a compromised host.

### Investigation

Open the PCAP file in Wireshark and navigate to **Tools → Credentials**. 
Wireshark automatically parses the entire capture and surfaces any 
detected plaintext credentials across all supported protocols without 
requiring manual packet-by-packet review.

<img width="853" height="334" alt="386747877-bc2ec2c9-cb25-4f3b-ae33-adb1eb8b7a0e" src="https://github.com/user-attachments/assets/bdd22e85-c92c-4436-acd1-a43b9efe1e36" />


The Credentials window displays each detected credential with the packet 
number, protocol, username, and additional context. In this capture, 
Wireshark identified repeated FTP authentication attempts using the 
username **"admin"** across multiple sessions — packets 41, 44, 53, 55, 
78, 86, 119, 124, 126, 170, 210, 223, and 233. Clicking any packet 
number jumps directly to that packet in the main capture view for 
deeper inspection.

### Key Findings
- Wireshark's credential parser extracted plaintext FTP usernames 
  across 13+ packets from a single capture file
- The username "admin" appeared repeatedly across multiple sessions, 
  indicating either credential reuse, brute force activity, or a 
  persistent connection from a compromised account
- FTP transmits both usernames and passwords in cleartext — meaning 
  anyone with network access or a captured PCAP can recover full 
  credentials with zero decryption required
- This technique directly applies to SOC investigations involving 
  data breaches, insider threats, or network reconnaissance

---

## Lab 2: Detecting Malicious ICMP & DNS Traffic

### Background
ICMP and DNS are trusted, essential protocols that most firewalls 
permit without deep inspection. Attackers exploit this trust to 
tunnel data and C2 traffic inside these protocols — hiding malicious 
activity in plain sight. Identifying these attacks requires knowing 
what "normal" traffic looks like and applying targeted filters to 
surface the anomalies.

---

### Part A: ICMP Tunnel Detection

#### Why ICMP?
Standard ICMP ping packets are tiny - typically under 64 bytes. 
When an attacker embeds a full protocol like SSH inside ICMP payloads 
to create a covert C2 channel, the packet sizes become abnormally 
large. This size anomaly is the primary detection indicator.

#### Investigation

Apply the following Wireshark display filter to isolate packets that 
exceed the normal ICMP size threshold:
```
data.len > 64 and icmp
```

<img width="1459" height="367" alt="402676648-0690fc86-a8b8-414b-a2dd-c3957d68b82d" src="https://github.com/user-attachments/assets/86b42fb1-6f44-43e4-beab-9404ed2b34e1" />


The filter immediately surfaces a stream of ICMP packets sized between 
**1028 and 1033 bytes** - dramatically larger than legitimate ping 
traffic - all flowing between 192.168.154.131 and 192.168.154.132 
at regular intervals. This pattern is a strong indicator of 
automated tunneling activity.

Opening the packet detail pane and examining the raw hex data of 
one of the flagged packets reveals the embedded payload:

<img width="2000" height="1579" alt="402682006-1657121b-b731-48cb-9ac0-572aeae916be" src="https://github.com/user-attachments/assets/54de6cf0-552b-4cff-8b7b-613de309f791" />


The hex dump clearly shows **OpenSSH_5** string data embedded inside 
the ICMP packet body - definitively confirming that SSH protocol 
traffic is being tunneled through ICMP to evade network-layer 
detection.

#### Finding
**An attacker established a covert SSH channel by tunneling it 
inside ICMP echo requests**, bypassing firewall rules that permit 
ICMP while blocking direct SSH connections. The regular timing 
and consistent oversized packets confirm automated, ongoing 
C2 communication.

---

### Part B: DNS Exfiltration Detection

#### Why DNS?
DNS is one of the most universally permitted protocols on any 
network - blocking it breaks internet functionality. Attackers 
use abnormally long DNS query names to encode data and exfiltrate 
it to attacker-controlled domains, or to communicate with C2 
infrastructure while appearing to perform routine DNS lookups.

#### Investigation

The DNS analysis reference table shows the key detection filters 
and what each one surfaces:

<img width="2000" height="2034" alt="402679040-190e1d00-f967-426a-b18f-d613b23df924" src="https://github.com/user-attachments/assets/324e86e8-3f83-4ec3-b6cf-455303d26d68" />


Key filters for identifying malicious DNS:
- `dns` - broad baseline view of all DNS traffic
- `dns contains "dnscat"` - targets the dnscat C2 tool specifically  
- `dns.qry.name.len > 15 and !mdns` - surfaces abnormally long 
  query names while excluding legitimate local mDNS traffic

Applying `dns.qry.name.len > 15 and !mdns` to the capture reveals 
the exfiltration activity:

<img width="2000" height="1838" alt="402683809-0309afa9-4f53-44ee-875e-9a5720bc46a3" src="https://github.com/user-attachments/assets/5f552f68-73fa-4923-ab18-25eb8ad8ce96" />


The filtered results surface DNS queries containing long encoded 
subdomains being sent to **dataexfil[.]com** - a domain name that 
makes no attempt to disguise its purpose. The encoded data is 
visible in the query strings: `BA7C01B0DE682B2B4554B6000101E88144.dataexfil.com`.

#### Finding
**The attacker used DNS queries as a data exfiltration channel**, 
encoding stolen data as subdomain strings and resolving them against 
an attacker-controlled domain. The lack of obfuscation beyond DNS 
masking indicates an unsophisticated but effective technique that 
would bypass most traditional perimeter controls.

---

## Summary of Findings

| Lab | Protocol | Technique | MITRE ID | Finding |
|---|---|---|---|---|
| Lab 1 | FTP | Network Sniffing | T1040 | Plaintext FTP credentials extracted via Tools → Credentials |
| Lab 2A | ICMP | Protocol Tunneling | T1095 | SSH data embedded in oversized ICMP packets (1028+ bytes) |
| Lab 2B | DNS | DNS Exfiltration | T1071.004 | Encoded data exfiltrated to dataexfil[.]com via DNS queries |

---

## SOC Skills Demonstrated

- Packet capture analysis and forensic investigation with Wireshark
- Cleartext credential extraction using built-in protocol parsers
- Custom display filter construction for anomaly detection
- ICMP anomaly detection — identifying tunneling via packet size analysis
- Raw hex payload inspection to confirm embedded protocol data
- DNS anomaly detection — long query name analysis for exfiltration
- IOC identification and documentation (malicious domains, C2 indicators)
- MITRE ATT&CK technique mapping from raw network evidence
