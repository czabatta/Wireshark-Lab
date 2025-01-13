# Wireshark-Lab
Hunting Clear Text Credentials

The objective of this lab is to extract cleartext passwords from the capture file.
You can view detected credentials using the "Tools --> Credentials" menu.
Once you use the feature, it will open a new window and provide detected credentials. It will show the packet number, protocol, username and additional information. 
This window is clickable; clicking on the packet number will select the packet containing the password, and clicking on the username will select the packet containing the username info. 
The additional part prompts the packet number that contains the username.
![image](https://github.com/user-attachments/assets/bc2ec2c9-cb25-4f3b-ae33-adb1eb8b7a0e)

Detecting ICMP and DNS Anomalies

The Objective of this exercise is to provide an understanding of how Wireshark can be used to sniff data and find malicious/abnormal traffic.  
ICMP ANALYSIS:
ICMP is used to send diagnostic messages for network issues, and is a part of routine network traffic.  Since it is a trusted protocol, it can be used for DoS (Denial-of-Service) attacks, and C2 (Command-and-Control) data exfiltration. An adversary will attach http, tcp, or ssh data to an ICMP packet.  A large volume of ICMP traffic will indicate malicious ICMP tunneling.  Below are filters used to navaigate ICMP traffic on Wireshark.
![image](https://github.com/user-attachments/assets/0690fc86-a8b8-414b-a2dd-c3957d68b82d)

DNS Analysis

Domain Name System is used to convert IP hostnames to IP addresses. As with ICMP, it is an essential part of internet traffic, it is often overlooked.  It can commonly be used to mask C2 attacks and DoS attacks.  Below are filters used on Wireshark to navigate DNS traffic.
![image](https://github.com/user-attachments/assets/190e1d00-f967-426a-b18f-d613b23df924)
Investigation

First I will filter through the ICMP traffic, and find out what protocol is being exploited and embedded into malicious traffic.  With the amount of ICMP packets you will typically be investigating, it would be like trying to find a needle in a haystack if we try to manually go through the data.  Typical ICMP packets are small in size, a couple of bytes.  So lets use a filter to display any ICMP traffic that might be malicious from large packet sizes, and search through the contents of the packets.  "data.len>64 and ICMP"
Wireshark gives you the ability ot display the raw data of a packet, which can be a very powerful tool used in an investigation.  After opening up one of the first few packets, ssh protocols are found hidden within the data.
![image](https://github.com/user-attachments/assets/1657121b-b731-48cb-9ac0-572aeae916be)

We can then switch our investigation over to the malicious DNS traffic, using the Wireshark filter "dns.qry.name.len>15".  We are trying to find what website the attackers are sending malicious DNS traffic to in this scenario.  We can see that the attackers did not take much effort to conceal their hacking other than DNS masking.  We find many instances of large DNS query packets being sent to "dataexfil[.]com".
![image](https://github.com/user-attachments/assets/0309afa9-4f53-44ee-875e-9a5720bc46a3)








