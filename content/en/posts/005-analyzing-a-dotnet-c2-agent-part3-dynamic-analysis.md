+++
title = '005 - Analyzing a C2 agent - Part 2: the agent - Dynamic analysis'
date = 2024-02-12T12:03:49-05:00
draft = false   
translationKey = '005-dotnet-agent'
description = 'In this article we will dynamically analyze the C2 agent we previously obtained and evaluate ways to interact with it in order to understand how it works.'
+++

*Este artículo también está disponible en [español](/es/posts/005-analyzing-a-dotnet-c2-agent-part3-dynamic-analysis/)*

## 1. Introduction

In [the second part of this article](/en/posts/004-analyzing-a-dotnet-c2-agent/) we statically analyzed the .exe binary we obtained from a malicious macro; during the analysis, we identified that the program was developed in .NET, which facilitated the analysis because the intermediate language (IL) used by this framework is very similar to the original source code, allowing it to be easily decompiled.

In this section we will dynamically analyze the binary to confirm our static analysis was correct, as well as develop ways to interact with the agent.

> **Disclaimer**: Running malware on a personal or corporate device can put your information/your company's information at risk. Never run malware on a device that has not been specifically configured for malware analysis.

## 2. Dynamic analysis of the binary

### 2.1 Environment setup and initial connection

As part of the static analysis we identified that, after waiting for a few seconds, the program tries to communicate with the IP *162.245.191.217* on the ports 9149, 15198, 17818, 27781 and 29224, iterating through them until it gets a successful connection. We can verify that the program does indeed make such connection attempts using *TCPView* or *Process Monitor*:

![alt text](/img/005_TCPView1.png "Connection in TCP View")

![alt text](/img/005_Procmon1.png "Connection in Process Monitor")

Since the binary requires a successful response from the server to continue, we can proceed in two ways:

1. Modify the destination IP during execution using DNSpy
2. Modify Remnux to intercept the traffic directed to the server

On this occasion I opted for the second option, which can be implemented by modifying Remnux's firwall rules; to do so, we can redirect all traffic destined to the server's IP to a specific port in Remnux:

```bash
sudo iptables -t nat -A PREROUTING -i ens33 -p tcp -d 162.245.191.217  -j DNAT --to-destination 10.0.0.3:4321
```

As part of the static analysis we identified that the program gets a response from the server, splits it using the "=" character and based on the first part of the message (what is before the "=" character) performs an action. We can test this by sending a value that we know the program understands and see if it follows the expected path:

```python
import socket
import struct

message_content = "thyTumb=LoremIpsumTest"
print(message_content)

HOST = '0.0.0.0'
PORT = 4321


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print("Server is listening...")
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        conn.sendall(message_content.encode())
        print("Data sent to the client.")

```
![alt text](/img/005_expected.png "Message to send")

However, we quickly realize that sending a message will not be so simple; the agent implements custom logic to determine the size of the message and thus know when to stop "reading" data:
![alt text](/img/005-breakpoint.png "Identification logic")

Furthermore, due to differences in how C# (what the agent is written in) and Python (the server we are using to impersonate the real server) handle TCP messages, it is necessary to make adjustments to the code so that the agent can understand the message:

```python
import socket
import struct

message_content = "thyQumb=LoremIpsumTest"

message_length = len(message_content.encode())
packed_length = struct.pack('!I', message_length)

reversed_length = packed_length[::-1]

reversed_length = reversed_length + b'\x00' * (5 - len(reversed_length))

message_to_send = reversed_length + message_content.encode()
print(message_to_send)

HOST = '0.0.0.0'  
PORT = 4321     

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print("Server is listening...")
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        conn.sendall(message_to_send)
        print("Data sent to the client.")

```

With these modifications we verify that the message reaches the agent correctly:
![alt text](/img/005-fixedcode.png "Agent receives response")

During analysis it can take a long time for the necessary conditions to be met for the malware to communicate with the server, so extracting the part of the code we want to understand and using it in another program can help us understand what is happening more effectively; to understand how Python sent the messages and how .NET received them, I made a small program that allowed me to validate the response of each stage of the process:
![alt text](/img/005-customdebug.png "Debugging using Visual Studio")

Once we are able to send information to the agent in a "language" that it can understand, implementing the logic of receiving information from the agent takes little time. Finally we have how to send commands to the Command and Control agent and we can verify how it behaves in practice.

### 2.2 Analysis of the agent's capabilities

As in the previous article, we will analyze some capabilities offered by the agent to verify how they behave during its execution:

#### 2.2.1 Listing processes

When the command "geyTtavs" is received, we expect the ID of each process to be sent, followed by the name of each process, following the pattern
*Process ID1>ProcessName1>0>IDProcess2>ProcessName2>0><*. Using Wireshark, we can verify that the information is indeed sent this way:
![alt text](/img/005-listarProcesos.png "DNSpy view of parsing processess")
![alt text](/img/005-listarProcesosWireshark.png "Wireshark view of parsing processess")

On the server, we can modify our script to better parse the received information:
![alt text](/img/005-viewProcEng.png "Server view of parsing processess")
![alt text](/img/005-taskexplorer.png "Server view of parsing processess")

#### 2.2.2 Establish persistence

Another of the functions offered by the C2 agent that we identified during the static analysis is that of establishing persistence, which we can verify using *Autoruns* and *Process monitor*. 
![alt text](/img/005-persistenceEng.png "Command to establish persistence")
![alt text](/img/005-persistenciaPM.png "Persistence through Registry key")
![alt text](/img/005-persistencia2.png "Persistence through Registry key")

The C2 agent uses the registry key _HKEY\_CURRENT\_USERSoftware\Microsoft\Windows\CurrentVersion\Run_ to configure the agent to run at each login ([technique T1547.001 in MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/001/)).


#### 2.2.3 Exfiltrating files

The agent offers the attacker the ability to exfiltrate files using the "afyTile" command, for which it receives a file path and proceeds to send the file to the C2 server; we can update our server to interact with that function and confirm the agent read and sent the file using *Wireshark* and *Process Monitor*:
![alt text](/img/005-exfilEng.png "File exfiltrated to C2")
![alt text](/img/005-exfil2.png "File read on filesystem")
![alt text](/img/005-exfil3.png "Data sent through Wireshark")

#### 2.2.4 Downloading and executing programs

One of the most interesting capabilities offered by the agent is the ability to download and execute binaries from the C2 server, so an attacker can extend their attack using capabilities not initially available in the malware. One of the situations where we constantly see such a technique is with [organizations that](https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/) [deploy](https://www.darkreading.com/threat-intelligence/-gold-melody-access-broker-unpatched-servers) [ransomware](https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/lockbit), where organizations known as *Initial Access Brokers (IABs)* sell the access they gained into a company to Ransomware organizations such as Lockbit and Conti.

![alt text](/img/005-download.png "Download and execute")

For my initial test, I had the application download and execute the Windows calculator:
![alt text](/img/005-calc.png "Opening a calculator")

However, since running the calculator is boring, I decided to download Wannacry simulating what a real attacker might do:
{{< youtube BXkm-5nxo2A >}}

### 2.3 C2 server demo 

After analyzing some of the capabilities offered by the agent (facilitated by the easy decompilation of .NET), I managed to implement a server capable of communicating with it based only on the agent's code; among the features that I implemented are listing processes, obtaining system information, executing commands, establishing persistence, listing files in a directory, and downloading and executing binaries.

The following video shows some of the capabilities:
{{< youtube kr9-kPQhMEo >}}

As shown in the video, the agent establishes communication with the Command and Control server every minute, which allows the attacker to send different commands; among those reviewed are the download and execution of binaries, where [*Mimikatz*](https://github.com/gentilkiwi/mimikatz) was downloaded and executed, the listing of system processes, where we identified the *Mimikatz* process, and obtaining system information, where we obtained the name of the machine, the user, the Windows version, as well as the path where the agent was running.

Furthermore, we can see how these activities appear in tools such as *Process Explorer*, *Process Monitor*, *TCP View* and *Wireshark*, which allow us to understand in detail the actions triggered by each capability of the malware.

The video does not show all the implemented capabilities, as well as others offered by the agent that were not adapted to the fake server (deleting files, taking screenshots, etc.), which is why I encourage the readers to reverse-engineer the binary and implement these capabilities as a way of learning.


## 3. Conclusions

When I started the analysis of this malware I only knew that it contained a malicious macro, but not that it embedded a Command and Control agent, that I would be able to decompile, analyze, and develop a POC to interact with it. The malware obtained was the perfect opportunity to practice different analysis techniques, both static and dynamic, allowing us to reverse engineer the malware without having to read assembly code.

In a future article I will analyze new malware, ideally one that is not based on Macros or .NET to document new analysis techniques; even so, regardless of the analysis tool, the methodology is the same, so I invite readers to replicate what has been done and thus practice.

If you have any feedback or suggestions do not hesitate to contact me at contact@threatanatomy.io!

## 4. MITRE ATT&CK Mapping

| ID        | Tactic              | Technique                                                             | Description                                                                 |
|-----------|---------------------|-----------------------------------------------------------------------|-----------------------------------------------------------------------------|
| T1059.003 | Execution           | Command and Scripting Interpreter: Windows Command Shell              | The method Process.Start was used to initiate new processes                 |
| T1547.001 | Persistence         | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | A registry key was used to stablish persistence                             |
| T1070.004 | Defence evasion     | Indicator Removal: File Deletion                                      | The agent has the capability to delete files                                |
| T1027.010 | Defence evasion     | Obfuscated Files or Information: Command Obfuscation                  | Character substitution was used to obfuscate commands                       |
| T1057     | Discovery           | Process Discovery                                                     | The agent has the capability to list processes                              |
| T1082     | Discovery           | System Information Discovery                                          | The agent has the capability to obtain information about the system         |
| T1113     | Collection          | Screen Capture                                                        | The agent has the capability to take screenshots                            |
| T1005     | Collection          | Data from Local System                                                | The agent has the capability to obtain information about the system's files |
| T1571     | Command and Control | Non-Standard Port                                                     | The agent communicates using a non-standard port                            |
| T1095     | Command and Control | Non-Application Layer Protocol                                        | The agent communicates directly through a TCP connection                    |
| T1041     | Command and Control | Exfiltration Over C2 Channel                                          | The agent exfiltrates information using the connection with the C2 server   |

## 5. IOC

| IOC                                                                           | Tipo              | Descripción                                |
|-------------------------------------------------------------------------------|-------------------|--------------------------------------------|
| 59211a4e0f27d70c659 636746b61945a                                              | MD5 Hash          | C2 agent hash                              |
| 162.245.191.217                                                               | IP                | IP that the agent calls                    |
| HKEY\CURRENT \USER\Software \Microsoft\Windows \CurrentVersion \Run\haijwivetsgVr | Registry key | Registry key used to establish persistence |