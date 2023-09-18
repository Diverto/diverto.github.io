---
layout: post
title: Forensic analysis of MITRE ATT&CK Techniques 2 - Execution
date: 2023-08-22
author: goran
categories: [forensic, windows, mitre, attack]
category: forensic, windows, mitre, attack
color: blue
tags: [forensic, analysis, windows, mitre, attack]
otherLanguages:
- locale: sl
  path: /sl/blog/2023-08-22-forensic-analysis-mitre-attack-2
- locale: hr
  path: /hr/blog/2023-08-22-forensic-analysis-mitre-attack-2
---


In the previous blog [**Forensic analysis of MITRE ATT&CK Techniques - PART 1**](https://www.diverto.hr/en/blog/2022-12-18-forensic-analysis-mitre-attack/)
the first phase of the adversary was explained. In that phase the adversary achieved his goal by 
obtaining and abusing the credentials of existing local account to gain initial access to the system. 
Looking at the MITRE ATT&CK framework, the next goal of the adversary is to run malicious code on the system.

<!--more-->

## PART 2 - Execution


In this phase of the attack, the adversary uses various techniques to run malicious code on a local or remote system. 
Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, 
like exploring a network or stealing data. Adversaries often rely on the ability to execute code, especially on 
non-cloud-based applications, such as employee workstations and servers.


**Execution Techniques**

<a href="/images/2023-08-22-forensic-analysis-mitre-attack/image1-big.png" rel="nofollow noopener noreferrer" target="_blank">
<img src="/images/2023-08-22-forensic-analysis-mitre-attack/image1.png">
</a>

*Figure 1. Execution Techniques*


This example will show two techniques, [**T1059 Command and Scripting Interpreter**](https://attack.mitre.org/techniques/T1059/), 
Sub-technique [**T1059.001 PowerShell**](https://attack.mitre.org/techniques/T1059/001/) in which an adversary uses PowerShell to 
download an executable file from the Internet and run it from the disk, and 
[**T1053 Scheduled Task/Job**](https://attack.mitre.org/techniques/T1053/), Sub-technique [**T1053.005 Scheduled Task**](https://attack.mitre.org/techniques/T1053/005/) 
in which an adversary abuse the Windows Task Scheduler to execute malicious code.


**1) Sub-technique [**T1059.001 PowerShell**](https://attack.mitre.org/techniques/T1059/001/)**


Adversaries may abuse PowerShell commands and scripts to perform several actions, including discovery of 
information and execution of code. Examples include the ***Start-Process*** cmdlet which can be used to run an 
executable and the ***Invoke-Command*** cmdlet which runs a command locally or on a remote computer. 
PowerShell may also be used to download and run executables from the Internet, which can be executed 
from the disk or in memory without touching disk.


**Detection analysis**

     
In the picture below we can see the evidence of PowerShell execution. The adversary executed an obfuscated PowerShell command.  


![Obfuscated PowerShell command](/images/2023-08-22-forensic-analysis-mitre-attack/image2.png)
*Figure 2. Obfuscated PowerShell command*

An adversary typically uses obfuscation commands to conceal command and control communication, to evade detection by a signature-based 
solution or to obfuscate strings within the malicious binary, evading detection via static analysis.


The next step in analysis is to make PowerShell command readable. To do that, we need to de-obfuscate that PowerShell command. 
There is a various tool for that, but the great online tool is [***CyberChef***](https://gchq.github.io/CyberChef/)


When the obfuscated text was copied into *CyberChef* and the ***From Base64*** data format was selected, the result is as follows:


![De-obfuscated PowerShell command](/images/2023-08-22-forensic-analysis-mitre-attack/image3.png)
*Figure 3. De-obfuscated PowerShell command*

Additionally, ***Remove null bytes*** can be selected to make it more readable.

![De-obfuscated PowerShell command – Remove null bytes](/images/2023-08-22-forensic-analysis-mitre-attack/image4.png)
*Figure 4. De-obfuscated PowerShell command – Remove null bytes*

From the command above, we can see that the adversary used the *BITSAdmin* command-line tool (*Background Intelligent Transfer Service Admin*) 
to download the malicious file ***64IBMserver.zip*** from the remote location to the ***C:\\Windows\\*** location and that the malicious file was 
extracted and executed. The malicious file was Ransomware that encrypted the entire server.
 

***Evidence of the file location on the disk and from $MFT***

![File location on the disk](/images/2023-08-22-forensic-analysis-mitre-attack/image5.png)
*Figure 5. File location on the disk*

![File creation evidence in the $MFT](/images/2023-08-22-forensic-analysis-mitre-attack/image6.png)
*Figure 6. File creation evidence in the $MFT*


**2) Sub-technique [**T1053.005 Scheduled Task**](https://attack.mitre.org/techniques/T1053/005/)** 


Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution 
of malicious code. Tasks can be scheduled on a remote system and adversaries may use task scheduling to 
execute programs at system startup or on a scheduled basis for persistence.


**Detection analysis**


In the picture below we can see the evidence of Scheduled Task Execution. The adversary created and 
started a scheduled task to execute the Powershell script.

![Scheduled Task execution](/images/2023-08-22-forensic-analysis-mitre-attack/image7.png)
*Figure 7. Scheduled Task execution*

The Powershell command was obfuscated.

![Obfuscated PowerShell command](/images/2023-08-22-forensic-analysis-mitre-attack/image8.png)
*Figure 8. Obfuscated PowerShell command*

After de-obfuscate that PowerShell command with *CyberChef*, the result is as follows:

![De-obfuscated PowerShell command](/images/2023-08-22-forensic-analysis-mitre-attack/image9.png)
*Figure 9. De-obfuscated PowerShell command*

From the command above, we can see that the adversary downloaded the malicious file ***flash.exe*** from the 
remote location to the ***C:\\Windows\\Temp\\*** location. After that, the file was executed. 

![File execution](/images/2023-08-22-forensic-analysis-mitre-attack/image10.png)
*Figure 10. Program execution*

An adversary managed to run a malicious file on the system. It used Powershell and Windows Task Scheduler to execute malicious code. 
The part 3 of the blog will cover the Persistence phase and techniques.
