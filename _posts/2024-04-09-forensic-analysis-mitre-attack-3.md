---
layout: post
title: Forensic analysis of MITRE ATT&CK Techniques 3 - Persistence
date: 2024-04-09
author: goran
categories: [forensic, windows, mitre, attack]
category: forensic, windows, mitre, attack
color: blue
tags: [forensic, analysis, windows, mitre, attack]
otherLanguages:
- locale: hr
  path: /hr/blog/2024-04-09-forensic-analysis-mitre-attack-3
- locale: sl
  path: /sl/blog/2024-04-09-forensic-analysis-mitre-attack-3
---
In the previous blog [**Forensic analysis of MITRE ATT&CK Techniques - PART 2**]({% post_url 2023-08-22-forensic-analysis-mitre-attack_2 %})
the second phase of the adversary was explained. In that phase the adversary managed to run a malicious file on the system using
*PowerShell* and *Windows Task Scheduler* to execute malicious code. 
Looking at the MITRE ATT&CK framework, the next goal of the adversary is to ensure persistence on the system.


## PART 3 - Persistence


In this phase of the attack, the adversary uses various techniques to keep access to the system over restarts, changed credentials 
or any other type of change that might disrupt access. 


**Persistence Techniques**

<a href="/images/2024-04-09-forensic-analysis-mitre-attack-3/image1.png" rel="nofollow noopener noreferrer" target="_blank">
<img src="/images/2024-04-09-forensic-analysis-mitre-attack-3/image1.png">
</a>
*Figure 1. Persistence Techniques*

This example will show two techniques, [**T1136 Create Account**](https://attack.mitre.org/techniques/T1136/), 
Sub-technique [**T1136.001 Local Account**](https://attack.mitre.org/techniques/T1136/001/) in which an adversary 
creates a local account to maintain access to the victim system, and  
[**T1547 Boot or Logon Autostart Execution**](https://attack.mitre.org/techniques/T1547/), 
Sub-technique [**T1547.001 Registry Run Keys/Startup Folder**](https://attack.mitre.org/techniques/T1547/001/) 
in which an adversary adds a shortcut file (*.lnk*) to Startup Folder to achieve persistence.


**1) Sub-technique [**T1136.001 Local Account**](https://attack.mitre.org/techniques/T1136/001/)**


Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured 
by an organization for use by users, remote support, services or for administration on a single system or service.


**Detection analysis**

     
In the picture below we can see the evidence of user account creation. The adversary created a local user account 
with the name ***sqlbackup***. Event ID **4720** indicates that a user account has been created.

![User Account Creation](/images/2024-04-09-forensic-analysis-mitre-attack-3/image2.png)

*Figure 2. User Account Creation*

The adversary also set the new password for the account ***sqlbackup***.  
Event ID **4724** indicates that an attempt was made to reset the account password. 

![Account Password Reset](/images/2024-04-09-forensic-analysis-mitre-attack-3/image3.png)

*Figure 3. Account Password Reset*

Additionally, Event ID **4738** also indicates that the account has been changed and provides the information 
about the last password set.

![Account Changed](/images/2024-04-09-forensic-analysis-mitre-attack-3/image4.png)

*Figure 4. Account Changed*

And finally, the adversary added account ***sqlbackup*** to local ***Administrators*** group. 
Event ID **4732**  indicates that the account was added to a security-enabled local group. 

![Account added to local Administrators group](/images/2024-04-09-forensic-analysis-mitre-attack-3/image5.png)

*Figure 5. Account added to local Administrators group*

When we go further into the forensic analysis, we find the evidence that the adversary opens ***Command Prompt*** 
a few seconds before creating the local account. The adversary wrote the command ***net user /add*** inside the 
***Command Prompt*** to create the local account. In the most cases, when the command ***net user*** was entered inside 
the ***Command Prompt***, the process **net.exe** was executed. We found evidence of this after parsing the **$MFT**.

The **net** command is a component of the Windows operating system, and it is used in command-line operations for 
control of users, groups, services, and network connections. 

![Command Prompt Opened](/images/2024-04-09-forensic-analysis-mitre-attack-3/image6.png)

*Figure 6. Command Prompt Opened*

![net.exe Execution](/images/2024-04-09-forensic-analysis-mitre-attack-3/image7.png)

*Figure 7. “net.exe” Execution*


**2) Sub-technique [**T1547.001 Registry Run Keys/Startup Folder**](https://attack.mitre.org/techniques/T1547/001/)** 

Adversaries may achieve persistence by adding a program to a *Startup Folder* or referencing it with a *Registry Run Key*. 
Adding an entry to the Run Keys in the *Registry* or *Startup Folder* will cause the program referenced to be executed 
when a user logs in. 

There is a *Startup Folder* location for individual user accounts as well as a system-wide *Startup Folder*.

The ***Startup Folder*** path for the ***current user*** is 

![Startup Folder - Current User](/images/2024-04-09-forensic-analysis-mitre-attack-3/image8.png)

*Figure 8. Startup Folder - Current User*

The ***Startup Folder*** path for ***all users*** is  

![Startup Folder – All Users](/images/2024-04-09-forensic-analysis-mitre-attack-3/image9.png)

*Figure 9. Startup Folder – All Users*

Adversaries can maintain persistence on the system and evade detection by security software, using the 
*Startup Folder* on the two ways:

- ***Placing a malicious shortcut in the Startup Folder*** - place a shortcut to a malicious executable in the
  *Startup Folder* and when the user logs in to the system the malicious code will be automatically executed

- ***Hijacking an existing shortcut*** - modify an existing, legitimate shortcut in the *Startup Folder* to point
  to a malicious executable instead of the intended application

The shortcut file placed in the *Startup Folder* is a ***Windows Shortcut File (.LNK)*** which can in many scenarios 
execute a Command and Control (C2) agent or code that will automatically download an agent in an obfuscated way.


**Detection analysis**


The detection analysis will include the way in which adversaries place a malicious shortcut in the *Startup Folder* 
for the ***current user***.

In the picture below we can see that the adversary created shortcut ***OneDrive.lnk*** in the *Startup Folder* of the current user.

![OneDrive.lnk Created](/images/2024-04-09-forensic-analysis-mitre-attack-3/image10.png)

*Figure 10. OneDrive.lnk Created*

Of course, the name of the shortcut is fake, and the shortcut doesn’t represent the real *OneDrive software*. 
Analyzing the shortcut ***OneDrive.lnk*** we find evidence that *PowerShell* was called to download the batch file ***onedrive.bat*** and run it.

![OneDrive.lnk Details](/images/2024-04-09-forensic-analysis-mitre-attack-3/image11.png)

*Figure 11. OneDrive.lnk Details*

When the user logged in, the *PowerShell* command was executed and the batch file ***onedrive.bat*** was downloaded on 
the location ***C:\Windows\Temp***.

![onedrive.bat Created](/images/2024-04-09-forensic-analysis-mitre-attack-3/image12.png)

*Figure 12. “onedrive.bat” Created*

After that the batch file was executed with ***Command Prompt***.

![onedrive.bat Executed](/images/2024-04-09-forensic-analysis-mitre-attack-3/image13.png)

*Figure 13. “onedrive.bat” Executed*

The batch file ***onedrive.bat*** represented the C2 agent which periodically connects to the C2 server to check for commands.

An adversary managed to ensure persistence on the system. Adversary created the local account and placed a malicious shortcut 
in the *Startup Folder*. The part 4 of the blog will cover the Credential Access phase and techniques.
