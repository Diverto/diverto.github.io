---
layout: post
title: Forensic analysis of MITRE ATT&CK Techniques
date: 2022-12-18
author: goran
categories: [forensic, windows, mitre, attack]
category: forensic, windows, mitre, attack
color: blue
tags: [forensic, analysis, windows, mitre, attack]
otherLanguages:
- locale: hr
  path: /hr/blog/2022-12-18-forensic-analysis-mitre-attack
---
Cyber-attacks have become every day and forensic analysis plays an
important role in the investigation of cyber incidents. When a security
incident occurs, it is important to perform a forensic analysis to
obtain details about the incident.

<!--more-->

## Introduction

Forensic analysis can provide answers related to a security incident, such as:

![Figure 1. Digital Forensics 5W (DF5W)](/images/2022-12-18-forensic-analysis-mitre-attack/media/image1.JPG)

*Figure 1. Digital Forensics 5W (DF5W)*

In the almost every cyber-attack, the adversaries use different tactics
and techniques to get to the victim or to compromise the system. The
MITRE ATT&CK framework provides a knowledge base that tracks cyber
adversary tactics and techniques used by threat actors across the entire
attack lifecycle.

It is intended to be used as a tool to strengthen an organization's
security posture and to deduce an adversary's motivation more easily for
individual actions and understand how those actions relate to specific
classes of defenses.

![Figure 2. MITRE ATT&CK framework](/images/2022-12-18-forensic-analysis-mitre-attack/media/image2.png)
*Figure 2. MITRE ATT&CK framework*

The idea of this blog is to show how some MITRE ATT&CK Techniques can be
detected, on the real forensic examples. The blog series will cover the
adversary techniques from Initial Access, Execution, Persistence,
Privilege escalation, Defense Evasion, Lateral Movement, Command and
Control, Exfiltration and provide examples of how attackers have used
these techniques in a ***Windows environment***.

## PART 1 - Initial access

In the first phase of the attack, the adversary is simply looking to
gain a foothold in the organization's network. To gain initial access, a
threat actor might attempt several techniques that range from simple but
effective phishing campaigns to more sophisticated supply chain attacks
or exploitation of remote and public-facing applications using known and
unknown (zero-day) vulnerabilities.

**Initial Access Techniques**

![Figure 3. Initial Access Techniques](/images/2022-12-18-forensic-analysis-mitre-attack/media/image3.png)

*Figure 3. Initial Access Techniques*

This example will show the techniques [**T1078 Valid
Accounts**](https://attack.mitre.org/techniques/T1078/),
[***Sub-techniques T1078.003 Local
Accounts***](https://attack.mitre.org/techniques/T1078/003/) in which an
adversary obtains and abuses credentials by brute-forcing the local
admin password. An adversary uses automated tools to guess all possible
passwords until the correct input is identified (*Dictionary attack*).

**Detection analysis**

In the picture bellow we can see multiple failed logons attempts for the
user "***admin***". The Windows OS record multiple *Event ID* "*4625*"
which indicates "*Failed Logon*" attempts.

![Figure 4. Failed Logon Attempts](/images/2022-12-18-forensic-analysis-mitre-attack/media/image4.jpg)

*Figure 4. Failed Logon Attempts*

The failed logons attempts were every 2 seconds.

![Figure 5. Failed Logon Attempts - every 2 seconds](/images/2022-12-18-forensic-analysis-mitre-attack/media/image5.jpg)

*Figure 5. Failed Logon Attempts - every 2 seconds*

The next thing is to look the "*Sub Status*" code within the description
of the *Event ID* "*4625*". This is important because that code provides
a detailed failure information.

**Sub Status Error Codes**

| **Event ID 4625 (Sub Status Codes)** |                **Reason**                 | 
| :----------------------------------: | :---------------------------------------- |
| 0xC0000064                           | Invalid/non-existent username             |
| 0xC000006A                           | Invalid/Wrong password (username correct) |
| 0xC0000071                           | Expired password                          |
| 0xC0000234                           | Account locked, disabled or expired       |
| 0xC0000072                           | Disabled account                          |
| 0xC0000193                           | Expired account                           |
 
*Table 1. Sub Status Error Codes*

In this case, the "*Sub Status*" code is "***C000006A***" which
represents failed login attempts with the "***Invalid/Wrong
password***".

![Figure 6. Sub Status code -- C000006A](/images/2022-12-18-forensic-analysis-mitre-attack/media/image6.jpg)


*Figure 6. Sub Status code -- C000006A*

This is the evidence that adversary used a password dictionary
brute-force tool for the attack. After a few hours, adversary
successfully obtain the password of the user "***admin***". The evidence
showed that the adversary after obtaining the password, successfully
established a connection to the system.

![Figure 7. Adversary established connection](/images/2022-12-18-forensic-analysis-mitre-attack/media/image7.jpg)

*Figure 7. Adversary established connection*

Windows OS record *Event ID* "*4624*" which indicates "*Successfully
Logon*" with the account "***admin***". An important thing to pay
attention to, is the filed "***Logon Type: 10***" which shows Remote
interactive logon. The adversary logged on this system remotely using
Remote Desktop Protocol.

The evidence about successfully RDP connection also found in the Windows
OS *Event ID "21"* which appears after an account has been successfully
authenticated.

![Figure 8. RDP connection](/images/2022-12-18-forensic-analysis-mitre-attack/media/image8.jpg)

*Figure 8. RDP connection*

The adversary achieved his goal by obtaining and abusing the credentials
of existing local account to gain initial access on the system. The part
2 of the blog will cover the Execution phase and techniques.
