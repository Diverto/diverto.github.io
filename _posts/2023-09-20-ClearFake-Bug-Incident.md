---
layout: post
title: ClearFake utilizes fake Chrome updates to deliver Amadey and RedLine stealers
date: '2023-09-20'
author: igor
category: 'Malware, Windows'
categories: [windows, malware]
color: 'mediumvioletred'
tags: [windows, malware]
otherLanguages:
- locale: sl
  path: /sl/blog/2023-09-20-ClearFake-Bug-Incident
- locale: hr
  path: /hr/blog/2023-09-20-ClearFake-Bug-Incident
---

Diverto SOC team recently received ClearFake malware that was delivered through a drive-by download attack on [Mreza Bug](https://mreza.bug.hr), which is one of Croatia's biggest IT websites. ClearFake is a new malware similar to SocGholish and uses JavaScript injection to present users with fake MSIX Google Chrome updates. After a successful download, the user who starts the update procedure will eventually be infected by Amadey and RedLine stealers. RedLine is directly downloaded and executed, but Amadey infostealer is actually loaded by IDAT loader, which resembles IDAT loader described by Rapid7, but with few differences.

This article describes techniques used by attackers in the September 2023 attack, from the initial visit of the website to the final delivery of Amadey and RedLine stealers. At the end of the article, there are tips for hunting ClearFake malware and IOC's specific to the attack, which will hopefully be useful for hunting or further understanding of this new threat. Some well-known concepts like Amadey and RedLine stealer will be described only briefly.

Although we have not successfully captured all steps of the attack, we believe this is sufficient to explain the steps in entire chain of attack.

### ClearFake delivery

Our users detected that after a few seconds of browsing through [Mreza Bug](https://mreza.bug.hr), they were presented with a Google Chrome Update page as seen in Figure 1. This was very unusual and suspicious because the update itself was presented on legitimate page, and the website is not known to host that kind of page. On top of that, a Google Chrome update was presented on any browser, not just Chrome, as long as users were on the Windows operating system. The displayed page invited users to download MSIX file that was supposed to update their browser. Interestingly, the name of the MSIX file was tailored according to the browser, although the fake page was always for Google Chrome. For example, users who used Chrome could download ChromeSetup.msix, while users who used Opera browser were offered OperaSetup.msix, but from a malicious perspective, these files were identical..

![Figure 1 (Fake Google Chrome Update Page)](/images/2023-09-20-clearfake-bug-incident/figure1.png)

*Figure 1 (Fake Google Chrome Update Page)*

After closer inspection of the source code of page which showed a fake Chrome update, we noticed the use of Ethers.js library and base64 encoded string.

![Figure 2 (Malicious code on website)](/images/2023-09-20-clearfake-bug-incident/figure2.png)

*Figure 2 (Malicious code on website)*

Ethers.js is a JavaScript library used to communicate with the Ethereum Blockchain, and as it turns out base64 encoded string did exactly that. It communicated with Binance Smart Chain (BNB Chain), fork of the Ethereum Blockchain, to retrieve the payload for the next stage. The decoded base64 is shown in Figure 3.

![Figure 3 (Decoded base64 string)](/images/2023-09-20-clearfake-bug-incident/figure3.png)

*Figure 3 (Decoded base64 string)*

Malicious code communicates with Smart Contract on address **0x7f36D9292e7c70A204faCC2d255475A861487c60** through Binance public RPC Node **bsc-dataseed1**. By using BscScan it is possible to get additional information about Smart Contract and its transactions. Smart Contract was created in early September 2023, and continues to push updates that host malicious URLs. 

![Figure 4 (Smart Contract Transaction History)](/images/2023-09-20-clearfake-bug-incident/figure4.png)

*Figure 4 (Smart Contract Transaction History)*

The transaction that is related to our incident is **0x09a5f9c76763f4bd4b4b06417471f027edcd41877fd5bdc80aa6c3214b1e9a7c**. By inspecting and decoding the base64 data of that transaction, we arrive at the URL that will be used by eval function in Figure 3.

![Figure 5 (Malicious URL redirect)](/images/2023-09-20-clearfake-bug-incident/figure5.png)

*Figure 5 (Malicious URL redirect)*

ClearFake uses multiple payloads and redirects to arrive at the final destination of the fake Google Chrome update page, but we were unable to fetch all payloads. After all payloads are fetched and Fake Google Chrome Update page is presented, the user can download MSIX file. MSIX file contains a legitimate updater file, but also an additional malicious PowerShell script called **shark.ps1**, which acts as a downloader for other malware. PowerShell script shark.ps1 is executed immediately after MSIX file is started. This is done through Package Support Framework (PSF) which can be used to run one PowerShell script before a packaged application executable runs. This option is set in the **config.json** file of MSIX, and as it can be seen in Figure 6, it is set to shark.ps1.

![Figure 6 (MISX config.json)](/images/2023-09-20-clearfake-bug-incident/figure6.png)

*Figure 6 (MISX config.json)*

Main objectives of shark.ps1 script is to download files **kone.rar.gpg** and **1.jpg**, which will eventually run and start Amadey and RedLine stealers. Content of shark.ps1 can be seen in Figure 7.

![Figure 7 (shark.ps1 PowerShell script)](/images/2023-09-20-clearfake-bug-incident/figure7.png)

*Figure 7 (shark.ps1 PowerShell script)*

Kone.rar.gpg file is a password protected RAR archive with the password **"putin"**. After successful decryption and decompression, the archive contains legitimate ICQ software, and two malicious files: **coolcore49.dll** and **icq.irc**. coolcore49.dll is loaded when ICQ is started and will hijack execution completely, while icq.irc is a PNG file that contains an encrypted payload inside IDAT section and will be used by coolcore49.dll. Based on analysis of coolcore49.dll, it was determined that this is IDAT loader which will eventually drop Amadey infostealer.

1.jpg file is actually .NET executable that contains RedLine infostealer and it is started directly from the shark.ps1 script.

### IDAT loader

Kone.rar.gpg archive contains a legitimate ICQ.exe file, with its DLLs, and additional coolcore49.dll and icq.irc PNG image. When shark.ps1 script runs ICQ.exe, malicious coolcore49.dll is loaded, and immediately redirects execution to coolcore49.dll entry point, so ICQ entry point is never actually reached. During the execution of coolcore49.dll, it loads the icq.irc PNG file in memory and searches for the IDAT section whit magic bytes *0xC6 0xA5 0x79 0xEA*.

![Figure 8 (IDAT search function)](/images/2023-09-20-clearfake-bug-incident/figure8.png)

*Figure 8 (IDAT search function)*

After the entire IDAT section is loaded, the next step is decryption of the buffer, which is XOR encrypted with the key which follows IDAT magic bytes, and in our case key was *0x92 0x83 0x5B 0xE9*. Decryption function is shown in Figure 9. When the buffer is decrypted, it is additionally decompressed with RtlDecompressBuffer. 

![Figure 9 (IDAT decryption function)](/images/2023-09-20-clearfake-bug-incident/figure9.png)

*Figure 9 (IDAT decryption function)*

Next step of IDAT malware is loading **mshtml.dll** and replacing its .text section with part of the decrypted and decompressed buffer. After shellcode is injected, execution is redirected to the start of mshtml.dll .text section.

![Figure 10 (Start of mshtml injected payload)](/images/2023-09-20-clearfake-bug-incident/figure10.png)

*Figure 10 (Start of mshtml injected payload)*

Mshtml.dll injected payload then XOR encrypts a large part of initially decrypted and decompressed buffer with key **0xCF 0x37 0xA7 0xA6** and stores it in 8 character random file name in **%TEMP%** directory. An example of XOR encrypted file stored in **5edfe0f7** file is shown in Figure 11.

![Figure 11 (XOR encrypted file)](/images/2023-09-20-clearfake-bug-incident/figure11.png)

*Figure 11 (XOR encrypted file)*

After storing the file, mshtml.dll injected payload starts cmd.exe, loads mshtml.dll into it, and replaces its .text section with another part of initially decrypted and decompressed buffer. This is all done through the Heaven's Gate technique.

![Figure 12 (Heaven's Gate technique)](/images/2023-09-20-clearfake-bug-incident/figure12.png)

*Figure 12 (Heaven's Gate technique)*

Heaven's Gate technique is used to make analysis more complex, but the whole code of 64-bit is relatively simple, and all it does is make direct **syscall** to ntdll.dll functions (NtCreateSection + NtMapViewOfSection + NtWriteVirtualMemory + NtResumeThread), which then successfully load the payload inside mshtml.dll in cmd.exe. Figure 13 shows 64-bit code.

![Figure 13 (Heaven's Gate syscall function)](/images/2023-09-20-clearfake-bug-incident/figure13.png)

*Figure 13 (Heaven's Gate syscall function)*

After mshtml.dll is mapped inside cmd.exe and thread is resumed, ICQ.exe is terminated, and cmd.exe continues execution. Injected payload first reads an XOR encrypted file, and decrypts it in a buffer. Part of the buffer is then used to create a file using the Process Doppelgänging Transaction functions (RtlSetCurrentTransaction + NtCreateSection + NtRollbackTransaction). This file contains actual Amadey infostealer. When a transaction is discarded with NtRollbackTransaction and a file is mapped inside cmd.exe using NtCreateSection, then the explorer.exe is spawned. After explorer.exe process is created, cmd.exe copies the section containing Amadey infostealer using NtMapViewOfSection into it. Finally, cmd.exe injects additional code inside explorer.exe .text section with NtWriteVirtualMemory function and resumes explorer.exe. All ntdll.dll functions are called using Heaven's Gate technique. The full process chain is shown in Figure 14.

![Figure 14 (Process chain)](/images/2023-09-20-clearfake-bug-incident/figure14.png)

*Figure 14 (Process chain)*

At the end, cmd.exe will terminate, and explorer.exe will redirect its execution to the mapped section, which contains Amadey infostealer.

### Amadey and Redline infostealers

Amadey and RedLine stealers are very well-known malware families and heavily documented. RedLine stealer is downloaded and directly executed through shark.ps1 PowerShell script. Infostealer is protected with .NET Reactor obfuscator, which is used to hinder malware analysis. On the other hand, Amadey stealer version 3.88 arrives via more convoluted path, through IDAT loader which is described in the previous section. Indicators for both are provided in the Appendix A of this article.

### APPENDIX A - INDICATORS OF COMPROMISE

* SHA1 Hashes:
  * 7b2fc957c43c9b16ea4ccc54267dca04418a3207 (ChromeSetup.msix)
  * d230494f63112fb028c450c75b105c2ce33c634b (OperaSetup.msix)
  * 2d2073923ac7815f5e9ea5b452243dda56e2b4f1 (Firefox_Installer.msix)
  * 972d76f68c415cd4058864bfbb409209d78c75bf (shark.ps1)
  * 786def7bb0043faab8f35b989dcdd63e969734ad (kone.rar.gpg)
  * 2a4f43613df9d39ef8bcf650ee01b29ee20ed0a8 (RedLine)
  * 2b4d14ef562e7ea95519358530eef0f6577148eb (RedLine - served the next day)

* Filenames:
  * ChromeSetup.msix
  * OperaSetup.msix
  * Firefox_Installer.msix
  * shark.ps1
  * kone.rar.gpg
  * 1.jpg

* Network:
  * hxxps[:]//vvooowkdqddcqcqcdqggggl[.]site/vvmd54/ (URL fetched from BNB Chain)
  * hxxps[:]//trustdwnl[.]ru/1.jpg (RedLine)
  * hxxps[:]//trustdwnl[.]ru/kone.rar.gpg (IDAT Loader + Amadey)
  * 5[.]42[.]65[.]60:29012 (RedLine C2)
  * 5[.]42[.]64[.]33 (Amadey C2)

###APPENDIX B - YARA RULES

```
rule idat_loader 
{
    strings:
        $idat_section_search = { 81 ?? C6 A5 79 EA 75 ?? 83 ?? ?? 00 75 ?? 8B ?? ?? 89 ?? ?? 8B ?? ?? 8B ?? ?? 83 ?? 10 89 ?? ?? 8B ?? ?? ?? 6A 40 8B ?? ?? 8B ?? ?? FF ?? 89 ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? 0C 8B ?? ?? 03 ?? ?? 89 ?? ?? EB }
        
        $idat_decryption = { 8B ?? 83 ?? ?? 8B ?? ?? 89 ?? ?? 8B ?? ?? 33 ?? B9 04 00 00 00 F7 ?? 85 ?? 74 ?? 8B ?? ?? 83 ?? ?? 89 ?? ?? EB ?? C7 ?? ?? 00 00 00 00 EB ?? 8B ?? ?? 83 ?? 04 89 ?? ?? 8B ?? ?? 3B ?? ?? 73 ?? 8B ?? ?? 03 ?? ?? 89 ?? ?? 8B ?? ?? 8B ?? 89 ?? ?? 8B ?? ?? 33 ?? ?? 8B ?? ?? 89 ?? EB ?? 8B }
    
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $idat_section_search and $idat_decryption
}
```
###APPENDIX C - USEFUL REFERENCES

[https://www.rapid7.com/blog/post/2023/08/31/fake-update-utilizes-new-idat-loader-to-execute-stealc-and-lumma-infostealers/](https://www.rapid7.com/blog/post/2023/08/31/fake-update-utilizes-new-idat-loader-to-execute-stealc-and-lumma-infostealers/)

[https://securitynews.sonicwall.com/xmlpost/amadey-malware-has-improved-its-string-decoding-algorithm/](https://securitynews.sonicwall.com/xmlpost/amadey-malware-has-improved-its-string-decoding-algorithm/)

[https://www.malwarebytes.com/blog/news/2018/08/process-doppelganging-meets-process-hollowing_osiris](https://www.malwarebytes.com/blog/news/2018/08/process-doppelganging-meets-process-hollowing_osiris)
