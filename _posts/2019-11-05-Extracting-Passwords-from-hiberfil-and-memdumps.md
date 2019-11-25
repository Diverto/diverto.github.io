---
layout: post
title: Extracting passwords from hiberfil.sys and memory dumps
author: kost
categories: [windows]
tags: [windows, password, hiberfil.sys, hibernate, memdumps]
---

When in password hunting mode and having access to the filesystem of the target, most people would reach out to SAM and/or extracting cached credentials.
While this can usually be the way to go, it can pose a huge challenge, as the result can depend on the strength of the storage format of the password and the strength of the password itself.
Something often overlooked is hiberfil.sys and/or virtual machine snapshots or memory dumps, as they usually contain passwords in plain text.
When you have those, there's no need for cracking at all and it doesn't depend on password strength/size.

Methods described in this article can be used in different scenarios: from the DFIR side and also from the offensive side.
Main requirement is that you somehow have access to the required file (like hiberfil.sys), snapshot or the memory dump.
It can be from the backup, obtained from the live system or a virtual machine. It doesn't matter.
The only challenge is to actually convert it to the proper format of standard crash dump format (DMP).

![Conversion Path]({{ site.baseurl }}/images/hiberfil-dump-password/conversion-paths.png)

## Introduction

We're taking advantage of a less known feature of mimikatz that it can work on memory/crash dumps through windbg extension called `mimilib.dll`.
This technique is [quite old](http://blog.gentilkiwi.com/securite/mimikatz/windbg-extension) and [already known](https://www.remkoweijnen.nl/blog/2013/11/25/dumping-passwords-in-a-vmware-vmem-file/), but that information is still not that widespread, especially the part that you can take the advantage of the Volatility framework for conversion.

## File copy methods

Windows uses hiberfil.sys as a file where it stores hibernated (RAM) data. Its usual location is `C:\hiberfil.sys` and it is hidden system file, so you will have problem with copying it directly.
There is excellent article [7 Tools to Copy Locked or In Use Files](https://www.raymond.cc/blog/copy-locked-file-in-use-with-hobocopy/) that can help you obtain it from the live system.

I had good experience with extracting system files from vmdk, vhd and similar formats using PowerISO (even with the trial version).

There are some cases where hiberfil.sys is present, but it is not yet used. It is a good practice to actually check if hiberfil.sys is empty (all zero bytes).
File size can be quite big, but there is still a possibility that it's filled with only zero bytes.
The following shell oneliner can help you in determining if file is filled with zero bytes only:

```bash
cat hiberfil.sys | tr -d '\0' | read -n 1 || echo "All null bytes"
```

Oneliner will display `All null bytes` if file is filled with zero bytes.

## Converting hiberfil.sys to dmp format

hiberfil.sys cannot be read directly by windbg, so hiberfil.sys should be converted to standard crashdump dmp format which can be read by windbg.
There are multiple ways to do it. We can take advantage of the Volatility Framework or commercial Comae Toolkit (aka Moonsols tools).

### Converting to dmp format using Volatility

Conversion using Volatility Framework is multi-step process. First, it is good practice to identify the image itself:

```console
C:\> volatility_standalone.exe -f d:\hiberfilsys.copy imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : No suggestion (Instantiated with Win7SP1x64)
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : WindowsHiberFileSpace32 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (D:\copy\hiberfilsys.copy)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002a460a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002a47d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-11-04 20:32:59 UTC+0000
     Image local date and time : 2019-11-04 21:32:59 +0100
```

We can also get the basic information about the hibernate file:

```console
C:\> volatility_standalone.exe -f d:\hiberfilsys.copy --profile=Win7SP1x64 hibinfo
Volatility Foundation Volatility Framework 2.6
PO_MEMORY_IMAGE:
 Signature: HIBR
 SystemTime: 2019-11-04 20:32:59 UTC+0000

Control registers flags
 CR0: 80050031
 CR0[PAGING]: 1
 CR3: 00187000
 CR4: 000406f8
 CR4[PSE]: 1
 CR4[PAE]: 1

Windows Version is 6.1 (7601)
```

The first step is to convert it to the raw memory dump format using `imagecopy`:

```console
C:\> volatility_standalone.exe -f d:\hiberfilsys.copy imagecopy --profile=Win7SP1x64 -O hiber.raw
Volatility Foundation Volatility Framework 2.6
Writing data (5.00 MB chunks): |...............
```

Next step would be to convert raw memory dump to the crash dump format using `raw2dmp` volatility command:

```console
C:\> volatility_standalone.exe -f hiberfil.raw --profile=Win7SP1x64 raw2dmp -O hiberfil.dmp
Volatility Foundation Volatility Framework 2.6
Writing data (5.00 MB chunks): |...............
```

### Converting to dmp format using Comae Toolkit

There is straight way to convert hibernate files to crash dump (dmp) format.
Comae toolkit comes with Hibr2Dmp.exe utility which can directly convert the target hibernate file.

```console
C:\> Hibr2Dmp.exe hiberfil.sys hiberfil.dmp

Hibr2Dmp 3.0.20190124.1
Copyright (C) 2007 - 2017, Matthieu Suiche <http://www.msuiche.net>
Copyright (C) 2012 - 2014, MoonSols Limited <http://www.moonsols.com>
Copyright (C) 2015 - 2017, Comae Technologies FZE <http://www.comae.io>
Copyright (C) 2017 - 2018, Comae Technologies DMCC <http://www.comae.io>

Initializing memory descriptors... Done.
Sorting 199949 entries... 88 seconds.
Looking for kernel variables... Done.
Loading file... Done.
nt!KiProcessorBlock.Prcb.Context = 0xFFFFF80002FFFFA0

[0x000000011E000000 of 0x000000011E000000]
MD5 = 04AEAAA37C21455DEF0F970E76D82185

Total time for the conversion: 2 minutes 30 seconds.
```

## Converting virtualization snapshots to dmp format

hiberfil.sys cannot be read directly by windbg, so hiberfil.sys should be converted to standard crashdump dmp format which can be read by windbg.
There are multiple ways to do it. We can take advantage of Volatility Framework or commercial tool like Comae Toolkit (aka Moonsols tools).

### Converting VMware snapshot to dmp

VMware saves the memory dump of the guest virtual machine every time you snapshot the virtual machine when the guest is running.

Once you have the snapshot, in most cases you have raw memory image in vmem file.
You just need to find the snapshot file ending with .vmem.

The next step consists of converting raw memory dump to the crash dump (dmp) format.
There are different ways to accomplish this.

VMware have its own tool called `vmss2core` that you can use to convert vmem file to crash dump (dmp) format.

You can use it the following way:

```console
vmss2core.exe -W snapshot.vmsn snapshot.vmem
```

If the snapshot file is from a Windows 8/Server 2012 or later VM, the command line is:

```console
vmss2core.exe -W8 snapshot.vmsn snapshot.vmem
```

Output of this command is `memory.dmp` file in same directory.

#### Alternative Vmware conversions

One of the alternatives, would be to convert it using `Bin2Dmp.exe` from [Comae Toolkit](https://my.comae.io/) :

```console
C:\> Bin2Dmp.exe vmware.vmem vmware.dmp
```

Other alternative is to use Volatility's `raw2dmp` converter, but you will need to specify the profile:

```console
C:\> volatility_standalone.exe -f vmware.vmem --profile=Win7SP1x64 raw2dmp -O vmware.dmp
Volatility Foundation Volatility Framework 2.6
Writing data (5.00 MB chunks): |..........|
```

### Converting VirtualBox snapshot to dmp

VirtualBox memory dumps can be triggered by using `debugvm` command of vboxmanage:

```console
$ vboxmanage debugvm "win7test" dumpvmcore --filename testvbox.elf
```

VirtualBox memory dump comes in ELF format where load1 segment holds the raw memory dump.
So, simple bash script was made to extract only the raw memory dump.
[Andrea](https://github.com/andreafortuna) already released a helpful script, but the script itself did not work for me.
So, I have modified it to work and published it as
[vboxelf2raw](https://gist.github.com/kost/606145346d47c5ed0469d4e9ac415927).
Usage of vboxelf2raw is illustrated in the following example:

```bash
# ./vboxelf2raw.sh testvbox.elf
testvbox.elf -> testvbox.elf.raw (off: 0x2560, size: 0x80000000)
```

By having the memory dump in a raw format, further process is straightforward.
Using Volatility's `raw2dmp` command, raw format is converted to the crash dump (dmp) format:

```console
C:\> volatility_standalone.exe -f testvbox.elf.raw --profile=Win7SP1x64 raw2dmp -O testvbox.dmp
Volatility Foundation Volatility Framework 2.6
Writing data (5.00 MB chunks): |..........|
```

Output of the previous command is a file *testvbox.dmp* in dmp format.

## Dumping passwords through Windbg

Once you have the file in a dmp format, you can easily load the obtained dump in the windbg using `File -> Open Crash Dump` and load the file:

![Windbg open crash dump]({{ site.baseurl }}/images/hiberfil-dump-password/windbg-crashdump-file.png)

Now, you just have to load [mimikatz](https://github.com/gentilkiwi/mimikatz) windbg plugin (mimilib.dll), find lsass process in the dump and invoke mimikatz to perform its magic:

```
.load d:\mimikatz_trunk\x64\mimilib.dll
!process 0 0 lsass.exe
.process /r /p fffffa800a25ab30
!mimikatz
```

Note that `fffffa800a25ab30` is the address I actually obtained in the previous step (`!process 0 0 lsass.exe`).
You can check the steps in the following screenshot:

![Windbg open crash dump]({{ site.baseurl }}/images/hiberfil-dump-password/windbg-mimi.png)

If you don't get any output when you issue command `!process 0 0 lsass.exe`, check if the target is 32 or 64 bit.
If the target is 64 bit and you get x86 prompt like this:

```
16.kd:x86>
```

That means that probably you need to force switch to 64-bit using the following commands:

```
.load wow64exts
!wow64exts.sw
```

This will switch to 64-bit and prompt should look like this:

```
16.kd>
```

When you get a 64-bit prompt, you can try to repeat the process again (finding the lsass process and dumping it with mimikatz).

As you can see, the process identified the password `Strong!Passw0rd11`, which is quite long and, having only the hash, would take quite some time to crack it:

```
Authentication Id : 0 ; 82274 (00000000:00014162)
Session           : Interactive from 1
User Name         : user
Domain            : user-PC
Logon Server      : USER-PC
[..]
        tspkg :
         * Username : user
         * Domain   : user-PC
         * Password : Strong!Passw0rd11
```

## Volatility mimikatz plugin

There is an alternative to using windbg mimikatz plugin, as there is [volatility mimikatz.pl](https://github.com/RealityNet/hotoloti/blob/master/volatility/mimikatz.py) plugin.
You just need to install Volatility plugin and issue the `mimikatz` command:

```console
C:\> volatility_standalone.exe -f testvbox.elf.raw --profile=Win7SP1x64 mimikatz
```

Of course, the aforementioned method is limited to the formats that volatility supports.

## Remediations

It all adds up to restricting the access to the sensitive data and its backup.
If somebody can access your backup of hiberfil.sys or snapshot of the virtual machine, you can assume that attacker gained access to the plaintext password - not just hash.

If you are worried that someone might extract useful information from your hiberfil.sys, you can reduce the risk of extracting passwords by implementing full-disk encryption (BitLocker).
There is also an option to disable hibernation feature as well. You can turn off the hibernate feature using the console:

```console
C:\> powercfg /hibernate off
```

### Tools

Tools mentioned in this article:

 - [volatility](https://github.com/volatilityfoundation/volatility) - An advanced memory forensics framework
 - [Hibr2Bin](https://github.com/comaeio/Hibr2Bin) - Comae Hibernation File Decompressor
 - [Comae Toolkit](https://my.comae.io/) - Comae Toolkit which includes hibr2dmp, hibr2bin and Bin2Dmp
 - [mimikatz](https://github.com/gentilkiwi/mimikatz) - A little tool to play with Windows security
 - [vboxelf2raw](https://gist.github.com/kost/606145346d47c5ed0469d4e9ac415927) - script to convert from vbox elf to raw memory dump
 - [windbg](https://www.windbg.org) - Microsoft Windows Debugger - windbg
 - [volatility mimikatz.pl](https://github.com/RealityNet/hotoloti/blob/master/volatility/mimikatz.py) - mimikatz plugin for volatility

### References

 - [7 Tools to Copy Locked or In Use Files](https://www.raymond.cc/blog/copy-locked-file-in-use-with-hobocopy/)
 - [WinDbg et l’extension de mimikatz](http://blog.gentilkiwi.com/securite/mimikatz/windbg-extension)
 - [How to extract a RAM dump from a running VirtualBox machine](https://www.andreafortuna.org/2017/06/23/how-to-extract-a-ram-dump-from-a-running-virtualbox-machine/)
 - [Virtualbox: VM Core Format](https://www.virtualbox.org/manual/ch12.html#ts_guest-core-format)

