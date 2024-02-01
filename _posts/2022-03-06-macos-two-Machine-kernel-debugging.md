---
layout: post
title: MacOS Two-machine Kernel Debugging
date: 2022-03-06
author: antonio
categories: [macos, fuzzing]
category: macos, fuzzing
color: red
tags: [macos, fuzzing, kernel, debugging ]
otherLanguages:
- locale: hr
  path: /hr/blog/2022-03-06-macos-two-Machine-kernel-debugging
---
If you are a macOS security researcher, chances are that at some point
you’ll have to perform kernel-level code debugging. While there are many
great and helpful blog posts on topic of macOS kernel debugging, the
fact is that at this point they are slightly outdated and mostly focused
on using virtual machines.

The focus of this blog post is to describe how to perform two-machine
kernel debugging on newer devices including Apple Silicon and the latest
macOS version, which at the time of writing is macOS Monterey 12.2.1.

# Setup

The setup described in this blog post includes an:

-   Intel-based host device

-   Intel-based and Apple Silicon target devices

Intel-based devices are models released after 2020 that have only
Thunderbolt 3/Thunderbolt 4/USB-C support, and the same applies for
Apple Silicon.

The Kernel Debug Kit for macOS (*KDK\_ReadMe*), used in this blog post
as an official reference guide, describes that:

-   The target device is the Mac that runs the code you want to debug

-   The host device is the Mac that runs the debugger

Additionally, you cannot perform two-machine debugging using neither USB
Ethernet adapters nor wireless networking on any Mac. You must
connect the host and a target device to the same network, but there are
no other restrictions on how these devices are connected to that
network.

This means that we can use an ethernet cable and a total of four
additional adapters:

-   Two Thunderbolt 3 (USB-C) to Thunderbolt 2 Adapters

<img src="/images/2022-03-06-macos-two/media/image1.png"
style="width:1.9685in;height:1.9685in" alt="Inline - 1" />

*Figure 1 - Thunderbolt 3 (USB-C) to Thunderbolt 2 Adapter*

-   Two Thunderbolt to Gigabit Ethernet Adapters

<img src="/images/2022-03-06-macos-two/media/image2.png"
style="width:1.9685in;height:1.9685in" alt="Inline - 1" />

*Figure 2 - Thunderbolt to Gigabit Ethernet Adapter*

# Configuration

When configuring macOS for kernel debugging, the first thing to do is to
identify the build version by running the ***sw\_vers*** command in
terminal:

```sw_vers```

```ProductName: macOS```

```ProductVersion: 12.1```

```BuildVersion: 21C52```

The build version is important to download the appropriate
version of Kernel Debug Kit (KDK) from the [Apple’s Developer
Downloads](https://developer.apple.com/download/) site. For example, in
this setup the appropriate KDK file is
*Kernel\_Debug\_Kit\_12.1\_build\_21C52*.

Once installed, it will be located under
*/Library/Developer/KDKs/KDK\_12.1\_21C52.kdk/*. Inside the mentioned
directory there is a *KDK\_ReadMe* file which contains all the necessary
information regarding the macOS kernel debugging setup and
configuration, as well as a System directory with different kernel and
kernel extension variants:

-   kernel (release)

-   kernel.development (development)

-   kernel.kasan (kasan)

For two-machine kernel debugging it is necessary to:

-   install the KDK on both the host and target devices

-   configure the target devices

## Host:

### Intel-based

To configure an Intel-based Mac as a host device:

-   Install the appropriate version of KDK

-   [Download](https://developer.apple.com/download/) and install Xcode
    12.5.1

-   If a newer version of Xcode already exists on the system, rename the
    Xcode 12 and adjust the path accordingly

-   Set defaults to use Python 2 in Xcode 12 LLDB

    -   ```defaults write com.apple.dt.lldb DefaultPythonVersion 2```

-   Use the Xcode 12 LLDB version for kernel debugging

    -   ```/Applications/Xcode12.app/Contents/Developer/usr/bin/lldb```

Additionally, to perform kernel-level debugging for Apple silicon
devices, a core dump server should be configured by creating a
directory, configuring the required permissions and loading the
*kdumpd* Launch Daemon:

-   ```mkdir /var/tmp/PanicDumps```

-   ```chmod 1777 /var/tmp/PanicDumps```

-   ```sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.kdumpd.plist```

The last step in the configuration is to identify the correct ethernet
device (en0, en1, etc.) by running the ***ifconfig*** command.

It is recommended to assign both the host and the target machine’s
ethernet devices with a static IP address for simpler configuration,
even when directly connecting the devices via an ethernet cable,
especially if this is your first time configuring two-machine
kernel-level debugging.

## Target:

### Intel-based

To configure an Intel-based Mac as a target device:

-   Disable System Integrity Protection (SIP) from the [Recovery
    Mode](https://support.apple.com/guide/mac-help/use-macos-recovery-on-an-intel-based-mac-mchl338cf9a8/12.0/mac/12.0)

-   Launch a terminal and execute the ***csrutil disable*** command

-   Execute the ***csrutil authenticated-root disable*** command
    (required when using other kernel variants)

-   Set the [Secure Boot policy](https://support.apple.com/en-us/HT208198) to “Medium
    Security”

-   Reboot the Mac

Finally, the boot arguments should be configured properly. For example:

```sudo nvram boot-args="debug=0x44 kdp_match_name=enX wdt=-1"```

From the *KDK\_ReadMe* file*:*

-   **debug=0x44** – Tells the kernel to wait for a debugger to attach
    to the device when the kernel receives a non-maskable interrupt
    (NMI)

-   **kdp\_match\_name=enX** - Set the value of this key to the Ethernet
    device you will use (en0, en1, etc.)

-   **wdt=-1 (minus one)** – Disables watchdog monitoring

Additional
[boot-args](https://github.com/apple/darwin-xnu/blob/main/osfmk/kern/debug.h)
can be configured if needed.

<script src="https://gist.github.com/antonio-zekic/08608a8de2f4dba61f99bb2156e6b5ba.js"></script>

When using other kernel variants, several steps must be taken:

-   Execute the ***mount*** command in Terminal to identify the device
    mounted at “**/**” and remove the final “**sX**” from the device
    name to get the actual name. For example:

```% mount```

``` /dev/disk1s5s1 on / (apfs, sealed, local, read-only, journaled) ```

``` devfs on /dev (devfs, local, nobrowse) ```

-   Mount a live version of the system using the following commands:

```mkdir /Users/<USERNAME>/livemount```

```sudo mount -o nobrowse -t apfs /dev/disk1s5 /Users/<USERNAME>/livemount``` (note the previously identified device name)

-   Add kernel variant files to the newly mounted disk by copying the
    entire /System directory of the KDK into the /System directory of
    your mounted disk:

```sudo ditto /Library/Developer/KDKs/<KDK Version>/System /Users/<USERNAME>/livemount/System```

-   Rebuild the kernel collections for the variants you added to your
    mounted disk and “bless” them to authorize booting from your
    modified kernels:

```sudo kmutil install –volume-root /Users/<USERNAME>/livemount --update-all```

```sudo bless --mount /Users/<USERNAME>/livemount –bootefi –create-snapshot```

To boot the desired kernel variant, it is necessary to update the boot
arguments by specifying the desired kernel variant with the *kcsuffix*
argument:

```sudo nvram boot-args="debug=0x44 kdp_match_name=enX wdt=-1 kcsuffix=development"```

To verify the configuration, reboot the device and execute the following
command in the Terminal:

``` sysctl kern.osbuildconfig```

***kern.osbuildconfig: development*** (the result will depend on the
variant used)

When configuring kernel debugging using a two-machine setup note the
following:

-   Be careful when typing in the paths

-   Make sure that the mount device and ethernet device names are
    correct

### Apple silicon

*With Apple silicon, the situation is different and the KDK\_ReadMe*
states the following:

-   “Apple silicon doesn’t support active kernel debugging. You may
    inspect the current state of the kernel when it is halted due to a
    panic or NMI. However, you cannot set breakpoints, continue code
    execution, step into code, step over code, or step out of the
    current instruction.”

-   “Apple silicon doesn’t support installing the kernel and kernel
    extension variants from the KDK.”

It is, however, possible to inspect a kernel panic by capturing the core
dumps **over the network** by configuring additional *boot-args*:

-   ```debug=0xc44``` – Creates a core dump when a panic or NMI occurs

-   ```_panicd_ip=<CORE_DUMP_SERVER_IP>``` – Sets the IP
    address of the core dump server

To configure the Apple silicon as a target device:

-   Disable System Integrity Protection (SIP) from [Recovery
    Mode](https://support.apple.com/guide/mac-help/macos-recovery-a-mac-apple-silicon-mchl82829c17/mac)

-   Launch a terminal and execute the ```csrutil disable``` command

-   Reboot the Mac

Lastly, with SIP disabled, configure the boot arguments using the
following command:

```sudo nvram boot-args="debug=0xc44 kdp_match_name=enX wdt=-1 _panicd_ip=<CORE_DUMP_SERVER_IP>"```

The setup used in this blog post is shown in the figure below:

<img src="/images/2022-03-06-macos-two/media/image4.jpeg"
style="width:6.26806in;height:4.70139in"
alt="Laptops and a desktop computer on a table Description automatically generated with low confidence" />

*Figure 3 - Two-machine macOS kernel debugging setup*

# Debugging

macOS supports remote kernel debugging by implementing the Kernel
Debugging Protocol (KDP), a UDP based client-server protocol natively
supported in LLDB.

As previously mentioned, the LLDB used will be the one installed with
Xcode 12, and it can be launched by running the following command from a
Terminal on the host machine:

``` /Applications/Xcode12.app/Contents/Developer/usr/bin/lldb```

Next, kernel-code debugging can be performed in two situations:

-   If the target device panics

-   If you [trigger an
    NMI](https://developer.apple.com/documentation/kernel/generating_a_non-maskable_interrupt)
    on the target device, which is the case described in this blog post

<img src="/images/2022-03-06-macos-two/media/image5.png"
style="width:6.26806in;height:2.78333in"
alt="Graphical user interface, application Description automatically generated" />

*Figure 4 – Triggering Non-Mackable Interrupt*

On Apple silicon, if a *NMI* is triggered, a core dump will be generated
and sent to core dump server (it can take a while to generate a core
dump). The core dump can then be found in the previously set
*/var/tmp/PanicDumps* directory and loaded in *LLDB* once unzipped, as
shown in the following figure:

<img src="/images/2022-03-06-macos-two/media/image6.png"
style="width:6.26806in;height:7.02917in"
alt="Text Description automatically generated" />

*Figure 5 - Apple silicon core dump loaded in lldb*

Similarly, if a *NMI* is triggered on an Intel-based Mac with
*development* kernel variant, a core dump can be generated and sent to
the core dump server by running following commands from *LLDB*:

-   ```(lldb) target create /Library/Developer/KDKs/KDK_12.1_21C52.kdk/System/Library/Kernels/kernel.development```

-   ```(lldb) kdp-remote IP_ADDRESS_OF_THE_TARGET_DEVICE```

<img src="/images/2022-03-06-macos-two/media/image7.png"
style="width:6.26784in;height:7.02917in" />

*Figure 6 - Kernel-level debugging using KDP on Intel-based MAC*

It is recommended to execute scripts as suggested by *LLDB*.

Once you are finished with a debugging session, refer to the the
*KDK\_ReadMe* as a resource for information on how to restore the
original Mac configuration as well as default system security settings.

# Summary

Given a fact that you can’t debug macOS kernel using your own machine,
two machine macOS kernel debugging can look intimidating at first,
especially since it requires two machines and several adapters. However,
once configured properly it is a straight-forward process as described
in this blog post. Best practice is not to use production Macs to
perform kernel debugging but to use a machine for testing purposes.
Also, monitor the *KDK\_ReadMe* for any changes and use it as a
reference guide.

# References

[Kernel Debugging macOS with
SIP](https://www.offensive-security.com/offsec/kernel-debugging-macos-with-sip/)

[macOS Kernel
Debugging](https://knight.sc/debugging/2018/08/15/macos-kernel-debugging.html)

[An overview of macOS kernel
debugging](https://blog.quarkslab.com/an-overview-of-macos-kernel-debugging.html)
