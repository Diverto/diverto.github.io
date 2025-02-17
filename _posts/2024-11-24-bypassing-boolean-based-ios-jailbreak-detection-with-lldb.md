---
layout: post
title: Bypassing boolean-based iOS jailbreak detection with LLDB
date: 2024-11-24
author: antonio
categories: [iOS, LLDB]
category: iOS, LLDB
color: red
tags: [iOS, LLDB]
otherLanguages:
- locale: hr
  path: /hr/blog/2024-11-24-bypassing-boolean-based-ios-jailbreak-detection-with-lldb
- locale: sl
  path: /sl/blog/2024-11-24-bypassing-boolean-based-ios-jailbreak-detection-with-lldb
---

The relevance of jailbreak detection in modern iOS security remains a subject of ongoing discussion, especially since iOS is becoming increasingly challenging to jailbreak, particularly with the latest versions. This raises the question of whether implementing jailbreak detection mechanisms is still relevant. Nonetheless, industry best practices and standards continue to emphasize a defense-in-depth approach, incorporating jailbreak detection as both a preventive security measure and a valuable telemetry source.

Jailbreak detection telemetry provides critical insights into potential security compromises and helps organizations maintain a comprehensive understanding of their security posture in real-time. While open-source solutions offer robust integration options for these features and are always recommended, it's important to acknowledge that determined attackers with sufficient resources can bypass even sophisticated detection mechanisms.

This article is aimed at iOS security researchers, penetration testers, and developers interested in understanding the internals of jailbreak detection mechanisms. While numerous guides exist on bypassing iOS jailbreak detection, particularly using Frida scripts, we'll explore an alternative approach using LLDB to bypass simple boolean-based jailbreak detection mechanisms.

Throughout this article, we will:
* Explore essential LLDB debugging concepts and ARM architecture basics
* Set up a remote debugging environment for iOS devices
* Analyze jailbreak detection mechanisms using LLDB
* Develop both manual and automated bypasses using LLDB's features
* Learn how to leverage LLDB's Python API for automation

While demonstrating a jailbreak detection bypass, our primary focus is to deliver practical insights into LLDB debugging. We'll explore breakpoint commands and callbacks while providing a targeted overview of both LLDB and ARM architecture fundamentals necessary for understanding the techniques presented.

### The LLDB Debugger

> LLDB is a powerful, modern debugging platform built on the LLVM Project's foundation. By leveraging established components like the Clang expression parser and LLVM disassembler, LLDB delivers exceptional debugging performance and reliability.
>
> As the default debugging tool in Xcode for macOS development, LLDB provides comprehensive support for C, Objective-C, and C++ across both desktop applications and iOS environments, including physical devices and simulators.
>
> What sets LLDB apart is its flexible scripting capabilities. Developers can automate debugging sessions through Python scripts in two ways: by running non-interactive debug sessions from a Unix Python environment, or by executing Python scripts within LLDB itself. This scripting functionality enables advanced tasks such as program data inspection, container traversal, and sophisticated breakpoint management with conditional execution control.
>
> — From the [LLDB official website](https://lldb.llvm.org/)

#### Common LLDB Commands

##### Process Control
- **Running and Stopping**
  ```lldb
  run (r)              # Start program execution
  continue (c)         # Continue program execution
  step (s)             # Step into
  next (n)             # Step over
  finish              # Step out of the current function
  exit/quit (q)       # Exit LLDB
  ```

##### Breakpoints
- **Setting Breakpoints**
  ```lldb
  breakpoint set -n <name>           # Break on function name
  breakpoint set -f <file> -l <line> # Break on file and line
  breakpoint set -a <address>        # Break on memory address
  br s -n <name>                     # Short form
  ```

- **Breakpoint Management**
  ```lldb
  breakpoint list                    # List breakpoints
  breakpoint enable <id>             # Enable breakpoint
  breakpoint disable <id>            # Disable breakpoint
  breakpoint delete <id>             # Delete breakpoint
  breakpoint command add <id>        # Add commands to breakpoint
  ```

##### Register and Memory Operations
- **Register Commands**
  ```lldb
  register read                      # Read all registers
  register read <reg>                # Read specific register
  register write <reg> <value>       # Write to register
  ```

- **Memory Commands**
  ```lldb
  memory read <addr>                 # Read memory
  x/<size><format> <addr>           # Examine memory
  x/s <addr>                        # Read as string
  x/i <addr>                        # Read as instructions
  ```

##### Threading and Stack
- **Thread Commands**
  ```lldb
  thread list                        # List all threads
  thread select <id>                 # Switch to thread
  thread backtrace (bt)             # Show thread backtrace
  ```

- **Frame Commands**
  ```lldb
  frame select <id>                  # Select stack frame
  frame variable                     # Show frame variables
  frame info                        # Show frame information
  ```

##### iOS Specific
- **Platform and Process**
  ```lldb
  platform select remote-ios         # Select iOS platform
  process connect connect://<host>:<port>  # Connect to debug server
  ```

##### Data Inspection
- **Variable Inspection**
  ```lldb
  p <variable>                       # Print variable
  po <object>                        # Print object description
  expression <expr>                  # Evaluate expression
  ```

##### Script Integration
- **Python Integration**
  ```lldb
  script print(lldb.debugger)        # Access LLDB from Python
  command script import <file>       # Import Python script
  command script add <name> <file>   # Add script command
  ```

##### Useful Tips
1. **Command Aliases**
   - Most commands have short aliases (r, c, n, s, etc.)
   - You can create custom aliases

2. **Regular Expression Breakpoints**
   ```lldb
   breakpoint set -r <regex>         # Break on pattern match
   ```

### ARM Architecture

Modern iPhones use ARM-based processors with the ARM64 (AArch64) architecture. Starting from iPhone 5S, Apple moved to 64-bit ARM processors, with the latest devices using custom Apple Silicon designs based on the ARM architecture.

#### Register Overview

ARM64 provides 31 general-purpose registers (X0-X30) that are each 64 bits wide. These can also be accessed as 32-bit registers (W0-W30).

##### Key Registers

- **X0-X7**: Parameter and return value registers
  - X0: First parameter and function return value
  - Used for passing boolean results and small return values
- **X8-X15**: Temporary registers
  - Used for local variables and intermediate calculations
- **X16-X30**: Special purpose and callee-saved registers
- **X29 (FP)**: Frame pointer
- **X30 (LR)**: Link register, stores return address
- **SP**: Stack pointer (not directly accessible as X31)
- **PC**: Program counter

#### Function Calls and Register Usage

##### Calling Convention

In ARM64, function parameters are passed through registers:
- First eight arguments use X0-X7
- X0 is also used for return value
- For boolean functions:
  - X0 = 1 represents true
  - X0 = 0 represents false

##### Link Register (LR)

The Link Register (X30/LR) serves several critical functions:
- Stores the return address when a function is called
- Enables function return to the correct location
- Key register for debugging and stack trace analysis

With our understanding of LLDB's capabilities and ARM architecture fundamentals, let's proceed with setting up our debugging environment.

### Setup

The setup described in this blog post includes:

- Intel-based or Apple Silicon host device
- iPhone 8+ running iOS 16.7.10 jailbroken using [palera1n](https://palera.in/) jailbreak.

On the host device, we will use **iproxy** to connect via SSH to a jailbroken iPhone via USB.
The tool can be installed on macOS using [Homebrew](https://brew.sh/) with:

```zsh
brew install libusbmuxd
```

There are many tutorials available online that can guide you trough setting up the **debugserver** on the iOS device, however, the simplest one is to install it using *Sileo* from [Procursus repository](https://apt.procurs.us/).

Having established our testing environment, we'll now configure the necessary connections between our host device and the target iOS device.

### Configuration

On the host device it is necessary to open up four terminal windows:

#### Terminal #1

In the first terminal window we want to setup iproxy to forward the SSH communication via USB by typing:

```zsh
iproxy 2222 22
```

#### Terminal #2

The second terminal window is used to setup iproxy to forward the debugserver for remote debugging communication via USB by typing:

```zsh
iproxy 1234 5678
```

#### Terminal #3

We will use the third terminal window to connect to the iPhone via SSH and attach the **debugserver** to the application we want to debug using the command:

```zsh
debugserver *:1234 --waitfor ApplicationName
```

```zsh
iPhone102:~ root# debugserver localhost:5678 --waitfor ApplicationName
debugserver-@(#)PROGRAM:LLDB  PROJECT:lldb-16.0.0
 for arm64.
Waiting to attach to process ApplicationName...
```

We can now execute on the application on the device and the debugging session will start:

```zsh
Listening to port 5678 for a connection from localhost...
```

The steps above have to be repeated on each application execution.

#### Terminal #4

Fourth terminal window will be used to connect to a remote debugging session using following command:

```zsh
lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234"
```

With our debugging environment configured, we can begin analyzing the application's jailbreak detection mechanisms.

### Analysis

Let's start by connecting to a remote LLDB debugging session:

```zsh
user@macOS ~ % lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234"
```
```lldb
(lldb) platform select remote-ios
  Platform: remote-ios
 Connected: no
<redacted>
 SDK Roots: [ 1] "/Users/user/Library/Developer/Xcode/iOS DeviceSupport/iPhone10,5 16.7.10 (20H350)"
(lldb) process connect connect://localhost:1234
Process 46666 stopped
* thread #1, stop reason = signal SIGSTOP
    frame #0: 0x0000000101c86190 dyld`strcmp
dyld`strcmp:
->  0x101c86190 <+0>:  tst    x0, #0xf
    0x101c86194 <+4>:  b.eq   0x101c861b4    ; <+36>
    0x101c86198 <+8>:  ldrb   w4, [x0], #0x1
    0x101c8619c <+12>: ldrb   w5, [x1], #0x1
Target 0: (ApplicationName) stopped.
(lldb) continue 
Process 46666 resuming
Process 46666 exited with status = 45 (0x0000002d) 
(lldb)  
```

An application terminating with exit status `45 (0x0000002d)` might indicate the presence of anti-debugging mechanisms.

iOS implements a robust security model based on application sandboxing, which enforces strict access controls on filesystem operations and inter-process communications. Detection mechanisms exploit these restrictions and employ various techniques to identify system modifications.

#### Common Detection Methods

The following list presents some examples of detection approaches, though it's not exhaustive and implementation details may vary across different solutions:

##### File-Based Detection
- Access attempts to privileged paths
- Package management paths (e.g., `/etc/apt`, `/etc/dpkg`)
- Alternative shell binaries (e.g., `/bin/bash`, `/bin/sh`) 
- Third-party package manager paths (e.g., Cydia, Sileo, Zebra)

##### Runtime Environment Checks
- System modification indicators
- Process forking attempts
- Dynamic linker behavior analysis
- Suspicious dylib presence

##### URL Scheme Detection
- Package manager URL schemes (e.g., Cydia, Sileo)
- Custom URL scheme handling checks
- Application installation source verification

##### Permission and Privilege Checks
- Write attempts outside application container
- Privilege elevation indicators
- Sandbox violation attempts
- Process information queries

#### Dynamic Analysis

Although applications generally rely on high-level APIs for file operations, intercepting low-level syscalls like `stat` reveals the actual filesystem queries made during jailbreak detection. The `stat` syscall queries the filesystem for a file's metadata (permissions, size, timestamps) and takes a file path as its first argument.

In the following example, we use several LLDB commands to monitor the application's file checks:

- Set a breakpoint on the `stat` syscall to pause execution whenever it is called:
  ```lldb
  (lldb) b stat  # This halts the program when the `stat` syscall is called
  ```

- Add specific commands to the breakpoint to trigger additional actions:
  ```lldb
  (lldb) breakpoint command add 1  # Add commands to the breakpoint
  ```

- Examine the string at the memory address held by the `x0` register to inspect the path being passed:
  ```lldb
  (lldb) x/s $x0  # Display the string at the address in `x0`, showing the file path
  ```

- Resume program execution until the next breakpoint or program termination:
  ```lldb
  (lldb) c  # Continue running the program
  ```

With the breakpoints set and commands added, we can now step through the debugging process to observe how these instructions interact with the program flow and inspect file path checks in real-time.

```zsh
user@macOS ~ % lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234"
```
```lldb
(lldb) platform select remote-ios
  Platform: remote-ios
 Connected: no
 <redacted>
 SDK Roots: [ 1] "/Users/user/Library/Developer/Xcode/iOS DeviceSupport/iPhone10,5 16.7.10 (20H350)"
(lldb) process connect connect://localhost:1234
Process 47351 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = signal SIGSTOP
    frame #0: 0x00000002336c28ac libmacho.dylib`getsectiondata + 116
libmacho.dylib`getsectiondata:
->  0x2336c28ac <+116>: cmp    w8, #0x19
    0x2336c28b0 <+120>: b.ne   0x2336c2998    ; <+352>
    0x2336c28b4 <+124>: add    x24, x28, #0x8
    0x2336c28b8 <+128>: mov    x0, x24
Target 0: (ApplicationName) stopped.
(lldb) b stat
Breakpoint 1: 2 locations.
(lldb) breakpoint command add 1
Enter your debugger command(s).  Type 'DONE' to end.
> x/s $x0 
> c 
> DONE
(lldb) c
Process 47351 resuming
(lldb)  x/s $x0
0x1c023f4d5: "/"
(lldb)  c
Process 47351 resuming
Command #2 'c' continued the target.
(lldb)  x/s $x0
0xc3c008c00: "/private/var/containers/Bundle/Application/4DBE1BF1-6B85-4F9B-95E1-64983FDEB0F9/ApplicationName.app/ApplicationName"
(lldb)  c
<redacted>
Process 47351 resuming
Command #2 'c' continued the target.
(lldb)  x/s $x0
0x16f7baed6: "/private"
(lldb)  c
Process 47351 resuming
Command #2 'c' continued the target.
(lldb)  x/s $x0
0x16f7bc7c6: "/usr/sbin/frida-server"
(lldb)  c
Process 47351 resuming
Command #2 'c' continued the target.
Process 47351 exited with status = 45 (0x0000002d)
```

Analysis of the monitored paths revealed a check for `"/usr/sbin/frida-server"` immediately preceding process termination. To understand the execution flow that led to this check, we repeated the analysis with the addition of the `bt` (backtrace) command. This command reveals the full call stack, providing visibility into the sequence of function calls leading to our breakpoint.

```zsh
user@macOS ~ % lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234"
```
```lldb
(lldb) platform select remote-ios
  Platform: remote-ios
 Connected: no
 <redacted>
 SDK Roots: [ 1] "/Users/user/Library/Developer/Xcode/iOS DeviceSupport/iPhone10,5 16.7.10 (20H350)"
(lldb) process connect connect://localhost:1234
Process 47363 stopped
* thread #1, stop reason = signal SIGSTOP
    frame #0: 0x000000010599c5b0 dyld`stat64 + 8
dyld`stat64:
->  0x10599c5b0 <+8>:  b.lo   0x10599c5cc    ; <+36>
    0x10599c5b4 <+12>: stp    x29, x30, [sp, #-0x10]!
    0x10599c5b8 <+16>: mov    x29, sp
    0x10599c5bc <+20>: bl     0x10599fea0    ; cerror_nocancel
Target 0: (ApplicationName) stopped.
(lldb) b stat
Breakpoint 1: no locations (pending).
WARNING:  Unable to resolve breakpoint to any actual locations.
(lldb) breakpoint command add 1
Enter your debugger command(s).  Type 'DONE' to end.
> x/s $x0 
> bt 
> c 
> DONE
(lldb) c
Process 47363 resuming
2 locations added to breakpoint 1
(lldb)  x/s $x0
0x1c023f4d5: "/"
(lldb)  bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.2
  * frame #0: 0x00000001f4b956c4 libsystem_kernel.dylib`stat
    frame #1: 0x00000001c01d96d0 libsystem_c.dylib`realpath$DARWIN_EXTSN + 428
    frame #2: 0x000000010178d57c systemhook.dylib`___lldb_unnamed_symbol117 + 224
    frame #3: 0x00000001019b442c dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 152
    frame #4: 0x00000001019e36ec dyld`invocation function for block in dyld3::MachOAnalyzer::forEachInitializer(Diagnostics&, dyld3::MachOAnalyzer::VMAddrConverter const&, void (unsigned int) block_pointer, void const*) const + 164
    frame #5: 0x00000001019912d0 dyld`invocation function for block in dyld3::MachOFile::forEachSection(void (dyld3::MachOFile::SectionInfo const&, bool, bool&) block_pointer) const + 520
    frame #6: 0x0000000101990788 dyld`dyld3::MachOFile::forEachLoadCommand(Diagnostics&, void (load_command const*, bool&) block_pointer) const + 280
    frame #7: 0x000000010198fd78 dyld`dyld3::MachOFile::forEachSection(void (dyld3::MachOFile::SectionInfo const&, bool, bool&) block_pointer) const + 164
    frame #8: 0x00000001019dd160 dyld`dyld3::MachOFile::forEachInitializerPointerSection(Diagnostics&, void (unsigned int, unsigned int, bool&) block_pointer) const + 132
    frame #9: 0x000000010199ad94 dyld`dyld3::MachOAnalyzer::forEachInitializer(Diagnostics&, dyld3::MachOAnalyzer::VMAddrConverter const&, void (unsigned int) block_pointer, void const*) const + 324
    frame #10: 0x000000010199797c dyld`dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const + 392
    frame #11: 0x0000000101994444 dyld`dyld4::Loader::runInitializersBottomUp(dyld4::RuntimeState&, dyld3::Array<dyld4::Loader const*>&) const + 216
    frame #12: 0x00000001019b44b4 dyld`dyld4::Loader::runInitializersBottomUpPlusUpwardLinks(dyld4::RuntimeState&) const::$_1::operator()() const + 108
    frame #13: 0x00000001019994d4 dyld`dyld4::Loader::runInitializersBottomUpPlusUpwardLinks(dyld4::RuntimeState&) const + 272
    frame #14: 0x00000001019ca9a0 dyld`dyld4::APIs::runAllInitializersForMain() + 272
    frame #15: 0x00000001019a21cc dyld`dyld4::prepare(dyld4::APIs&, dyld3::MachOAnalyzer const*) + 2872
    frame #16: 0x00000001019a02e0 dyld`start + 1760
(lldb)  c
Process 47958 resuming
<redacted>
Command #3 'c' continued the target.
(lldb)  x/s $x0
0x16f14aee6: "/private"
(lldb)  bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.2
  * frame #0: 0x00000001f4b956c4 libsystem_kernel.dylib`stat
    frame #1: 0x00000001b3723e9c Foundation`-[NSFileManager fileExistsAtPath:isDirectory:] + 92
    frame #2: 0x00000001b3722d48 Foundation`-[NSURL(NSURL) initFileURLWithPath:] + 156
    frame #3: 0x00000001b3722ca0 Foundation`+[NSURL(NSURL) fileURLWithPath:] + 28
    frame #4: 0x00000001b3b625c4 Foundation`-[NSFileManager componentsToDisplayForPath:] + 76
    frame #5: 0x00000001b3787f9c Foundation`pathComponentFromPath + 488
    frame #6: 0x00000001b378ae18 Foundation`pathComponentFromURL + 416
    frame #7: 0x00000001b3712ec8 Foundation`-[NSError(NSErrorPrivate) _formatCocoaErrorString:parameters:applicableFormatters:count:] + 216
    frame #8: 0x00000001b37129fc Foundation`-[NSError(NSErrorPrivate) _cocoaErrorString:fromBundle:tableName:] + 540
    frame #9: 0x00000001b375ccdc Foundation`-[NSError(NSErrorPrivate) _cocoaErrorString:] + 68
    frame #10: 0x00000001b375cc78 Foundation`-[NSError _cocoaErrorStringWithKind:variant:] + 140
    frame #11: 0x00000001b375cbb4 Foundation`-[NSError _cocoaErrorStringWithKind:] + 320
    frame #12: 0x00000001b375ca40 Foundation`-[NSError _retainedUserInfoCallBackForKey:] + 144
    frame #13: 0x00000001b945df5c CoreFoundation`____CFErrorSetCallBackForDomainNoLock_block_invoke + 28
    frame #14: 0x00000001b94457dc CoreFoundation`_CFErrorCopyUserInfoKeyFromCallBack + 56
    frame #15: 0x00000001b3754ac8 Foundation`-[NSError localizedFailureReason] + 52
    frame #16: 0x00000001b3753900 Foundation`-[NSFileManager _URLForReplacingItemAtURL:error:] + 428
    frame #17: 0x00000001b37534ec Foundation`_NSCreateTemporaryFile_Protected + 164
    frame #18: 0x00000001b3761318 Foundation`_NSWriteDataToFileWithExtendedAttributes + 432
    frame #19: 0x00000001b37b911c Foundation`writeStringToURLOrPath + 184
    frame #20: 0x00000001b3a2feec Foundation`Swift.StringProtocol.write<τ_0_0 where τ_1_0: Swift.StringProtocol>(toFile: τ_1_0, atomically: Swift.Bool, encoding: Swift.String.Encoding) throws -> () + 172
    frame #21: 0x0000000102b2c9a0 IOSSecuritySuite`function signature specialization <Arg[0] = Dead> of static IOSSecuritySuite.JailbreakChecker.checkRestrictedDirectoriesWriteable() -> (passed: Swift.Bool, failMessage: Swift.String) + 832
    frame #22: 0x0000000102b2d3e0 IOSSecuritySuite`function signature specialization <Arg[0] = Dead> of static IOSSecuritySuite.JailbreakChecker.performChecks() -> IOSSecuritySuite.JailbreakChecker.JailbreakStatus + 788
    frame #23: 0x0000000102b29d4c IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool + 16
    <redacted>
    frame #63: 0x00000001019a0344 dyld`start + 1860
(lldb)  c
Process 47958 resuming
<redacted>
Command #3 'c' continued the target.
(lldb)  x/s $x0
0x16f14c7d6: "/usr/sbin/frida-server"
(lldb)  bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.2
  * frame #0: 0x00000001f4b956c4 libsystem_kernel.dylib`stat
    frame #1: 0x00000001b3723f48 Foundation`-[NSFileManager fileExistsAtPath:] + 88
    frame #2: 0x0000000102b2e668 IOSSecuritySuite`function signature specialization <Arg[0] = Dead> of static IOSSecuritySuite.ReverseEngineeringToolsChecker.performChecks() -> IOSSecuritySuite.ReverseEngineeringToolsChecker.ReverseEngineeringToolsStatus + 536
    frame #3: 0x0000000102b29f00 IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIReverseEngineered() -> Swift.Bool + 16
    <redacted>
    frame #43: 0x00000001019a0344 dyld`start + 1860
(lldb)  c
Process 47958 resuming
Command #3 'c' continued the target.
Process 47958 exited with status = 45 (0x0000002d) 
```

Analysis of the call stack revealed that the application relies on the IOSSecuritySuite framework for its detection routines, specifically using two functions:

* ```IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool + 16```
* ```IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIReverseEngineered() -> Swift.Bool + 16```

Now that we've identified the detection routines, let's explore how to bypass them manually using LLDB's debugging capabilities.

### Manual Bypass

With the insights gained from our analysis, we can implement a step-by-step approach to bypass the jailbreak detection by intercepting and altering the return value of the detection routines. The following LLDB commands demonstrate the process, with explanations of each step:

- Set a breakpoint on the jailbreak detection function:
  ```lldb
  (lldb) b IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken()  # This halts the program when the function is called
  ```

- Inspect the Link Register (LR) to identify where the function will return:
  ```lldb
  (lldb) register read lr   # LR holds the return address; we need it for setting a follow-up breakpoint
  ```

- Set a one-shot breakpoint at the return address to intercept the function return:
  ```lldb
  (lldb) br s -a $lr        # This breakpoint triggers only once at the function's return
  ```

- Read the `x0` register to check the current return value (1 = jailbroken, 0 = not jailbroken):
  ```lldb
  (lldb) register read x0   # Check the current state of the return value
  ```

- Modify the return value to indicate a non-jailbroken state:
  ```lldb
  (lldb) register write x0 0  # Force `x0` to return '0' (false), bypassing the jailbreak check
  ```

- Verify the change by reading the `x0` register again (optional but helpful for confirmation):
  ```lldb
  (lldb) register read x0   # Ensure `x0` is now '0'
  ```

- Resume program execution:
  ```lldb
  (lldb) c                  # Continue running the program with the modified return value
  ```

This debugging workflow enables us to intercept and modify the detection routine's behavior, circumventing the jailbreak check.

```zsh
user@macOS ~ % lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234"
```
```lldb
(lldb) platform select remote-ios
  Platform: remote-ios
 Connected: no
 <redacted>
 SDK Roots: [ 1] "/Users/user/Library/Developer/Xcode/iOS DeviceSupport/iPhone10,5 16.7.10 (20H350)"
(lldb) process connect connect://localhost:1234
Process 47365 stopped
* thread #1, stop reason = signal SIGSTOP
    frame #0: 0x00000001038085b0 dyld`stat64 + 8
dyld`stat64:
->  0x1038085b0 <+8>:  b.lo   0x1038085cc    ; <+36>
    0x1038085b4 <+12>: stp    x29, x30, [sp, #-0x10]!
    0x1038085b8 <+16>: mov    x29, sp
    0x1038085bc <+20>: bl     0x10380bea0    ; cerror_nocancel
Target 0: (ApplicationName) stopped.
(lldb) b IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool
Breakpoint 1: no locations (pending).
WARNING:  Unable to resolve breakpoint to any actual locations.
(lldb) c
Process 47365 resuming
1 location added to breakpoint 1
Process 47365 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000104959d3c IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool
IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool:
->  0x104959d3c <+0>:  stp    x20, x19, [sp, #-0x20]!
    0x104959d40 <+4>:  stp    x29, x30, [sp, #0x10]
    0x104959d44 <+8>:  add    x29, sp, #0x10
    0x104959d48 <+12>: bl     0x10495d0cc    ; function signature specialization <Arg[0] = Dead> of static IOSSecuritySuite.JailbreakChecker.performChecks() -> IOSSecuritySuite.JailbreakChecker.JailbreakStatus
Target 0: (ApplicationName) stopped.
(lldb) register read lr
      lr = 0x0000000102b5eff8  ApplicationName`___lldb_unnamed_symbol9009 + 52
(lldb) br s -a $lr
Breakpoint 2: where = ApplicationName`___lldb_unnamed_symbol9009 + 52, address = 0x0000000102b5eff8
(lldb) c
Process 47365 resuming
Process 47365 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 2.1
    frame #0: 0x0000000102b5eff8 ApplicationName`___lldb_unnamed_symbol9009 + 52
ApplicationName`___lldb_unnamed_symbol9009:
->  0x102b5eff8 <+52>: and    w8, w0, #0x1
    0x102b5effc <+56>: strb   w8, [x19, #0x30]
    0x102b5f000 <+60>: mov    x0, #0x0 ; =0 
    0x102b5f004 <+64>: bl     0x103150bb8    ; symbol stub for: type metadata accessor for IOSSecuritySuite.IOSSecuritySuite
Target 0: (ApplicationName) stopped.
(lldb) register read x0
      x0 = 0x0000000000000001
(lldb) register write x0 0
(lldb) register read x0
      x0 = 0x0000000000000000
(lldb) c
Process 47365 resuming
Process 47365 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000104959d3c IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool
IOSSecuritySuite`static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool:
->  0x104959d3c <+0>:  stp    x20, x19, [sp, #-0x20]!
    0x104959d40 <+4>:  stp    x29, x30, [sp, #0x10]
    0x104959d44 <+8>:  add    x29, sp, #0x10
    0x104959d48 <+12>: bl     0x10495d0cc    ; function signature specialization <Arg[0] = Dead> of static IOSSecuritySuite.JailbreakChecker.performChecks() -> IOSSecuritySuite.JailbreakChecker.JailbreakStatus
Target 0: (ApplicationName) stopped.
(lldb) register read lr
      lr = 0x0000000102b5fba0  ApplicationName`___lldb_unnamed_symbol9013 + 44
(lldb) br s -a $lr
Breakpoint 3: where = ApplicationName`___lldb_unnamed_symbol9013 + 44, address = 0x0000000102b5fba0
(lldb) c
Process 47365 resuming
Process 47365 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 3.1
    frame #0: 0x0000000102b5fba0 ApplicationName`___lldb_unnamed_symbol9013 + 44
ApplicationName`___lldb_unnamed_symbol9013:
->  0x102b5fba0 <+44>: tst    w0, #0x1
    0x102b5fba4 <+48>: mov    x8, #-0x1a00000000000000 ; =-1873497444986126336 
    0x102b5fba8 <+52>: mov    x9, #-0x1900000000000000 ; =-1801439850948198400 
    0x102b5fbac <+56>: csel   x20, x9, x8, ne
Target 0: (ApplicationName) stopped.
(lldb) register read x0
      x0 = 0x0000000000000001
(lldb) register write x0 0
(lldb) register read x0
      x0 = 0x0000000000000000
(lldb) c
Process 47365 resuming
(lldb)  
```

Interestingly, modifying only the return value of `amIJailbroken()` function was sufficient to prevent process termination, suggesting that the `amIReverseEngineered` function check was conditional upon the jailbreak detection result.

While the manual process demonstrates the core concepts of bypassing detection, automation can streamline and repeat the process efficiently. The following section explores how we can harness LLDB's Python API to implement an automated bypass approach, making the workflow reusable and less error-prone.

### Automated Bypass

Building upon our manual bypass approach, we can automate the entire process using LLDB's Python API. This implementation showcases LLDB's scripting capabilities while providing an efficient bypass solution.

The Python script implements the same logic we used in our manual bypass: intercepting detection routines and modifying their return values. However, it adds automation through breakpoint callbacks, making the bypass process more efficient and reusable.

The script consists of two main functions:

* `__lldb_init_module`: Handles the initial setup by creating breakpoints on both detection routines and assigning them callbacks:
```python
target = debugger.GetSelectedTarget()
# Set breakpoint on jailbreak detection
bp1 = target.BreakpointCreateByName("static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken()")
bp1.SetScriptCallbackFunction(basic_callback.__module__ + '.basic_callback')
# Set breakpoint on reverse engineering detection
bp2 = target.BreakpointCreateByName("static IOSSecuritySuite.IOSSecuritySuite.amIReverseEngineered()")
bp2.SetScriptCallbackFunction(basic_callback.__module__ + '.basic_callback')
```
This function initializes our debugging session by setting breakpoints on both security functions we identified during analysis. Each breakpoint is configured to trigger our callback function when hit.

* `basic_callback`: Automates the bypass process by handling breakpoint events. First, it gathers information about the current execution context:
```python
thread = frame.GetThread()
process = thread.GetProcess()
target = process.GetTarget()
debugger = target.GetDebugger()
```

Then, it reads the Link Register to find where the function will return:
```python
for reg in frame.registers[0]:
    if reg.name == "lr":
        return_addr = reg.unsigned
        ret_bp = target.BreakpointCreateByAddress(return_addr)
```

Finally, it sets up commands to modify the return value:
```python
ret_bp.SetOneShot(True)  # Breakpoint will be removed after being hit
commands = lldb.SBStringList()
commands.AppendString("register read x0")   # Read current value
commands.AppendString("register write x0 0") # Modify return value
commands.AppendString("register read x0")   # Verify modification
commands.AppendString("c")                  # Continue execution
ret_bp.SetCommandLineCommands(commands)
```

The script can be executed with a single command:
```python
lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234" -o "command script import /Users/user/bypass_JailbreakDetection.py" -o "continue"
```

#### Complete Python Script

```python
# lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234" -o "command script import /Users/user/bypass_JailbreakDetection.py" -o "continue"
#!/usr/bin/env python3
import lldb

def __lldb_init_module(debugger, dict):
    try:
        target = debugger.GetSelectedTarget()
        print("[*] Setting up breakpoints...")
        bp1 = target.BreakpointCreateByName("static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool", "IOSSecuritySuite")
        if bp1:
            print("[*] Created breakpoint 1")
            bp1.SetScriptCallbackFunction(basic_callback.__module__ + '.basic_callback')
            print("[*] Set callback for breakpoint 1")
        bp2 = target.BreakpointCreateByName("static IOSSecuritySuite.IOSSecuritySuite.amIReverseEngineered() -> Swift.Bool", "IOSSecuritySuite")
        if bp2:
            print("[*] Created breakpoint 2")
            bp2.SetScriptCallbackFunction(basic_callback.__module__ + '.basic_callback')
            print("[*] Set callback for breakpoint 2")
    except Exception as e:
        print(f"[-] Error in init: {str(e)}")

def basic_callback(frame, bp_loc, dict):
    try:
        thread = frame.GetThread()
        process = thread.GetProcess()
        target = process.GetTarget()
        debugger = target.GetDebugger()
        interpreter = debugger.GetCommandInterpreter()
        result = lldb.SBCommandReturnObject()
        print(f"Function: {frame.GetFunctionName()}")
        print(f"Address: 0x{frame.GetPC():x}")
        interpreter.HandleCommand("register read lr", result)
        if result.Succeeded():
            print("\nRegister state:")
            print(result.GetOutput())
        for reg in frame.registers[0]:
            if reg.name == "lr":
                return_addr = reg.unsigned
                print(f"[+] Return address from lr: 0x{return_addr:x}")
                ret_bp = target.BreakpointCreateByAddress(return_addr)
                if ret_bp:
                    ret_bp.SetOneShot(True)
                    commands = lldb.SBStringList()
                    commands.AppendString("register read x0")
                    commands.AppendString("register write x0 0")
                    commands.AppendString("register read x0")
                    commands.AppendString("c")
                    ret_bp.SetCommandLineCommands(commands)
                    print(f"[+] Set return breakpoint at 0x{return_addr:x}")
                break
        process.Continue()

    except Exception as e:
        print(f"[-] Error in callback: {str(e)}")
        if thread:
            process = thread.GetProcess()
            if process:
                process.Continue()
    return False
```

While numerous implementation strategies exist for LLDB automation, this script exemplifies a systematic approach that directly translates our manual debugging methodology into programmatic form while highlighting essential callback mechanisms.

#### Script Output

```zsh
user@macOS ~ % lldb -o "platform select remote-ios" -o "process connect connect://localhost:1234" -o "command script import /Users/user/bypass_JailbreakDetection.py" -o "continue"
```
```lldb
(lldb) process connect connect://localhost:1234
Process 47960 stopped
* thread #1, stop reason = signal SIGSTOP
    frame #0: 0x000000010110ba5c dyld`__mmap + 8
dyld`__mmap:
->  0x10110ba5c <+8>:  b.lo   0x10110ba78    ; <+36>
    0x10110ba60 <+12>: stp    x29, x30, [sp, #-0x10]!
    0x10110ba64 <+16>: mov    x29, sp
    0x10110ba68 <+20>: bl     0x101103ea0    ; cerror_nocancel
Target 0: (ApplicationName) stopped.
(lldb) command script import /Users/user/bypass_JailbreakDetection.py
[*] Setting up breakpoints...
[*] Created breakpoint 1
[*] Set callback for breakpoint 1
[*] Created breakpoint 2
[*] Set callback for breakpoint 2
(lldb) continue
1 location added to breakpoint 1
1 location added to breakpoint 2
Function: static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool
Address: 0x10222dd3c

Register state:
      lr = 0x000000010042eff8  ApplicationName`___lldb_unnamed_symbol9009 + 52

[+] Return address from lr: 0x10042eff8
[+] Set return breakpoint at 0x10042eff8
(lldb)  register read x0
      x0 = 0x0000000000000001
(lldb)  register write x0 0
(lldb)  register read x0
      x0 = 0x0000000000000000
(lldb)  c
Process 47960 resuming
Command #4 'c' continued the target.
Function: static IOSSecuritySuite.IOSSecuritySuite.amIReverseEngineered() -> Swift.Bool
Address: 0x10222def0

Register state:
      lr = 0x000000010042f068  ApplicationName`___lldb_unnamed_symbol9009 + 164

[+] Return address from lr: 0x10042f068
[+] Set return breakpoint at 0x10042f068
(lldb)  register read x0
      x0 = 0x0000000000000001
(lldb)  register write x0 0
(lldb)  register read x0
      x0 = 0x0000000000000000
(lldb)  c
Process 47960 resuming
Command #4 'c' continued the target.
Function: static IOSSecuritySuite.IOSSecuritySuite.amIJailbroken() -> Swift.Bool
Address: 0x10222dd3c

Register state:
      lr = 0x000000010042fba0  ApplicationName`___lldb_unnamed_symbol9013 + 44

[+] Return address from lr: 0x10042fba0
[+] Set return breakpoint at 0x10042fba0
(lldb)  register read x0
      x0 = 0x0000000000000001
(lldb)  register write x0 0
(lldb)  register read x0
      x0 = 0x0000000000000000
(lldb)  c
Process 47960 resuming
Command #4 'c' continued the target.
```

### Conclusion

This article demonstrated how LLDB's debugging capabilities, specifically its breakpoint manipulation features, can be used to bypass iOS jailbreak detection. While the example focused on jailbreak detection, these techniques help understand LLDB's breakpoint commands and callback functionality.

The manual process covered:
* Setting breakpoints
* Register inspection and modification
* Function return mechanisms

The automated solution, implemented through LLDB's Python API, showed how breakpoint callbacks can be used to:
* Automate debugging workflows
* Implement debugging logic
* Handle execution scenarios

This approach provides both a practical solution for security testing and examples of LLDB's debugging capabilities. Understanding these debugging techniques, particularly breakpoint commands and callbacks, is useful for iOS application security assessment and debugging tasks.
