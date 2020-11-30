---
layout: post
title: Extracting credentials from IoT devices via UART
author: kost
categories: [iot]
tags: [iot, wireless, password, credentials, uart, broadlink]
---

Buying IoT devices which communicates wirelessly means it have to store credentials to network it is connecting to. It could be Zigbee network key, wireless WPA key or any other wireless protocol .As an example, we have extracted wireless credentials stored in Broadlink RM Mini which can be easily bought from many gadget web shops on the Internet. Such credentials were extracted simply via standard and simple UART access to the device.

In this specific case it is interesting as there are no any user authentication needed and that credentials are stored and displayed in plain-text. That means that attackers do not need to perform any extra step in obtaining credentials from the device once they have physical UART access.

Methods described in this article can be used in different scenarios. Main requirement is that you have somehow physical access to the device and UART pins where device can be managed and/or display its configuration.

## Broadlink RM Mini

IoT device which we taken as an example is simple WiFi-to-IR gateway from Broadlink. Model is RM Mini and can be easily bought from many gadget web shops on the Internet including Aliexpress.

| ![Broadlink RM Mini]({{ site.baseurl }}/images/iot-devices-uart/broadlink-rm-mini.jpg) |
|:---:|
| *Broadlink RM Mini* |

## Opening device

Device can be easily opened removing the top cover. Top of the device reveals IR leds strategically placed on top of the PCB.

| ![Broadlink RM Mini opened]({{ site.baseurl }}/images/iot-devices-uart/broadlink-rm-mini-opened.jpg) | 
|:---:| 
| *Broadlink RM Mini opened* |

Removing the plastic case completely, there are two PCBs interconnected where interesting one is without IR leds since it have microcontroller on board and usually routed UART.


| ![Broadlink RM Mini PCB]({{ site.baseurl }}/images/iot-devices-uart/broadlink-rm-mini-pcb.jpg) | 
|:---:| 
| *Broadlink RM Mini 3 PCB* |

## Finding UART

UART is usually found as 3 or 4 set of pins on the board, so it is quite easy to find it as it needs only 3 signals (GND, RX, TX) and it is often accompanied by VCC. In this specific case, it is even marked as TX0 and RX0 on the board itself, so it is hard to miss it. If there are no labels, it is always worth looking for a populated or unpopulated 4-pin header on the PCB. There are many different methods in finding the serial using documentation, PCB designs online, service manuals, debugging with piezoelectric buzzer or multimeter. Of course, Logic Analyzer or Oscilloscope can be used as well.

| ![Broadlink RM Mini 3 pinout]({{ site.baseurl }}/images/iot-devices-uart/broadlink-rm-mini-pinout.jpg) | 
|:---:| 
| *Broadlink RM Mini 3 pinout* |

Once pinout is found, identifying GND pin is quite easy as it is usually connected to the same ground as the power connector. RX and GND are usually at 0V while VCC and TX pins are at voltage levels of the UART (usually 3.3V). To differentiate TX and VCC pins, one of the methods is to check if VCC pin is connected to the power connector. Also, there should be infinite resistance between VCC and TX pins. Usually, it is enough to connect TX, RX and GND pins as there is no need to connect VCC pin.
Having the header soldered to the pins, it is much simpler to perform further actions on the UART. Therefore, it is recommended to solder the header on identified UART pins if it is not already present.

| ![Broadlink RM Mini 3 UART header]({{ site.baseurl }}/images/iot-devices-uart/broadlink-rm-mini-uart-header.jpg) | 
|:---:| 
| *Broadlink RM Mini 3 UART header* |

## UART communication

Since it is standard serial communication from the hardware side, any USB to Serial TTL adapter should work. Other options include Shikra or Bus Pirate.

From the software side, any terminal application which allows access to serial ports should work. As long as you can specify port, terminal mode and speed.
For example, on Windows, putty can be used to access the serial port and on Linux/Unix/BSD/MAC picocom, minicom or screen.

In this example, we will use screen on standard Intel Linux device with following options:
```
screen /dev/ttyUSB0 115200 8N1
```

Once connected to the UART, the following output is visible when connected to the serial line:

```
broadlink Hello World application Started Product Type :10039 V20027
[partition] Error: Partition Table 1 @0x2000 is corrupted
[sdio] Card detected
[sdio] Card reset successful
[sdio] Card Version - (0x32)
[sdio] Card initialization successful
[wlcm] WLAN FW ext_version: w8801-B0, RF878X, FP68, 0.0.0.p16
[af] app_ctrl: reset_to_factory=0, prev_fw_version=1
[wlcm] SUPP EVENT = 0 data = 0x00000000 len=0
[net] Initializing TCP/IP stack
```

Looking at the debug messages reveals following messages with wireless credentials:

```
app_firmare_start startup success.
task_thread startup success.
,,,,,,,,,,,,,bl2_thread,,,,,,,,,,,,,,,
ssid WirelessSSID psk WirelessPassw0rd need broad 0
type 3
ssid WirelessSSID  psk WirelessPassw0rd psklen 16, type 5 special 0
app_network_status_set to status. 6.....
[af] app_ctrl: Connecting to the loaded network
```

As you can see from the output, IoT device is trying to connect to the wireless network with name "WirelessSSID" and password "WirelessPassw0rd" in plaintext. Attacker is now able to use these credentials to connect to the wireless network in question.

## Summary

As you can see, this is entry level hardware hacking, but it is good example how IoT devices could introduce risks and extend the attack surface if not handled properly.

If somebody can physically access your IoT device which connects somewhere, you can assume that attacker gained access to the plaintext credentials or passwords - not just hash.
Selling your previously owned and configured IoT device or throwing IoT device in trash with your network credentials should have its process.
So, what typical consumer can do if she/he wants to sell, give away or dispose IoT device? It would be good to perform resetting of the device to the factory defaults by using instructions found in the manual of the target IoT device.
If IoT device does not have option to perform hard reset on the device, another way is to actually change credentials to bogus one before disposal of the IoT device.
If device does not function properly and it is hard to know if reset was successful, it is advised to physically destroy the components which hold the credentials.
Another workaround is to change the credentials on the network itself, so device would hold old and invalid credentials. It is always good to change and rotate the credentials on the regular basis.

If you are vendor of IoT device, you should at least provide function to reset the device to the factory defaults. Such reset should wipe the credentials from the device, not just set flags for reset. That means that credentials are not present and readable after hard reset, but this is subject for another blog post. Stay tuned.

### Tools

Tools mentioned in this article:

 - [putty](http://www.chiark.greenend.org.uk/~sgtatham/putty/) - putty terminal
 - [Tera Term](https://es.osdn.net/projects/ttssh2/) - terminal for Windows
 - [Minicom](https://man.cx/Minicom) - Minicom terminal 
 - [USB2TTL](https://www.instructables.com/USB-to-Serial-TTL/) - USB to Serial TTL
 - [Bus Pirate ](http://dangerousprototypes.com/docs/Bus_Pirate) - hardware hacking swiss tool
 - [Shikra](https://www.xipiter.com/musings/using-the-shikra-to-attack-embedded-systems-getting-started) - another hardware hacking swiss tool

### References

 - [Serial Console on OpenWRT](https://openwrt.org/docs/techref/hardware/port.serial)

