---
layout: post
title: Cracking LUKS/dm-crypt passphrases
author: kost
categories: [linux, cracking]
tags: [linux, passphrase, luks, luks1, luks2, cryptsetup, dm-crypt]
---

Linux uses dm-crypt in order to provide transparent disk or partition encryption. What are the options in case you need to recover passphrase from such encryption? There are already ready-made tools, but we have also produced and published our own in order to support newer LUKS format/ciphers/hashing.

*dm-crypt is a transparent disk encryption subsystem in the Linux kernel. It is implemented as a device mapper target and may be stacked on top of other device mapper transformations. It can thus encrypt whole disks (including removable media), partitions, software RAID volumes, logical volumes, as well as files. It appears as a block device, which can be used to back file systems, swap or as an LVM physical volume.*

There are many formats or types which dm-crypt/cryptsetup support (current version supports luks, luks1, luks2, plain, loopaes, tcrypt), but the most commons ones are LUKS1 and LUKS2, where LUKS2 is an obviously newer format, which uses argon2i by default. It is a less known fact that cryptsetup supports TrueCrypt/VeraCrypt as well. Here are usual compiled-in defaults of cryptsetup:
```
Default compiled-in key and passphrase parameters:
	Maximum keyfile size: 8192kB, Maximum interactive passphrase length 512 (characters)
Default PBKDF2 iteration time for LUKS: 2000 (ms)
Default PBKDF for LUKS2: argon2i
	Iteration time: 2000, Memory required: 1048576kB, Parallel threads: 4

Default compiled-in device cipher parameters:
	loop-AES: aes, Key 256 bits
	plain: aes-cbc-essiv:sha256, Key: 256 bits, Password hashing: ripemd160
	LUKS1: aes-xts-plain64, Key: 256 bits, LUKS header hashing: sha256, RNG: /dev/urandom
```

## Introduction

If you are using any popular Linux distribution and you're using encrypted partitions, there is a high chance that it is using LUKS1. Android encryption is also using LUKS for device encryption option. The way the LUKS works is that you have a master key which is generated for encryption and there are 8 key slots which are guarding the master key. Any key slot is able to unlock the partition if it is enabled and it is also able to dump the master key. When you setup the passphrase for the encryption, you are actually changing the passphrase for the slot and you're not changing the master key itself as that would require reencrypting the whole partition. If somebody has access to the master key, that somebody can decrypt the data without knowing any passphrase.

In this text, we will focus on cracking the passphrases behind key slots and not attacking the master key itself as that would require much more resources if the master key is generated properly. Once you have a valid passphrase for any of the key slot, it is possible to dump the master key. So, basically having a passphrase is the same as having the master key and attacking the passphrases, in most cases, is the most viable option.

Recovering the passphrase of such an encryption depends on format, cipher and key size, mode used and the strength of the passphrase that you are recovering.

## Identifying LUKS

There are different ways to identify LUKS. One of the most easiest one is to use `blkid`:

```bash
# blkid -t TYPE=crypto_LUKS -o device
/dev/sdb2
/dev/sdb3
```

Command will output each device/partition identified to stdout separated by new line. Once identified, you can gain more data about the target with `luksDump` command:
```bash
# cryptsetup luksDump /dev/sdb3
```

Command will output information about encryption used and key slots on specified partition (in this case: `/dev/sdb3`).

## Backup

Before we go any further with cracking, you should be careful with encryption actions you perform. If you are an IT veteran, you will know that backup is essential before doing anything experimental (or just create experimental LUKS encryption to test). Let me give you a single argument in this case: you don't want to lose your data. Another argument is that you don't want to transfer the whole disk, of which you only want to recover the LUKS passphrase, but only the smaller part. This is especially important if you plan to distribute it to many computers for cracking purposes. Command to backup the needed data from the disk is following:

```bash
$ dd if=/dev/sdb3 bs=1 count=2066432 of=./sdb3-to-crack
```

You're probably wondering how I figured the exact number of 2066432 bytes? Well, you can try with the smaller number and open it with luksDump command and you will get the following output:

```bash
$ cryptsetup luksDump sdb3-to-crack
Device sdb3-to-crack is too small. (LUKS1 requires at least 2066432 bytes.)
```

So, this is the evidence that you copied enough data in order to crack it.

## Basic cracking

cryptsetup itself allows to test the single passphrase by using --test-passphrase option:
```bash
$ echo "test" | cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

Therefore, it is possible to run the basic cracking job using wordlist with the following options:
```bash
$ cat wordlist.txt | xargs -t -P `nproc` -i echo {} | cryptsetup --verbose --test-passphrase open sdb3-to-crack sdb3_crypt
```

It is also possible to run password cracking legend John The Ripper with any of his powerful options (you just need --stdout option):
```bash
$ john --wordlist=wordlist.txt --stdout | xargs -t -P `nproc` -i echo {} | cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

Hashcat is also an option to generate candidate passwords:
```bash
$ hashcat -m 0 --stdout -a 3 ?a?a?a?a | xargs -t -P `nproc` -i echo {} | cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

The main problem here is that such cracking is pretty slow, as you have to spawn cryptsetup for each test of the candidate password. You also have to inspect the output of the commands manually in order to check that password was cracked.

## Faster cracking

Basic cracking works if you have few candidate passwords to try. But, if you have a tougher job and you need to guess the password faster, as you have many more candidate passwords to try, it is time to look for faster options. Both Hashcat and John the Ripper support password cracking of LUKS passphrases, but they are both limited to what cipher/hashing/LUKS[12] they support. If you're lucky enough that you need to recover passphrase from some older LUKS encryption, you can use both tools.

### Cracking using John The Ripper

For example, when using John The Ripper (Jumbo version!), you need to prepare the data for cracking by using luks2john helper python script available from the run directory of John The Ripper:

```bash
# luks2john.py /dev/sdb3 > sdb3.john
Best keyslot [0]: 460431 keyslot iterations, 4000 stripes, 120250 mkiterations
Cipherbuf size: 128000
```

**sdb3.john** file should end up with all the data needed for cracking. You will recognize it by `$luks$1$` magic in front of the hash. Once the data is prepared, you can begin with standard John the Ripper session:

```bash
# john sdb3.john
```

John the Ripper has a hard limitations on cipher/hash/mode combinations, so there is a high chance that you will not be able to crack it with John The Ripper. One of the examples when luks2john fails is the following:

```bash
$ luks2john.py sdb3-to-crack
sdb3-to-crack : Only cbc-essiv:sha256 mode is supported. Used mode: xts-plain64
```

### Cracking using Hashcat

In case you get that message from John, and if using LUKS version 1, you will have more luck if you try to crack it by using Hashcat. Hashcat is a bit different to use, but it does have far better and complete support for LUKS cracking than John The Ripper. In order to prepare the target for cracking, you have to dump the LUKS header and add a first sector of payload since hashcat has optimized the cracking, where it does not perform second PBKDF2 which LUKS performs, so cracking is significantly faster using hashcat. Usually, the preparation consist of copying the LUKS header and payload with dd command:

```
# dd if=/dev/sdb3 of=hashcat.luks bs=512 count=4097
```

Once you have the header, you can start the cracking session by using 14600 as hash type:

```
$ hashcat -a 0 -m 14600 hashcat.luks wordlist.txt
```

The output is pretty standard hashcat status output (luks1 type with aes, cbc-essiv:sha256, sha1):

```
Session..........: hashcat
Status...........: Exhausted
Hash.Type........: LUKS
Hash.Target......: hashcat.luks
Time.Started.....: Sun Nov 10 07:43:27 2019 (1 min, 16 secs)
Time.Estimated...: Sun Nov 10 07:44:43 2019 (0 secs)
Guess.Base.......: File (example.dict)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      882 H/s (2.29ms) @ Accel:2 Loops:64 Thr:64 Vec:1
Speed.#2.........:      885 H/s (2.29ms) @ Accel:2 Loops:64 Thr:64 Vec:1
Speed.#*.........:     1767 H/s
Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
Progress.........: 128416/128416 (100.00%)
Rejected.........: 0/128416 (0.00%)
Restore.Point....: 123344/128416 (96.05%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:141568-141591
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:141568-141591
Candidates.#1....: tom -> webintec
Candidates.#2....: webis -> zzzzzzzzzzz
Hardware.Mon.#1..: Util: 27% Core: 406MHz Mem:1250MHz Bus:16
Hardware.Mon.#2..: Util:  0% Core:1000MHz Mem:1250MHz Bus:4
```

And for another type of LUKS1 hash (aes, xts-plain64, sha256) output is also standard one:

```
Session..........: hashcat
Status...........: Exhausted
Hash.Type........: LUKS
Hash.Target......: hashcat.luks
Time.Started.....: Sun Nov 10 07:59:45 2019 (3 mins, 7 secs)
Time.Estimated...: Sun Nov 10 08:02:52 2019 (0 secs)
Guess.Base.......: File (example.dict)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      351 H/s (2.71ms) @ Accel:2 Loops:64 Thr:64 Vec:1
Speed.#2.........:      358 H/s (2.52ms) @ Accel:2 Loops:64 Thr:64 Vec:1
Speed.#*.........:      709 H/s
Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
Progress.........: 128416/128416 (100.00%)
Rejected.........: 0/128416 (0.00%)
Restore.Point....: 123344/128416 (96.05%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:331584-331604
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:331584-331604
Candidates.#1....: tom -> webintec
Candidates.#2....: webis -> zzzzzzzzzzz
Hardware.Mon.#1..: Util:  0% Core: 420MHz Mem:1250MHz Bus:16
Hardware.Mon.#2..: Util:  7% Core:1000MHz Mem:1250MHz Bus:4
```

As you can see, speed of cracking LUKS1 on two R9 290x GPUs is around 790 H/s (candidate passwords per seconds). Therefore, cracking is not that fast as some other password/hashing formats.
But benchmarking is topic for another article.

There are cases when specified size is not the standard one, so you will get error message like this:

```bash
$ hashcat64.bin -a 0 -m 14600 sdb3-to-crack wordlist.txt
hashcat (v5.1.0) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-4710HQ CPU @ 2.50GHz, 8192/21999 MB allocatable, 8MCU

Hashfile 'sdb3-to-crack': Invalid LUKS filesize
No hashes loaded.
```

If you get such or similar error, sometimes [LuksHeader4Hashcat](https://github.com/paule965/LuksHeader4Hashcat) utility by [paule965](https://github.com/paule965/) might help as it rebuilds luksheader in order to prepare it for hashcat:

```bash
# ./LuksHeader4Hashcat.py /dev/sdb3
##############################################################################################################

Basic-Data
----------
Date/ Time (YYYY-MM-DD HH:MM:SS):  2019-11-16 07:12:17
FileName(arg1):                    /dev/sdb3
ScriptName(arg0):                  ./LuksHeader4Hashcat.py
Filepath:                          /dev/sdb3
############################################################

Luks-Basic-Data
[..]
Status          SlotNumber      Iterations      MeyMaterialSector       AF-Stripes
----------------------------------------------------------------------------------
ACTIVE-Slot:    0               141592          0X0008                  4000
EMPTY-Slot:     1               -               -                       -
EMPTY-Slot:     2               -               -                       -
[..]
##################################################################################

Which KeySlot should be used? Possible is [0]: 0

Your Choice is KeySlot0.

Write to File:         /dev/sdb3_KeySlot0.bin
```

Even if **LuksHeader4Hashcat** cannot help you, check the format and LUKS version of the target to crack with `luksDump` command.
The real problem is that, both hashcat and JtR, support older LUKS1 format, so you would get an error if you try to crack the newer format like LUKS2 (or other uncommon format).
In such cases you have to read further in order to recover such passphrase.

## Cracking newer formats

Currently, to crack newer or other uncommon formats, it is only possible to use cryptsetup based tools. That means that you have to go back to basic cracking section of this article, and use the shell scripts or binaries that use direct functions from the cryptsetup library.

### Cracking using grond.sh

One of such scripts is [grond.sh](http://www.incredigeek.com/home/downloads/grond.sh) and you can use it to crack luks format. Its pretty limited and thread support is pretty hard coded, but you can use it for basic cracking.

Basic invocation of grond script is following:

```bash
# ./grond.sh -t4 -w wordlist.txt -d /dev/sdb3
```

Grond can use multiple threads, but if you need something faster, there are still different options.

### Cracking using bruteforce-luks

More advanced tool is [bruteforce-luks](https://github.com/glv2/bruteforce-luks). bruteforce-luks is a C program which binds to cryptsetup library and has the basic bruteforcing options included. 

Once you manage to compile it, you can invoke it by number of threads you want to use and choose different modes of cracking. For example, you can use dictionary mode and read the candidate password from the wordlist or dictionary:

```bash
# bruteforce-luks -t 4 -f wordlist.txt /dev/sdb3
```

There is also an interesting mode where you can specify possible beginning of the password and ending of the password and bruteforce-luks will bruteforce the missing characters in the middle:

```bash
# bruteforce-luks -t 4 -l 5 -m 12 -b "Begin" -e "End" /dev/sdb3
```

Actually, while writting this article, there were commits which enabled bruteforce-luks to support LUKS2, so it was good timing to actually introduce this feature.

### Cracking using modified cryptsetup

The only issue with bruteforce-luks is that you cannot use John the Ripper and hashcat powerful candidate rule generation as it does not support stdin. Also, I wanted to have an approach where cracking will work under any custom parameter and format that cryptsetup supports. Therefore, an approach was to [change the cryptsetup itself minimally](https://github.com/Diverto/cryptsetup-pwguess/compare/master...pwguess?expand=1) to accept multiple tries from standard input (stdin). Such patch was made and you can download and compile original cryptsetup with patch.

```bash
git clone -b pwguess https://github.com/diverto/cryptsetup-pwguess.git
cd cryptsetup-pwguess
./autogen.sh
./configure
make
```

You can still use the newly compiled cryptsetup as usual with single passphrase:
```bash
$ echo "test" | ./cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

Where modified cryptsetup really shines is when you pass multiple passwords, separated with the newline, on its standard input:
```bash
$ cat wordlist.txt | ./cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

It will try each password candidate from the wordlist.txt and report if password is correct. Another helpful way of cracking is by using [rexgen](https://github.com/teeshop/rexgen), where you can specify password candidates using regular expression (as an example it will generate Test01 to Test99 password candidates):

```bash
$ rexgen 'Test[0-9]{2}' | ./cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

There are also helpful environment variables for password guessing. For example, you can set `DIVERTO_LUKS_VERBOSE` to any value and it will report each password result:

```bash
$ export DIVERTO_LUKS_VERBOSE=1
```

I would suggest to use `DIVERTO_LUKS_VERBOSE` for setting up cracking session and checking if everything is working like expected, and later you can just unset it:

```bash
$ unset DIVERTO_LUKS_VERBOSE
```

Another helpful environment variable is `DIVERTO_LUKS_OUT` which you can set to write successfully guessed passwords. Example is trivial:

```bash
$ export DIVERTO_LUKS_OUT=/tmp/cracked.txt
```

When using it this way, you can monitor for /tmp/cracked.txt file if cracking was successful. Make sure that cryptsetup have permissions to create file in the directory you plan to write the output to.

Real power comes from using Hashcat and/or John The Ripper candidate password generator feature and piping it to the modified cryptsetup:

```bash
$ john --wordlist=wordlist.txt --rule=jumbo --stdout  | ./cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

And example for hashcat
```bash
$ hashcat -m 0 --stdout -a 3 ?a?a?a?a | ./cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

If you want to crack using multiple threads, you can take advantage of GNU parallel. The following is an example with 2 threads:

```bash
$ cat wordlist.lst | parallel --pipe -j 2 -N 1000 ./cryptsetup open --test-passphrase sdb3-to-crack sdb3_crypt
```

The following example is using jumbo rules to feed it to the modified cryptsetup (using 2 threads):

```bash
$ john --wordlist=wordlist.txt --rule=jumbo --stdout  | parallel --pipe -j 2 -N 1000 ./cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

Similar can be used to crack using Hashcat (using 4 threads):

```bash
$ hashcat -m 0 --stdout -a 3 ?a?a?a?a | parallel --pipe -j 4 -N 1000 ./cryptsetup --test-passphrase open sdb3-to-crack sdb3_crypt
```

## Remediations

If you are worried that someone might steal your data by using these techniques, you can start by changing the LUKS passphrase you're using. Of course, you can even change it on a regular basis. LUKS can hold up to 8 slots numbered from 0 to 7 and any key slot is able to unlock the partition if it is enabled. So, changing the passphrase consists of calling `luksChangeKey` with slot number specified (if having a single passphrase, slot should be 0):

```bash
# cryptsetup luksChangeKey /dev/sdb3 -S 0
```

Alternative would be adding a new passphrase to an empty slot and deleting the slot that holds the old passphrase:

```bash
# cryptsetup -y luksAddKey /dev/sdb3
# cryptsetup luksRemoveKey /dev/sdb3
```

Advantage of this method is that you can first test is everything is working before deleting the old passphrase. Still, if you forget to remove the slot, both old and new passphrases will work and therefore will reduce the overall security level of the encryption.

### Converting to LUKS2

If you're still worried and want to increase your security posture, you can carefully choose encryption/hash/mode and convert your partition to LUKS2 format. Note that [GRUB2 still does not support LUKS2](https://savannah.gnu.org/bugs/?55093), so having LUKS2 format requires having at least `/boot` partition unencrypted. Converting to LUKS2 format is done by using the following command:

```bash
# cryptsetup convert /dev/sdb3  --type=luks2

WARNING!
========
This operation will convert /dev/sdb3 to LUKS2 format.


Are you sure? (Type uppercase yes):
```

### Hiding LUKS headers

Another good trick is to remove the luks header completely from the partition, in cases when you are forced to provide your key to encrypted data or when your passphrase leaked. Attacker would have a hard time recovering as he does not have encryption methods used and salt. When creating such scenario, you can use following command:

```bash
# cryptsetup luksFormat --type luks2 /dev/sdb3 --align-payload 8192 --header /somewhere/safe/header.luks
```

Opening the encrypted container is also bit different as you have to specify location of LUKS header:

```bash
cryptsetup open --header=/somewhere/safe/header.luks /dev/sdb3 sdb3_crypt
```

In this case, it is no longer easy to identify LUKS partition. Of course, entropy analysis would provide clue about potential encryption.

By looking at the hashcat discoveries, it seems that it would be harder for an attacker to backup and remove first sector of the payload itself.
Idea is to backup LUKS header and first sectors of the encrypted data to different safe medium:

```bash
# dd if=/dev/sdb3 of=luks.sensitive bs=512 count=4097
```

After successful backup, you can overwrite it with the random data:

```bash
# dd if=/dev/random of=/dev/sdb3 bs=512 count=4097
```

In this case, you have to copy back the first sector of the payload data before specifying the location of the LUKS header:

```bash
# dd if=luks.sensitive of=/dev/sdb3 bs=512 skip=4096 seek=4096 count=1 conv=notrunc
# cryptsetup open --header=/somewhere/safe/luks.sensitive /dev/sdb3 sdb3_crypt
```

And of course, after finishing - filling up with the random bytes again:

```bash
# cryptsetup close sdb3_crypt
# dd if=/dev/random of=/dev/sdb3 bs=512 skip=4096 seek=4096 count=1 conv=notrunc
```

## Recovery concerns and backup

If you are worried that you will forget your passphrase or your data, it is a good practice to actually backup LUKS header and store it somewhere safe. So, in case of LUKS data corruption - you would still have the most valuable data in recovery - the keys to the encrypted data. Command is:

```bash
# cryptsetup luksHeaderBackup /dev/sdb3 --header-backup-file /somewhere/safe/sdb3-luks-header.backup
```

Restore of the header is done via luksHeaderRestore command:

```bash
# cryptsetup luksHeaderRestore /dev/sdb3 --header-backup-file /somewhere/safe/sdb3-luks-header.backup
```

Note that, in the case of recovery of backup, valid passphrase would be in time when the backup is performed.

### Backup of master key

Another thing that can help during the recovery procedure is backing up the master key. Having the master key allows access to the encrypted data without the knowledge of any passphrase of the slots. You can dump the master key with the `--dump-master-key` option:

```bash
# cryptsetup luksDump -q --dump-master-key /dev/sdb3 > /somewhere/safe/sdb3-luks-master.key
```

With master key you can manage key slots even when you don't know any passphrase. Therefore, you should store your master key in a safe place. Even better, it is recommended to immediately encrypt it in the process. One of the good options is using your GPG key, so you can just pipe it to the gpg for encryption. Of course, all of that depends on your threat model and encryptions preferred.

Note that dump-master-key will dump the master key in hex format under `MK dump` field. Therefore, you need to convert it to the binary format if you plan to use it later with cryptsetup. You can use the following oneliner to create a binary file:

```bash
# cryptsetup luksDump -q --dump-master-key /dev/sdb3 | grep -A 3 'MK dump' | sed -e 's/MK dump://g' -e 's/\s//g' | xxd -r -p > sdb3-luks-master.bin
```

After having the binary form of the master key, you can easily manipulate with the key slots. Here's the example:

```bash
# cryptsetup luksAddKey /dev/sdb3 --master-key-file sdb3-luks-master.bin
Enter new passphrase for key slot:
Verify passphrase:
```

## Disclaimer

Current limitations of the tools are described as of the date of this blog post. Hopefully, both Hashcat and John The Ripper will get a support for all of the format/hash/cipher combinations that LUKS supports.

### Tools

Tools mentioned in this article:

 - [cryptsetup-pwguess](https://github.com/Diverto/cryptsetup-pwguess) - cryptsetup with minimal modification to accept multiple tries of password guessing
 - [bruteforce-luks](https://github.com/glv2/bruteforce-luks) - separate LUKS cracking project taking advantage of cryptsetup library with needed function calls
 - [grond.sh](http://www.incredigeek.com/home/downloads/grond.sh) - shell script to automatize cracking
 - [rexgen](https://github.com/teeshop/rexgen) - A tool to create words based on regular expressions
 - [John The Ripper Jumbo](https://github.com/magnumripper/JohnTheRipper) - Jumbo version of the John The Ripper
 - [hashcat](https://hashcat.net/) - Hashcat, advanced password recovery
 - [LuksHeader4Hashcat](https://github.com/paule965/LuksHeader4Hashcat) - rebuild a luksheader for hashcat


### References

 - [Recovering forgotten passwords with stutter and GNU parallel](https://www.nmattia.com/posts/2017-03-05-crack-luks-stutter-gnu-parallel.html)
 - [Brute forcing password cracking devices (LUKS)](https://dfir.science/2014/08/how-to-brute-forcing-password-cracking.html)
 - [How to crack encrypted disk (crypto-LUKS) in an efficient way?](https://security.stackexchange.com/questions/128539/how-to-crack-encrypted-disk-crypto-luks-in-an-efficient-way)
 - [LUKS HDD Encryption crack](https://security.stackexchange.com/questions/90000/luks-hdd-encryption-crack)
 - [LUKS support on hashcat.net forums](https://hashcat.net/forum/thread-6225.html)
 - [How to recover lost LUKS key or passphrase](https://access.redhat.com/solutions/1543373)

