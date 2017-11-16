

layout: post
title: Hack Dat Kiwi 2017 wp
categories: ctf Hack_Dat_Kiwi 2017
tags: ctf writeup 2017 Hack_Dat_Kiwi







# Web

### MD5 Games 1-50

> 10 years has passed since MD5 was broken, yet it is still frequently used in web applications, particularly PHP powered applications (maybe because there's a function after it?). Break it again to prove the point!
>
> [Start](http://cdf257.2017.hack.dat.kiwi/web/md5games1/)
>

就是要md5的明文和密文相同，让我想起了一道题，图片中显示的数字和该图片的md5值相同。



### Serial Number-60

> We bought this electric oven that looked so nice, and it stopped working after a few months. Unfortunately we never registered our product and we also trashed the box. Now the registration requires a serial number, and they won't service our oven without a registration. Help us!
>
> note:[Source code](http://cdf257.2017.hack.dat.kiwi/web/serialnumber.zip)
>
> [Start](http://cdf257.2017.hack.dat.kiwi/web/serialnumber/)



### Hasher-100

> There's this system that has a hardcoded admin user/password, in a way that can not be brute forced or cracked. We desperately need to acquire access to this system, can you help us?
>
> NOTE:Source code inside challenge
>
> [Start](http://cdf257.2017.hack.dat.kiwi/web/hasher/)



### MD5 Games 2-120

> You broke that one using birthday paradox right? Well you can't use that in this one...
>
> [Start](http://cdf257.2017.hack.dat.kiwi/web/md5games2)



### Fractal-150

> This dude in my classroom has created a crappy shopping software for the class project, and has sold it to his father's company for a hundred thousand kiwis!
>
> Bust his ass and make us all feel good about it.
>
> [Start](http://cdf257.2017.hack.dat.kiwi/web/fractal/)



### Authenticator-240

> You know OAuth and all those complicated authentication libraries? Well screm the mall!
>
> We have created a lightweight and simple authentication library, and it works flawlessly! Here's a sample web application that uses our authenticator. See how fast and lightweight it is for yourself.
>
> [source code](http://cdf257.2017.hack.dat.kiwi/web/authenticator.zip)
>
> [Start](http://cdf257.2017.hack.dat.kiwi/web/authenticator/)



### Strongpass-250

> These guys are enterprise! They use very strong password management systems. The system does not let you reuse any of your previously used passwords, and doesn't store any of your passwords either!
>
> How can we possibly hack such an enterprise system!?
>
> [source code](http://cdf257.2017.hack.dat.kiwi/web/strongpass.zip)
>
> [Start](http://cdf257.2017.hack.dat.kiwi/web/strongpass/)





# Forensic

### Eluware 1-100

> There's a nasty malware infecting our visitors. We were unable to find out where it's coming from and what it's doing. Do us a solid and find that out!
>
> NOTE:You will see a red square saying 'Pwned' when the malware runs.
>
> [start](http://cdf257.2017.hack.dat.kiwi/forensics/eluware/)
>



### Eluware 2-150

> Apparently that malware you just found was a first in a wave of new malwares. They have struck again, this time on our partner service.
>
> This malware is a little tricky and does not trigger all the time. We guess that it only runs on certain conditions. Find it for us please!
>
> NOTE:You will see a red square saying 'Pwned' when the malware runs.
>
> [Start](http://cdf257.2017.hack.dat.kiwi/forensics/eluware2/)



### Eluware 3-200

> We have heard reports from some of our users that there is a new version of the recent malware wave on our website. We were unable to locate it, and figure out what it's doing.
>
> Apparently, only our most loyal users have been infected by this malware. Maybe it has means of detecting user loyalty? Also none of the malware scan and analysis tools were able to discover it.
>
> NOTE:You will see a red square saying 'Pwned' when the malware runs.
>
> [Start](http://cdf257.2017.hack.dat.kiwi/forensics/eluware3/)



### Eluware 4-250

> Apparently this new malware only infects certain users. A lot of iphone users have reported suspicious activity. We were unable to track and find the malware though, do that for us please!
>
> NOTE:You will see a red square saying 'Pwned' when the malware runs.
>
> [Start](http://cdf257.2017.hack.dat.kiwi/forensics/eluware4/)



# MISC

### PS 1-100

> A very old (relative to our age) cipher that made many children happy. Break it, and you'll be happy too!
>
> NOTE:[Source code](http://cdf257.2017.hack.dat.kiwi/crypto/ps/cipher.txt)
>
> NOTE:Params: {block_size:16, seed:1396, rounds:1}
>
> [Start](http://cdf257.2017.hack.dat.kiwi/crypto/ps/ps1.php)



### PS 2-100

> PS 2 cipher is an improved PS 1 cipher, made 5 years later! It supports many new usages, and new controllers too!
>
> [Source code](http://cdf257.2017.hack.dat.kiwi/crypto/ps/cipher.txt)
>
> Params: {block_size:16, seed:7, rounds:2}
>
> [Start](http://cdf257.2017.hack.dat.kiwi/crypto/ps/ps2.php)



### PS 4-120

> On release of PS 4 cipher, crypto lovers stood in lines for hours. They just couldn't get it late!
>
> [Source code](http://cdf257.2017.hack.dat.kiwi/crypto/ps/cipher.txt)
>
> Params: {block_size:16, seed:999999, rounds:4}
>
> [Start](http://cdf257.2017.hack.dat.kiwi/crypto/ps/ps4.php)



### PSP-180

> Wow! This is a lightweight and portable version of PS cipher! It's stronger too! Lets run to the mall and buy one...
>
> [Source code](http://cdf257.2017.hack.dat.kiwi/crypto/ps/cipher.txt)
>
> Params: {block_size:16, seed:1, rounds:8, plus:1}
>
> [Start](http://cdf257.2017.hack.dat.kiwi/crypto/ps/psp.php)



### Pimple Stegano-180

> Just a basic stegano software, with some freshly baked pimples. Find the message hidden in the original image, and you're good to go. You can hide any message you want in the image too (and we will bake some fresh pimples for you)!
>
> [Start](http://cdf257.2017.hack.dat.kiwi/crypto/pimple_stegano/)



# Reverse/Exp

### pppoly-100

> There's this piece of malware that we can't figure out. It will only trigger when proper password is provided, but we don't have the password. Please figure it out for us!
>
> [Download](http://cdf257.2017.hack.dat.kiwi/re/polyglot/pppoly.txt)



### Beast-120

> Beast is a text management database. It is create to store and retrieve text documents of orgnizations.
>
> Crash the beast to retrieve the flag. It runs on port 2001 of your challenge server.
>
> Server environment is Ubuntu 16.04 x86_64, has only 3 binaries [sh,cat,ls] and has no ASLR.
>
> ```shell
> nc cdf257.2017.hack.dat.kiwi 2001
> ```
>
> [Download](http://cdf257.2017.hack.dat.kiwi/re/beast/server)



### Chessmaster-150

> Every single person I see claims to be a chess master. Then you play with them and realize that they use chess master behind the scenes to decide what move to make! Well, I say no more. I have invented a new chess game, a little different than the original chess, but anyone skillful enough in original chess will be able to beat it [badly].
>
> Lets make chess great again! It runs on port 2002 of your challenge server.
>
> server environment is Ubuntu 16.04 x86_64, has only 3 binaries [sh,cat,ls] and has no ASLR.
>
> you get partial score flag on crash.
>
> ``` shell
> nc cdf257.2017.hack.dat.kiwi 2002
> ```
>
> [Download](http://cdf257.2017.hack.dat.kiwi/re/chessmaster/server)



### Polyglot-180

> Wow that piece of malware just evolved! I guess a million years must've passed...
>
> This new one is much harder to figure out, and requires your expertise!
>
> **Hint:** The expected password is proper English and is related to the theme of the CTF!
>
> [Download](http://cdf257.2017.hack.dat.kiwi/re/polyglot/polyglot.txt)



### Halftp-200

> Halftp is a very basic FTP server. It allows uploading and downloading files! You just need to show the whole world once again that reinventing the wheel is not a great idea.
>
> Access the challenge on your challenge server on port 2004.
>
> server environment is Ubuntu 16.04 x86_64, has only 3 binaries [sh,cat,ls] and has no ASLR.
>
> you get partial score flag on crash.
>
> ```shell
> nc cdf257.2017.hack.dat.kiwi 2003
> ```
>
> [Download](http://cdf257.2017.hack.dat.kiwi/re/halftp/server)



### Set Theory-250

> We have a server that implements set operations, and we use it frequently to study set theory concepts, and derive experimental proofs. Sometimes it crashes, and we'd like you to figure out why, so that we can fix it. Please don't steal our sensitive data!
>
> Access the challenge on your challenge server on port 2003.
>
> server environment is Ubuntu 16.04 x86_64, has only 3 binaries [sh,cat,ls] and has no ASLR.
>
> you get partial score flag on crash.
>
> ```shell
> nc cdf257.2017.hack.dat.kiwi 2004
> ```
>
> [Download](http://cdf257.2017.hack.dat.kiwi/re/settheory/server)



# Experimental / Academic

### PHP Sandbox -150

> We have created an experimental PHP sandbox. Give it a go!
>
> [Start](http://cdf257.2017.hack.dat.kiwi/experimental/sandbox/)



### HTI+-200

> You know what? I hate those companies that create cheap, insecure, crappy software, and then pay large sums of cash to buy security software like WAFs to protect that crap. Why don't you spend the money initially to fix the code?
>
> The security software employed by this company has 3 modes of operation, some modes are slower and more secure, and some are faster and less secure. Hack them to show this is not how you protect code.
>
> NOTE:revised, strengthened version
>
> [Start](http://cdf257.2017.hack.dat.kiwi/experimental/hti/)

