---
layout: post
title: "HackCon 2017 Writeup"
categories: ctf HackCon 2017
tags: ctf writeup 2017
---

# Bacche

### *Rotate It*

> Found this weird code can you make something out of it?
>
> q4ex{ju0_tvir$_pn3fne_va_PGS???}p0qr

rotate就是置换，rot变换。



### Cave

> Are these cave drawings?
>
> Note: Flag is not in standard format, enclose it in d4rk{..}c0de
>
> file:Bacche/cave.png

![cave]({{ site.url }}/assets/img/2017-09-02-HackCon-WP-cave.png)

A little bit of googling, and we find out it's [Egyptian Glyph Alphabet](http://www.virtual-egypt.com/newhtml/hieroglyphics/sample/alphabet.gif) After decoding, we get `THE FLAG IS EGYPTISBETTERTHANYOU`

<!--

### Numbers

> These are some numbers, try to make sense of them.
>
> file:Bacche/numbers.txt

-->

### *flag.txt*

> Even google won't be able to find the flag.
> Still you can try if you want: <http://defcon.org.in:6061/>

这题根据robots.txt可以发现`500786fbfb9cadc4834cd3783894239d`，但是访问了却是404。题目提示是flag.txt，所以待访问文件应该是`500786fbfb9cadc4834cd3783894239d/flag.txt`。

注：

- robots.txt中disabled列的表项一般都应该是目录，所以应该想到目录拼接flag.txt。
- Nginx/Apache都可以通过配置文件改变response code，估计本题就是这么设置的，因此起到了很大的迷惑。

  [1]: http://www.cnblogs.com/freeweb/p/5724545.html"Nginx配置指定response code"
  [2]: https://gxnotes.com/article/207667.html"Apache配置指定response code"



### *Xrrrr*

> Now, what is this code, can you break it?
>
> file:file.txt

根据题目名称猜测是xor加密，使用xortool破解。

先估计key长度：

```shell
xortool -x file.txt	#注意要加-x参数，表述hex编码
```

发现可能性最大的长度为6，然后再爆破：

```shell
xortool -x -l 6 -o file.txt
```

此时，会在当前文件夹下生成xortool_out文件夹，里面的filename-key.csv和filename-char_used-perc_printable.cvs文件内容和其名称对应。其他out文件均为解密后输出内容。正确文件必然是只有可打印字符的文本文件，根据flag形式再查找flag：

```shell
strings xortools_out/* |grep d4rk
```



# Web

### *Noobcoder*

> A junior recently started doing PHP, and makes some random shit. He uses gedit as his go-to editor with a black theme thinking it was sublime.
> So he made this login portal, I am sure he must have left something out. Why don't you give it a try?
> Server: [http://defcon.org.in:6062](http://defcon.org.in:6062/)

老外这提示也是没谁了，就怕你想不到，找不到。分别找到`index.php~`和`checker.php~`，查看源码，用PHP的科学记数法绕过即可。



### *Magic*

> Everything disappears magically.
> Can you magically prevent that?
> <http://defcon.org.in:6060/index.php>

这题有点小脑洞，访问首页后有一长串的cookie值，将这串cookie值全拼起来并就是brainfuck代码。

另外，这题还要注意的是，因为返回的header值太多，requests会报错，需要做如下修改：

```python
import httplib  # or http.client if you're on Python 3
httplib._MAXHEADERS = 1000
```

可解出来用户名和密码：`username: abERsdhw password: HHealskdwwpr`

<!--

### Dictator

> A dictator is creating a lot of fuss nowadays by claiming to have nuclear weapons. I somehow got access to his personal website that he uses to send instructions, but I cannot get in. Can you try?
>
> Link: [Website](http://defcon.org.in:6063/)
>
> Hint: you need to be living in that country to get access.



### Stolen Calculator - PWN

> I stole this calculator from someone and made some changes because I am the plagiarism god. Bow before me now.
>
> btw wanna try it: <http://defcon.org.in:9080/>
>
> Hint: This is a pwn challenge



# Misc

### Forgot Password

> I safely secured my flag in a zip file long ago but forgot the password, can you help me recover it?
> The password wouldn't be too complicated, I was just a child.
>
> file: zipfile_500.zip



### Typing isn't fun

> This message was intercepted between two well known hackers in 1999. No one has been able to decrypt it since then. Can you do it?
>
> file：[finalaudio.wav](https://hackcon.in/files/0093101b84597d82335f7e4f5ef42842/finalaudio.wav)



### Corrupt python

> Someone send me this python code, but I don't understand what it's printing, maybe its corrupt or something. I have it compressed here, please have a look:
>
> `cCA9IDUgIwloIGUJbA0KcyA9IDUjMSBoCW8gdyB1DQpzMiA9IDUjeCB0aGUJCQkJDQpmbGFnID0gWydhJywnYicsJ2MnLCdkJywnZScsJ2YnLCdnJywnaCcsJ2knLCdqJywnaycsJ2wnLCdtJywnbycsJ3AnJ3EnLCdyJywncyddI3ggeAl4CXgNCmZsYWdbMF0gPSA1ICsgb3JkKCd7JykJKwkxMDAJfAkzMAkrIG9yZCgnfScpCS0yDQpmbGFnWzFdID0gNiArCW9yZCgneycpICsgOTkJfAkzMQ0KZmxhZ1syXSA9IDcgKwlvcmQoJ3snKSArCTk4DQpmbGFnWzNdID0gOCArCW9yZCgneycpCSNoZWxsbw0KZmxhZ1s0XSA9IDkgKwlvcmQoJ3snKQ0KZmxhZ1s1XSA9IDEwICsJb3JkKCd7JykgKyA5NSB8IDM1DQpmbGFnWzZdID0gMTEgKwlvcmQoJ3snKSArIDk0CXwJMzYNCmZsYWdbN10gPSAxMiArCW9yZCgneycpICsJOTMNCmZsYWdbOF0gPSAxMyArCW9yZCgneycpICsJOTIgfCAzOA0KZmxhZ1s5XSA9IDEgKwlvcmQoJ2QnKSArIDEwMAkjaGVsbG8NCmZsYWdbMTBdID0gMiArCW9yZCgnNCcpICsgMTAxICNmbGFnaXNoZXJlDQpmbGFnWzExXSA9IDMgKwlvcmQoJ2snKSArCTEwMgl8CTMyDQpmbGFnWzEyXSA9IDQgKyBvcmQoJ2UnKQkrCTEwMwl8CTMzICsJb3JkKCc0JykJLTUNCmZsYWdbMTNdID0gNSArCW9yZCgncycpICsJMTA0CSNvcm1heWJlaXRzbm90DQpmbGFnWzE0XSA9IDYgKwlvcmQoJ2YnKSArIDEwNQl8IDM1DQpmbGFnWzE1XSA9IDcgI25vcGUJDQpmbGFnWzE2XSA9IDggKwlvcmQoJzAnKSArIG9yZCgnZCcpDQpwcmludCAiIGN1eiBoZWxsbyBmcm9tCXRoZQlvdGhlciBzaWRlIEkJd2lzaCAiCQ0KcHJpbnQgIiB0byBhY2NlcyB0aGUJZmxhZwl5b3UJbXVzdCBkbyB0aGUJIiANCnByaW50ICIgZm9sbG93aW5nIHRoaW5ncyBzdGVwCWJ5CXN0ZXAgZmlyc3QJbGVhcm4JaG93CSIJDQpwcmludCAiIHRvIHVzZSBpbnN0ZXJlc3RpbmcJdGhpbmdzCWxpa2UgbGFuZ3VhZ2VzCWFuZAl0aGVuICIJDQpwcmludCAiIHRyeSB0byBhdHRlbXB0IHRoaXMJYWdhaW4gb2s/IG9rPyBvaz8gIiANCnByaW50ICIgZmFrZWZsYWdkNHJre2xvbH1jMGRlIHNlZSB0aGlzCXdvbnQJd29yayBzbwlkb250IHRyeQkiCQ0KdGdlID0gNSArIDk0CXwJMjMgXgkxCSsJOQkNCnByaW50IHRnZSArIDIzICsJMzQJfCAzNAkrCTIzCSs1CQ0KZ2VlID0gMyArIDQqNQktMwkvMiArCTUJLTMgKzQgDQpGbGFnPQkwDQpwcmludCBGbGFnICsJNQ0KcHJpbnQgRmxhZyArCTEwDQpwcmludCBzdHIoRmxhZykgKwkiaGVkbGxvciINCnByaW50ICJpZiIgKwkieW91Ig0KcHJpbnQgImFyZSIgKwkicmVhZGluZyINCnByaW50ICJ0aGlzIiArCSJ0aGF0Ig0KcHJpbnQgIm1lYW5zIiArCSJ0aGF0Ig0KcHJpbnQgInlvdSIgKwkiaGF2ZSINCnByaW50ICJmb3VuZCIgKwkidGhlIg0KcHJpbnQgImZsYWciICsJImlmX3lvdV9jYWxjdWxhdGVkX2FsbF90aGF0X3RoZW5feW91X2hhdmVfaXRfZm9yX3N1cmUiDQpwcmludCAiaWZfbm90X2hlcmVfaXNfdGhlX2ZsYWciICsJImZsYWciDQpmcm9tIG1hdGggaW1wb3J0CWNlaWwNCnByaW50IGNlaWwoNS42KSArCWNlaWwoNi41KQ0KZnJvbSBvcyBpbXBvcnQJc3lzdGVtDQpzeXN0ZW0oImxzIikgIyBmaW5kCXRoaXMNCnN5c3RlbSgiY2F0ICoiKSMgZmxhZwlpc19oZXJlDQpzeXN0ZW0oIm5ldHN0YXQiKSAjdGhpc19pcyBpbXBvcnRhdAl0b19zb2x2ZQ0KcHJpbnQgInB5dGhvbl9pc19sb3ZlIiArCSJweXRob25faXNfbGlmZSINCnByaW50ICJ3aGljaF92ZXJzaW9uX29mX3B5dGhvbj8iICsJInRoaW5rIg0KZnJvbSBtYXRoIGltcG9ydAlmYWJzDQphYnMoNS44KSAjIHRoaXNfZnVuY3Rpb25faXNfaW5jb21wbGV0ZVQJDQpzeXN0ZW0oImlmY29uZmlnIikgIyBzb3JyeQkNCnN5c3RlbSgibHMiKSAjIHNyeWFnYWluCQ0KcHJpbnQgImZ1biIgI3JpZ2h0PwkNCnByaW50ICJ0aGlzX2lzX3RoZV9iZXN0IiAjaGFoYWhhCQ0KcHJpbnQgImZvdW5kaXR5ZXQ/IiAjZG9udGxpZQkNCnByaW50ICJhbG1vc3RfY3JhY2tlZF9pdCIgI29yX25vdAkNCnByaW50IGZsYWcgI25vcAkNCnByaW50ICJzdXAiICNkb25lYXRsYXN0CQ0KcHJpbnQgImxhc3R0aW1laXByb21pc2UiIA0KcHJpbnQoZmxhZykNCnByaW50KEZsYWcp`
>
> Note: Slightly different flag format.



### Code Golf

> Heard of factorial right? Can you write a code for me?
>
> Server:
>
> nc defcon.org.in 8080

-->

# Steg

### *Standard Steg*

> I hacked my friend's facebook, by seeing his chrome password. I am smart, right?
> Anyways, he sent this image to one of his friends, idk what it is, looks like a useless logo, can you check?
>
> file: Secret.png encrypt.py

分析encrypt.py，就是将信息通过LSB方式隐写到Secret.png里，但是有所变化的是，每个像素点只在RGB其中的一个通道中写入。需要脚本将信息重新提取出来。

```python
from PIL import Image
import re
def getLSB(pixel):
    return str(bin(pixel))[-1]

header, trailer = 2*"11001100",2*"0101010100000000"
im=Image.open(r'D:\security\WP\HackCon\2017\Steg\Secret.png')
pixels,mode=list(im.getdata()),im.mode
s=''
for i in range(len(pixels)):
    s+=getLSB(pixels[i][i%len(mode)])
#print s
s=re.search('^'+header+'([01]*)'+trailer,s).group(1)
flag=[]
for i in range(0,len(s),8):
    flag.append(chr(int(s[i:i+8],2)))
print ''.join(flag)
```



### *White*

> This is a white image. Or is it?
>
> file:[final.png](https://hackcon.in/files/fa152fbb6c29afbfaf4f4eb95f898245/final.png)

这题是png+base64，然后base64解出来之后还是这样的循环，就一直这样一共能拆出来30个小图片，再以6*5的格式拼成一张图片就复原了flag。循环次数太多，需要脚本。

```python
import base64
from PIL import Image
data=open(r'final.png','rb').read()
_h=r'iVBORw0KG'
p=data.find(_h)
f=r'final/final%d.png'
i=0
while(-1!=p):
    #print p
    open(f%(i),'wb').write(data[:p])
    data=data[p:]
    data=base64.b64decode(data)
    p=data.find(_h)
    i+=1
open(f%(i),'wb').write(data)
x,y=0,0
im=Image.new('RGB',(28*6,34*5))
for y in range(5):
    for x in range(6):
        _frag=Image.open(f%(y*6+x))
        im.paste(_frag,(x*28,y*34))
im.show()
```

<!--

### Cache

> This audio file seems really suspicious. Maybe something is hidden in it. Could you help me find it out? And ofc by help I mean just give me the answer.
>
> file:[File](https://drive.google.com/file/d/0B-VogpUTH6AkcVFrS3N0eFZqU1k/view?usp=sharing)



### Weird file

> I was sniffing the CSI networks and was able to capture this weird file. I know it is something important, but it doesn't seem to do anything.
>
> Download: [File](https://goo.gl/z12VZv)
>
> [wierd_file.exec](https://hackcon.in/files/fc633abeb1573cae1d5345791142004b/wierd_file.exec)



# Crypto

### RSA - 2

> No p,q this time. LOL, what will you do now?
>
> n = 109676931776753394141394564514720734236796584022842820507613945978304098920529412415619708851314423671483225500317195833435789174491417871864260375066278885574232653256425434296113773973874542733322600365156233965235292281146938652303374751525426102732530711430473466903656428846184387282528950095967567885381
>
> e = 49446678600051379228760906286031155509742239832659705731559249988210578539211813543612425990507831160407165259046991194935262200565953842567148786053040450198919753834397378188932524599840027093290217612285214105791999673535556558448523448336314401414644879827127064929878383237432895170442176211946286617205
>
> c = 103280644092615059984518332609100925251130437801342718478803923990158474621180283788652329522078935869010936203566024336697568861166241737937884153980866061431062015970439320809653170936674539901900312536610219900459284854811622720209705994060764318380465515920139663572083312965314519159261624303103692125635



### VizHash

> I was bored and high af and thought of making a visual hash function where instead of a digest we get a png as hash of a string
> So I developed this algorithm to hash the flag. (Patent pending, don't even think of copying it)
> It is so secure that you need more computation to break this than to break a sha256 hash
>
> [vizhash.zip](https://hackcon.in/files/694263a1fb195f088e1ec57cf35b92da/vizhash.zip)



### RSA - 3

> I was finally able to capture the modulos and ciphertext that my friend uses to send the flag to everyone. Please hack it, and tell me what he is sending.Note: Different flag format.
>
> [rsa3.txt](https://hackcon.in/files/257f1bd531bea7b6a29a700bd949b42f/rsa3.txt)

-->

# Rev

### Keygen

> This proprietary software asks for a key, can you find what it is?
> To get the flag send your key to
>
> `defcon.org.in:8082`
>
> eg:
> `echo 'your_key' | nc defcon.org.in 8082`
>
> file: match_me

64位linux程序，但是IDA直接看c代码并不复杂，就是hextobin然后再计算了rot13。本地测试已经成功，但是远程发不上去。

<!-- 

### Keygen - 2

> This is the continuation of Keygen, solve that first.
> Now make a proper keygen.
>
> nc defcon.org.in 8083
>
> file:[match_me](https://hackcon.in/files/8cff71f63f624f6f036730420cc2729a/match_me)



### Not Web

> I hate JS, I seriously do. It is a mess.Hint: Just get over your fear of JS and try this challenge.
>
> [ihatejs.js.zip](https://hackcon.in/files/523cc093a0d36558a7ad47a88740cc62/ihatejs.js.zip)



### Black and White

> This image reminds you of something? Yes, it's just like your life.
>
> [image.png](https://hackcon.in/files/b46f8810bea05127f88aaf9229357db6/image.png)



### Secret Message

> Someone made a secret chatting application as part of their school assignment. They claim to have made their own private-private crypto. I somehow managed to capture their data and get the chat between them. Can you help me break the encryption? there has to be some bug in the code.
> Application: [Link](https://drive.google.com/file/d/0B-VogpUTH6AkblhFNjhNenE2aE0/view?usp=sharing)
> Capture: [Link](https://drive.google.com/file/d/0B-VogpUTH6AkY1hSLWJxUzJmdEU/view?usp=sharing)



### Super secret logger

> Yes, it's the same person. He edited his assignment to make a secret logger to log important conversations. I cannot seem to decode that, looks like he changed the encryption, you can try if you like.
> Application: [Link](https://drive.google.com/file/d/0B-VogpUTH6AkUFhITG1qRXBmZDg/view?usp=sharing)
> Capture: [Link](https://drive.google.com/open?id=0B-VogpUTH6AkMG1kbGdoUDR5VWs)



### Not web - 2

> There is another flag in Not Web, find it and 150 points are yours



# PWN

### netcat

> This is something:
>
>  nc 139.59.13.232 4200 
> Hint: This question should have been in the web category I suppopse :( . Sorry!



### Too Lazy

> I am too lazy to even type it out. Just read my mind.
>
> nc 139.59.13.232 3200



### Go knock yourselves. Easy shell!

> Yes you get to look at the binary this time.
>
> nc -v 139.59.13.232 2200
>
> file:[pwn75](https://hackcon.in/files/8f2051514ed9ea4401efbb67d7da362c/pwn75)

-->