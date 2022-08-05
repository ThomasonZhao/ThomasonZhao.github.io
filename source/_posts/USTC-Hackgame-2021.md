---
title: USTC Hackgame 2021
date: 2021-11-04 17:45:00
category: Writeup
tags: 
    - USTC Hackgame
---

此为Thomason的个人WP，官方WP：[USTC-Hackergame/hackergame2021-writeups: 中国科学技术大学第八届信息安全大赛的官方与非官方题解 (github.com)](https://github.com/USTC-Hackergame/hackergame2021-writeups)。个人战绩如下：

![image-20211103144007966](assets/image-20211103144007966.png)

[TOC]

## 签到

打开题目，是一个flag的日记，有显示时间，传入参数为`?page=`。通过简单调整参数发现表示的是秒数，从1970.1.1 8:00向后加。题目要求调到比赛时间，通过简单数学计算即可实现。

>   后来了解到这是Linux的时间戳，可以使用一些在线工具进行解答

![image-20211103165715029](assets/image-20211103165715029.png)

## 进制十六——参上

题目给出一个带有十六进制数据的flag文件，明文flag被处理遮挡住了，但是16进制的数据并未被遮挡。定位 f 对应的 ASCII-Hex 编码为66，向后一一解码 Hex 即可。

![hex_editor](assets/hex_editor.png)

## 去吧！追寻自由的电波

题目给出一个变调加速后的MP3文件，能够模糊听出“alpha beta”之类的单词，同时题目提示“考虑到信息的鲁棒性，X 同学使用了无线电中惯用的方法来区分字符串中读音相近的字母。”猜测使用 [NATO phonetic alphabet - Wikipedia](https://en.wikipedia.org/wiki/NATO_phonetic_alphabet) 读法朗读flag内容的字母。

这里笔者没有安装处理音频的软件，采用在线的一个浏览器插件解决。载入文件后直接调节速度即可，此插件自动变调减速音频。如果使用播放器进行低速播放还是会听到非常明显的小黄人音效，而且根本听不清，是因为播放器是不会对原本音频变调处理的，只做速度上的减速。

>   NATO phonetic alphabet 在众多战争类游戏中也有出现，比如战地五在夺取基地C时旁白播报：Take the objective Charlie. 

![image-20211103171404165](assets/image-20211103171404165.png)

![image-20211103171656102](assets/image-20211103171656102.png)

## 猫咪问答 Pro Max

猫咪问答，典型折磨题。题目答案都可以从互联网上找到，但是需要一些搜索技巧才能快速准确地找到答案。

1.   题目要求找到已经被并入中科大 Linux 用户协会（USTCLUG）的中科大信息安全俱乐部（SEC@USTC）的社团章程。题目给出了信息安全俱乐部以前的域名，想必是和这个有关。一开始尝试谷歌搜索几个关键字：“中科大信息安全俱乐部”，“章程”，“会员代表大会”，但都没有结果。域名无法打开，尝试寻找历史IP，也是无功而返。最后在好友的提醒下想到使用搜索引擎快照进行解决。[Wayback Machine (archive.org)](https://web.archive.org/) 通过网址输入域名查询历史快照，在快照首页找到章程。
2.   在 [中国科学技术大学 Linux 用户协会 - LUG @ USTC](https://lug.ustc.edu.cn/wiki/intro/) 首页即可找到评为五星社团的次数。“并于 2015 年 5 月、2017 年 7 月、2018 年 9 月、2019 年 8 月、2020 年 9 月及 2021 年 9 月被评为中国科学技术大学五星级学生社团。” 题目条件限制为近五年，因此舍去2015年那次
3.   找活动室门口牌子的字。既然题目明确表明不需要进入校园即可得到答案，依然搜索关键字：“中科大”，“西区”，“图书馆”。找到图片来源于 [西区图书馆新活动室启用 - USTC LUG](https://news.ustclug.org/2016/06/new-activity-room-in-west-library/) 的历史活动照片，高清无码。
4.   论文数据集查找。谷歌搜索论文，找到公开的源文件后稍微读一下论文内容即可知道答案。（或者直接根据图片数量猜测）
5.   RFC举报机制。搜索相关关键字即可找到 [官方文档](https://www.rfc-editor.org/rfc/rfc8962.txt) 中第六节有明确指出应该发向哪里。

## 卖瓜

通过6斤的瓜和9斤的瓜称出20斤，小学生都知道是称不出来的。这题有点脑筋急转弯的感觉。一开始尝试浮点数绕过，科学计数法等等操作，结果都以失败告终。但是在尝试科学计数法的时候不小心数字整大了没清零，瓜的显示直接变成浮点数了。猜测可能有溢出，溢出成负数再慢慢加回来。经过尝试，如图，正好在这个条件下的负数可以直接使用6斤的瓜称够20斤。

![image-20211103173402531](assets/image-20211103173402531.png)

![image-20211103173652547](assets/image-20211103173652547.png)

## 透明的文件

题目提示说文件是用来在终端生成五颜六色的flag。但是打开文件是一堆很奇怪的字符，有点像乱码。文件中找来找去找不到任何有关flag的线索，猜测是展示出flag并非直接在文中显示。搜索发现了一个[CSDN](https://blog.csdn.net/u014470361/article/details/81512330)的相关介绍，但是并没有说明为什么这样就能显示彩色字体，按照文中的格式，把每个 `[` 前面都加上 `\033` 并且分行， `[XXm` 为表示的颜色字符的结尾标识部分，使用简单的shell脚本打印所有行即可。

```shell
#!/bin/bash
for line in `cat transparent.txt`
do
    echo -e "$line"
done
```

>   后来查到终端显示彩色字符源于一个叫 [ANSI escape code](https://en.wikipedia.org/wiki/ANSI_escape_code) 的东西，终端把那些“奇怪”的字符序列解释为相应的指令，而不是普通字符编码。

![image-20211103200311283](assets/image-20211103200311283.png)

![image-20211103201003986](assets/image-20211103201003986.png)

## 旅行照片

这是个非常有趣的题目，题目提示没有隐写等各种奇技淫巧，就是直接答题。观察图片，题目提示左上角是一个KFC（不说我都没看到）。直接搜索蓝色KFC相关资料，查到是一个在秦皇岛的一处景点，新奥海地世界。谷歌地图查看位置，发现在图上方有一个类似港口的地方，结合地图确定拍摄者大概位置为13~15层，以及拍摄时间约为下午的3~4点，朝向东南。然后可以通过KFC官方渠道找到门店电话（或者美团什么的），至于KFC旁边的三个字可以通过这个店在地图上标注的具体位置猜测，地图的位置是...秦皇岛市...海豚馆旁。猜测是海豚馆。但是本人是找到了在停车场拍照的正门照片（忘记保存），旁边确实是海豚馆。

![img](assets/travel-photo.jpg)

![image-20211103201850335](assets/image-20211103201850335.png)

## FLAG 助力大红包

~~拼多多砍一刀拿flag~~ （bushi。题目要求通过不同IP访问平台砍一刀，但是每个/8地址只允许有一个IP参与砍。直接Python写脚本使用 `X-Forward-For` 伪造IP访问，当所有/8地址访问完之后就可以拿到flag。

```python
import requests
from time import sleep


url = 'URL'
ip = '.0.0.1'
headers = {'X-Forwarded-For':ip}
data = {'ip':ip}
proxies = {'http':'http://127.0.0.1:8080'} # 本地Burp监听，自己测试是否访问成功

 
for i in range (256):
	ip = '.0.0.1'
	ip = str(i) + ip
	print(ip)
	headers = {'X-Forwarded-For':ip}
	data = {'ip':ip}
	proxies = {'http':'http://127.0.0.1:8080'}
	req = requests.post(url, headers=headers, data=data, proxies=proxies)
	sleep(1)
```

## Amnesia

**轻度失忆**

题目使编译后 ELF 文件的 `.data` 和 `.rodata` 段会被清零。ELF文件中代码部分会放到 `.text` 段中，只读数据，或者不变的字符会放到 `.rodata` 段中（注意，`print` 中直接写入的字符串也会放到 `.rodata` 段中），初始化的全局变量会放到 `.data` 段中。因此使用 `print` 函数是行不通的，换一种方法，比如 `putchar();` 答案就出来了。

```c
int main()
{

    // prints hello world
    putchar('H');
    putchar('e');
    putchar('l');
    putchar('l');
    putchar('o');
    putchar(' ');
    putchar('W');
    putchar('o');
    putchar('r');
    putchar('l');
    putchar('d');

    return 0;
}
```

## 图之上的信息

搜索GraphQL相关资料以及其基础的使用和语法。参考 [Threezh1'Blog](https://threezh1.com/2020/05/24/GraphQL漏洞笔记及案例/) 和 [P神的PPT](https://xzfile.aliyuncs.com/upload/zcon/2018/7_攻击GraphQL_phithon.pdf) 即可完成题目。GraphQL实际上的查询模式与其他数据库都是大同小异，都有显而易见的基本特征。利用内省查看所有可用字段：

```
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

然后通过返回的数据直接利用payload完成攻击：

```
{"query":"{ user(id:1) { privateEmail }}"}
```

![image-20211103205326244](assets/image-20211103205326244.png)

## Easy RSA

参考：[RSA加密算法](https://zh.wikipedia.org/wiki/RSA加密演算法) [模逆元](https://zh.wikipedia.org/wiki/模反元素) [欧拉函数](https://zh.wikipedia.org/wiki/欧拉函数) [Python实现密码学中的模逆运算](https://blog.csdn.net/qq2539879928/article/details/106861935) [Compute n! under modulo p - GeeksforGeeks](https://www.geeksforgeeks.org/compute-n-under-modulo-p/)

**求 $p$**

利用[Wilson's theorem - Wikipedia](https://en.wikipedia.org/wiki/Wilson's_theorem) 即可快速求出大数的的余数，尤其是当有阶乘存在的时候，参考代码： [Compute n! under modulo p - GeeksforGeeks](https://www.geeksforgeeks.org/compute-n-under-modulo-p/)。**注意别忘记最后是求出数字的下一个质数。**

**求 $q$**

$q$ 是顶级套娃，$q$ 也被加了一层RSA，但是对q加密的RSA使用了一个由多个质数相乘得到的 $N$ 。通过代码注释中给出的 `value[-1]` 便可以很容易得到整个列表数据。再通过欧拉函数作用于 $N$ 得到 $r$ ，再求 $e$ 关于 $r$ 的模逆元即可得到 $d$ 。此时就有公钥 $(N,e)$ 和私钥 $(N,d)$ 。即可进行解密操作。**注意别忘记最后是求出数字的下一个质数。**

```python
import math
import sympy
from Crypto.Util.number import *

e = 65537


# Getting p
def power(x, y, p):
    res = 1;  # Initialize result
    x = x % p;  # Update x if it is more
    # than or equal to p
    while (y > 0):

        # If y is odd, multiply
        # x with result
        if (y & 1):
            res = (res * x) % p;

        # y must be even now
        y = y >> 1;  # y = y/2
        x = (x * x) % p;

    return res


# Function to find modular inverse
# of a under modulo p using Fermat's
# method. Assumption: p is prime
def modInverse(a, p):
    return power(a, p - 2, p)


# Returns n! % p using
# Wilson's Theorem
def modFact(n, p):
    # n! % p is 0 if n >= p
    if (p <= n):
        return 0

    # Initialize result as (p-1)!
    # which is -1 or (p-1)
    res = (p - 1)

    # Multiply modulo inverse of
    # all numbers from (n+1) to p
    for i in range(n + 1, p):
        res = (res * modInverse(i, p)) % p
    return res


def get_p():
    x = 11124440021748127159092076861405454814981575144744508857178576572929321435002942998531420985771090167262256877805902135304112271641074498386662361391760451
    y = 11124440021748127159092076861405454814981575144744508857178576572929321435002942998531420985771090167262256877805902135304112271641074498386662361391661439
    p = sympy.nextprime(modFact(y, x))
    return p


# Getting q
# 要定义这个运算，需要三个整数。a的模逆元素（对n取模）为b，意味着a*b mod m=1，则称a关于m的模逆为b
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


# 定义一个函数，参数分别为a,n，返回值为b
def findModReverse(a, m):  # 这个扩展欧几里得算法求模逆

    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def get_q():
    value = [80096058210213458444437404275177554701604739094679033012396452382975889905967]
    for i in range(1, 10):
        value.append(sympy.prevprime(value[i - 1]))

    # Euler's totient function
    r = 1
    n = 1
    for i in range(10):
        r = r * (value[i] - 1)
        n = n * value[i]

    # Modular multiplicative inverse
    d = findModReverse(e, r)

    cipher_q = 5591130088089053683141520294620171646179623062803708281023766040254675625012293743465254007970358536660934858789388093688621793201658889399155357407224541324547522479617669812322262372851929223461622559971534394847970366311206823328200747893961649255426063204482192349202005330622561575868946656570678176047822163692259375233925446556338917358118222905050574458037965803154233167594946713038301249145097770337253930655681648299249481985768272321820718607757023350742647019762122572886601905212830744868048802864679734428398229280780215896045509020793530842541217790352661324630048261329493088812057300480085895399922301827190211956061083460036781018660201163819104150988531352228650991733072010425499238731811243310625701946882701082178190402011133439065106720309788819
    q = sympy.nextprime(pow(cipher_q, d, n))
    return q


p = get_p()
q = get_q()
n = p * q
r = (p-1) * (q-1)
d = findModReverse(e, r)
c = 110644875422336073350488613774418819991169603750711465190260581119043921549811353108399064284589038384540018965816137286856268590507418636799746759551009749004176545414118128330198437101472882906564195341277423007542422286760940374859966152871273887950174522820162832774361714668826122465471705166574184367478
m = pow(c, d, n)
m = m.to_bytes(28, 'big')
print(m.decode())
```

## 加密的 U 盘

题目给出两个U盘文件，一个是第一天的，已知密码挂载即可打开。一个是第二天的，说是设置了“随机生成的强密码”。这里打引号是因为我们根本不需要破解所谓的强密码。根据 [Linux Unified Key Setup - Wikipedia](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) 给出的外链参考 [FrequentlyAskedQuestions · Wiki · cryptsetup / cryptsetup · GitLab](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/FrequentlyAskedQuestions) 写到：

>   CLONING/IMAGING: If you clone or image a LUKS container, you make a copy of the LUKS header and the master key will stay the same!  That means that if you distribute an image to several machines, the same master key will be used on all of them, regardless of whether you change the passphrases.  Do NOT do this!  If you do, a root-user on any of the machines with a mapped (decrypted) container or a passphrase on that machine can decrypt all other copies, breaking security.  See also Item 6.15.

通过 [How to decrypt LUKS with the known master key? - Unix & Linux Stack Exchange](https://unix.stackexchange.com/questions/119803/how-to-decrypt-luks-with-the-known-master-key) 的利用方法，导出第一天硬盘镜像的 `master-key` 文件，再用这个 `master-key` 去打开第二天的硬盘即可。

## 赛博厨房

**Level 0**

Level 0 甚至可以用来做签到题目，只需要基础的编程思想就可以按照指令一步步做出来，毕竟才两个材料。（没有特别多人做出来很可能是因为看到总分600分怕了，以为是一道题）

**Level 1**

有过指令集等相关知识的一看题目便知道这是使用循环，当不满足条件时向上跳转，直到满足条件。

```
向右 1 步
拿起 100 个物品
向左 1 步
向下 1 步
放下 1 个物品
如果手上的物品大于等于 0 向上跳转 1 行
```

## minecRaft

这题其实是披着web的皮，戴着crytpo手套的reverse狼。为什么这么说呢，打开web游戏的源代码，可以看到 JS 中打开所有三盏灯的关键部分是一个叫 `gyflagh()` 的函数。这个函数在 flag.js 里面，同样使用谷歌浏览器开发工具即可找到并以漂亮的代码格式整理好展示。

```javascript
if(cinput.length>=32){
	let tbool=gyflagh(cinput.join(''));
	if(tbool) {
		pressplateList[65].TurnOn_redstone_lamp();
		content.innerText='Congratulations!!!';
		return;
	}
	cinput.length=0;
}
```

但是，flag.js 的代码是过了混淆的，根据格式来看很可能是 javascript-obfuscator 混淆后生成的代码，多创建了一个字典函数，所有函数执行都是先通过字典函数还原之后再执行。通过 [JS NICE: Statistical renaming, Type inference and Deobfuscation](http://jsnice.org/) 能够一定程度上缓解混淆。

```javascript
function _0x381b() {
  const _0x4af9ee = ["encrypt", "33MGcQht", "6fbde674819a59bfa12092565b4ca2a7a11dc670c678681daf4afb6704b82f0c", "14021KbbewD", "charCodeAt", "808heYYJt", "5DlyrGX", "552oZzIQH", "fromCharCode", "356IjESGA", "784713mdLTBv", "2529060PvKScd", "805548mjjthm", "844848vFCypf", "4bIkkcJ", "1356853149054377", "length", "slice", "1720848ZSQDkr"];
  /**
   * @return {?}
   */
  _0x381b = function() {
    return _0x4af9ee;
  };
  return _0x381b();
}
function _0x2c9e(_0x49e6ff, _0x310d40) {
    const _0x381b4c = _0x381b();
    return _0x2c9e = function(_0x2c9ec6, _0x2ec3bd) {
        _0x2c9ec6 = _0x2c9ec6 - 0x1a6;
        let _0x4769df = _0x381b4c[_0x2c9ec6];
        return _0x4769df;
    }
    ,
    _0x2c9e(_0x49e6ff, _0x310d40);
}
```

细读代码之后可以发现，关键的加密代码是这个，并且通过谷歌浏览器调试也可以发现这个函数名是 encrypt。使用方式为 `String<type>.encrypt(seed)` 。而encrypted函数中关键的函数就是 `code()` 这个才是主要的加密功能的函数。反混淆之后的 `code()` 函数如下：

```javascript
function code(p, q) {
  const time = 2654435769;
  const constrain = time * 32;
  let i = 0;
  while (i != constrain;) {
    p[0] = p[0] + ((p[1] << 4 ^ p[1] >>> 5) + p[1] ^ i + q[i & 3]);
    i = i + time;
    p[1] = p[1] + ((p[0] << 4 ^ p[0] >>> 5) + p[0] ^ i + q[i >>> 11 & 3]);
  }
  p[0] = p[0];
  p[1] = p[1];
}
```

可以看到这个过程很像一个对称式加密，其中密钥的部分是恒定的，可以通过调试手段从混淆函数中找到，因此非常容易反解出来，以此为依据撰写他的解密函数 `decode()` ，函数如下：

```javascript
function decode(p, q) {
  const time = 2654435769;
  const constrain = time * 32;
  let i = constrain;
  while (i != 0) {
    p[1] = p[1] - ((p[0] << 4 ^ p[0] >>> 5) + p[0] ^ i + q[i >>> 11 & 3]);
    i = i - time;
    p[0] = p[0] - ((p[1] << 4 ^ p[1] >>> 5) + p[1] ^ i + q[i & 3]);
  }
  p[0] = p[0];
  p[1] = p[1];
}
```

同样的，逆向分解加密后的一长串字符串，并逐一解密即可，完整EXP代码如下，此代码可以直接放到浏览器调试窗口运行即可。

```javascript
cipher = '6fbde674819a59bfa12092565b4ca2a7a11dc670c678681daf4afb6704b82f0c';
seed = '1356853149054377';
output = 'flag{';
for (i = 0; i < 4; i++) {
    q[i] = Str4ToLong(seed.slice(i * 4, (i + 1) * 4));
}
for (i = 0; i < cipher.length; i = i + 16) {
    p[0] = Base16ToLong(cipher.slice(i, i + 8));
    p[1] = Base16ToLong(cipher.slice(i + 8, i + 16));
    decode(p, q);
    output = output + LongToStr4(p[0]) + LongToStr4(p[1]);
    p = [];
}
output = output + '}';
console.log(output);
```

