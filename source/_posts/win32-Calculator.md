---
title: win32 Calculator
date: 2022-01-07 15:07:00
category: Project Writeup
tags: 
    - Spark Program
---

## Challenge Description

difficulty: medium
type: basic
make the calulator in your system 1+1=3.

## Skills 
Reverse Engineering
Hooking
Tracing
Debugging

## Tools

Disasmbler + Decompiler : IDA Pro/Ghidra
Debugger: windbg/ollydbg/gdb
Tracer/hook: frida

## Keywords
frida hook
ida pro

## Write up

采用的是Win7的 win32calc.exe 作为逆向对象，没有采用Win10自带计算器主要是因为它的可执行文件和进程文件不是一个，不太好进行静态分析（不知道怎么进行操作）。Win10计算器已经开源：https://github.com/microsoft/calculator

### Static Analysis

用管理员权限打开IDA，直接在System32文件夹下打开win32calc.exe文件进行静态分析（管理员权限为了后期能够动态调试，纯静态调试可以把exe文件复制到工作目录）。IDA会自动从Microsoft官方地址下载相关的Symbol Table，所以在逆向这个文件时大部分函数都是有名字的，大大加速了逆向进度，同时也抛出疑问：

>   如果计算器没有符号(这个时候函数名都无了)，该怎样搞？

对着函数列表一通找，由于命名足够合理，很容易猜测函数的目的是什么，并且还有相关前缀，例如`CCalcEngine`，`CCalcHistory`，`CcalculatorController`等。现在就需要开始想一想要完成1+1=3这个任务的条件是什么了。当按下1+1=这几个按键时会调用很多不同的函数（在动态调试的时候稍微留意了一下），比如接受按键类型的函数，运算函数，运算结果显示函数。在一整条调用链里的任何一个地方都可以进行修改。

是在一开始过滤了其他不相关函数直接留下了`DoOperation`函数，猜测可能存在运算。在F5反汇编后一系列的过滤和调用更加证实了猜想很可能是正确的。

![image-20220109120553100](assets/image-20220109120553100.png)

### Debugging

在函数开头位置下断点，用IDA内选择Windbg动态调试计算器，结果果然像之前猜想的那样停在了断点处。说明这个函数确实是在调用链之中。

![image-20220109121215992](assets/image-20220109121215992-16502356803191.png)

之后进行单步调试，看看在函数内部发生了什么。在过完一系列的if-else之后调用了一个叫`addrat`的函数（看起来就很像加法函数Doge）。F7进入函数内部瞧瞧发现它调用了`addnum`函数，`addnum`函数调用了`_addnum`函数，这更像加法函数了！多调试几次可以发现如果使用乘法会调用`mulrat`函数，以此类推。由此可以大概猜测函数调用链如下：

按下等号-->调用`DoOperation`确定算数方法和内容-->调用相关算数函数-->给系统做交互最终显示在屏幕上。

![image-20220109121358078](assets/image-20220109121358078.png)

既然DoOperation函如其名，那么需要计算的数字肯定通过传参或者某种方式传了进去。在一开始下断点的位置函数刚刚开始运行，猜测传参可能是和需要计算的值相关。传参有三个，int，**（指针的指针），\*（指针）。

![image-20220109141132268](assets/image-20220109141132268.png)

经过多次测试，发现int是个常数，不管输入数值如何都是不会变的。因此直接去内存中找这两个指针所指的地址。如图所示为参数a4所指的值，右边8byte的区域就是输入计算的数值了，完成任务只需要去篡改内存即可。

关于这里为什么指针指的是前面部分而不是直接指向数值（一开始还找了好久找不到输入的数字去哪了），猜测可能是计算器支持多种计算方式还有科学计数法，用其他的一些方式表示数字。

![image-20220109141437411](assets/image-20220109141437411.png)

### Hooking

了解了函数调用链后便可以用frida-trace去hook关键的DoOperation函数了，位置就选在Debugging时下断点的地方，算好偏移地址，启动计算器。

```powershell
> frida-trace -f C:\Windows\System32\win32calc.exe --decorate -a "win32calc.exe!0x4753c"
```

frida-trace不会中断程序运行，但是在终端可以看到打印一行字。每当按下=号进行运算时，终端就会打印，说明位置应该是没有问题的。

![image-20220109122803673](assets/image-20220109122803673.png)

frida-trace会在当前文件夹下生成`__handlers__`文件夹，里面储存着需要hook函数的js文件，更改此文件中的内容即可对函数进行操作。像之前说的，直接篡改相应的内存地址即可。这里直接拿出最终exp（注释内容为调试所需，dump内存之类的）：

```javascript
onEnter(log, args, state) {
    // frida-trace -f C:\Windows\System32\win32calc.exe --decorate -a "win32calc.exe!0x4753c"
    log('sub_4753c() [win32calc.exe]');
    // **R8, *R9
    var R8 = ptr(args[2]);
    var R9 = ptr(args[3]);
    // log(R8);
    // log(R9);

    var oldValR9 = R9.readPointer().add("0xc");
    // log(oldValR9);
    // log(hexdump(oldValR9, {
    // offset: 0,
    // length: 32,
    // header: true,
    // ansi: true
    // })); 

    var newValR9 = oldValR9.writePointer(ptr("0x02"));
    // log(hexdump(oldValR9, {
    // offset: 0,
    // length: 32,
    // header: true,
    // ansi: true
    // })); 
}
```

再次运行命令后就会发现1+1=3了，成果展示：

![ezgif.com-gif-maker](assets/ezgif.com-gif-maker.gif)

### Reference

https://frida.re/docs/frida-trace/

https://frida.re/docs/javascript-api/

https://github.com/win32calc/win32calc/releases

https://tianyu-code.top/%E6%B1%87%E7%BC%96/%E5%AF%84%E5%AD%98%E5%99%A8%E4%BB%8B%E7%BB%8D/

https://zhuanlan.zhihu.com/p/53394807