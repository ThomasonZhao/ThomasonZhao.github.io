---
title: Win10 UWP Calculator
date: 2022-04-17 22:31:00
tags: Spark Program
category: Reverse
---

**Goals:** 

*   Make the win10 UWP calculator 1+1=3
*   Reverse engineering the win10 UWP calculator, understand all (at least most) functionalities. 

## What is UWP?

**Universal Windows Platform** (**UWP**) is a [computing platform](https://en.wikipedia.org/wiki/Computing_platform) created by [Microsoft](https://en.wikipedia.org/wiki/Microsoft) and first introduced in [Windows 10](https://en.wikipedia.org/wiki/Windows_10). The purpose of this platform is to help develop [universal apps](https://en.wikipedia.org/wiki/Universal_app) that run on Windows 10, [Windows 10 Mobile](https://en.wikipedia.org/wiki/Windows_10_Mobile), [Windows 11](https://en.wikipedia.org/wiki/Windows_11), [Xbox One](https://en.wikipedia.org/wiki/Xbox_system_software), [Xbox Series X/S](https://en.wikipedia.org/wiki/Xbox_system_software) and [HoloLens](https://en.wikipedia.org/wiki/Microsoft_HoloLens) without the need to be [rewritten for each](https://en.wikipedia.org/wiki/Porting). It supports [Windows](https://en.wikipedia.org/wiki/Microsoft_Windows) app development using [C++](https://en.wikipedia.org/wiki/C%2B%2B), [C#](https://en.wikipedia.org/wiki/C_Sharp_(programming_language)), [VB.NET](https://en.wikipedia.org/wiki/VB.NET), and [XAML](https://en.wikipedia.org/wiki/XAML). The [API](https://en.wikipedia.org/wiki/Application_programming_interface) is implemented in C++, and supported in C++, VB.NET, C#, [F#](https://en.wikipedia.org/wiki/F_Sharp_(programming_language)) and [JavaScript](https://en.wikipedia.org/wiki/JavaScript).[[1\]](https://en.wikipedia.org/wiki/Universal_Windows_Platform#cite_note-MicrosoftWhatIs-1) Designed as an extension to the [Windows Runtime (WinRT)](https://en.wikipedia.org/wiki/Windows_Runtime) platform first introduced in [Windows Server 2012](https://en.wikipedia.org/wiki/Windows_Server_2012) and [Windows 8](https://en.wikipedia.org/wiki/Windows_8), UWP allows developers to create apps that will potentially run on multiple types of devices. (From Wikipedia)

UWP application usually installed under the directory of `C:\Program Files\windowsapp`. Usually, users, even administrator, don't have the permission of editing the files under that directory. 

## Dynamic Analysis Based on Data Flow

### Anchor in the memory

Set the calculation result to a wired number, suppose they are store in somewhere in the memory in hex format (experience from win32 calc), break the program by windbg and search through the memory to see where it is. The result might be complicate, but after identified some key characteristics of the data, only a few of them "might" be the correct value we want. Here I use "yy" in ascii form and 31097 for decimal value to test the memory. 

```windbg
s -a 0 L?fffffffffff "yy"
or
s -q 0 L?fffffffffff 0x00007979
```

![image-20220403154256266](assets/image-20220403154256266.png)

Then, assign them with different value in the memory and continue run the calculator. Base on different value we assigned to them, we can easily identify which memory location is the real one. 31097 + 1 will never results 31105, therefore, we found the correct memory location. 

```windbg
ed 0000014a`91a83bd0 0000000000007980
```

![image-20220403154645935](assets/image-20220403154645935.png)

### Who touches my anchor?

Set up breakpoint on that memory location when any code read it.

```windbg
ba r 2 0000014a`91a83bd0
```

Then when the calculator is running and hitting the **"+" button**, the program hit the break point with stack organization (also the control flow) shown as below. 

![Snipaste_2022-04-03_15-25-07](assets/Snipaste_2022-04-03_15-25-07.png)

The current function call is in the library(like "printf" function for c code in stdio.h), ignore that. Step out the current function and examine the code. 

![image-20220403161157003](assets/image-20220403161157003.png)

Locate it in the IDA, combine the dynamic analysis stack contents, the \*\*a1 is a double pointer of one of the number we want to add. We guess that \*\*a2 **could be** another double pointer which points to the number we want to add (Not add yet, this breakpoint happened just after we push the button "+") 

![image-20220403161439426](assets/image-20220403161439426.png)

The whole control flow is shown in the below:

![image-20220403170537010](assets/image-20220403170537010.png)

After figure out the control flow of the "+" button, another button will also cause the break point, **"=" button**. Using same idea, drag out the control flow of the "=" button. 

![image-20220403171802888](assets/image-20220403171802888.png)

It is worth noting that this function manipulates both input we use to add the number. 

![image-20220403172531763](assets/image-20220403172531763.png)

It get called under this function. 

![image-20220403172904998](assets/image-20220403172904998.png)

Until now, we have discovered a lot about the "+" and "=" buttons, let's move on to the static analysis part. 

## Static Analysis

Two important functions are: sub_140239270 and sub_140222AE0 do not have any sign to do the addition. Rather, sub_140239270 place space for both numbers we want to add. sub_140222AE0 returns an array with both pointers pointing to the numbers we want to add. 

So the addition will appear in higher level functions. 

What's more, sub_140222AE0 was found always to be called in pairs. It is reasonable to speculate that other functions are likely to be other operators (addition, subtraction, multiplication, division, ..., etc)

![image-20220417165207231](assets/image-20220417165207231.png)

The caller function of sub_140222AE0.  

![image-20220417165724038](assets/image-20220417165724038.png)

Just after two sub_140222AE0 function calls, sub_140233050 do the addition. It updates the pointer in the v13, which stores the new value after the addition. With this information, the challenge will be solved soon. 

![image-20220417173049009](assets/image-20220417173049009.png)

## Hook

Originally will use frida to hook the function, but it has some bug when attach to the UWP calculator. So I decide to use windbg scripting instead. 

After search for the windbg scripting, the search results shows that windbg can be script using JavaScript files. 

```windbg
dx Debugger.State.Scripts.EXP.Contents.EXP(2)
```

```javascript
"use strict";

function initializeScript()
{
    host.diagnostics.debugLog("EXP is ready!\n");
}

function EXP(num)
{
    var ctl = host.namespace.Debugger.Utility.Control;
    host.diagnostics.debugLog("Setting up EXP!\n");
    ctl.ExecuteCommand("bp Calculator!VSDesignerDllMain+0xda1ac");
    ctl.ExecuteCommand("g");
    ctl.ExecuteCommand("eb qwo(@rsi)+0xc 0x3");
    ctl.ExecuteCommand("bd 0");
    ctl.ExecuteCommand("g");
    host.diagnostics.debugLog("Finished!\n");
}
```

## Achievement display

![Source image](assets/ezgif-1-4818e84a2a.gif)

## Thanks

Atum

Tencent Spark Program

## References

[【原创】去一个小广告-软件逆向-看雪论坛-安全社区](https://bbs.pediy.com/thread-246657-1.htm)

[UWP逆向初接触 | l1nk3dHouse (showlinkroom.me)](http://showlinkroom.me/2017/05/31/UWP逆向初接触/)

[(1/2) 为了理解 UWP 的启动流程，我从零开始创建了一个 UWP 程序 - walterlv](https://blog.walterlv.com/post/create-uwp-app-from-zero-0.html)

[(2/2) 为了理解 UWP 的启动流程，我从零开始创建了一个 UWP 程序 - walterlv](https://blog.walterlv.com/post/create-uwp-app-from-zero-1.html)

[NaniteFactory/hookwin10calc: Reverse engineered Windows 10 Calculator.exe (UWP application) hacker. 한글/漢文을 배운 윈도우 계산기 패치. (github.com)](https://github.com/NaniteFactory/hookwin10calc)

[Universal Windows Platform - Wikipedia](https://en.wikipedia.org/wiki/Universal_Windows_Platform)

[GDB commands for WinDbg users | Matthew Justice’s blog (mattjustice.com)](https://blog.mattjustice.com/2018/08/24/gdb-for-windbg-users/)

[Common WinDbg Commands (Thematically Grouped)](http://windbg.info/doc/1-common-cmds.html)

---------------------

[s (Search Memory) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/s--search-memory-)

[ba (Break on Access) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ba--break-on-access-)

[e, ea, eb, ed, eD, ef, ep, eq, eu, ew, eza (Enter Values) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/e--ea--eb--ed--ed--ef--ep--eq--eu--ew--eza--ezu--enter-values-)

[x64 calling convention | Microsoft Docs](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)

[MASM Numbers and Operators - Windows drivers | Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/masm-numbers-and-operators?redirectedfrom=MSDN)

[JavaScript Debugger Scripting - Windows drivers | Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/javascript-debugger-scripting)

