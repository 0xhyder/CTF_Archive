#!/usr/bin/env python3

from pwn import *

elf = ELF("./uc_patched")
libc = ELF('libc-2.24.so')
context.binary = elf
context.terminal = ['kitty','-e']

gdbscript = '''
b*main
c
'''

if args.REMOTE:
	p = remote('litctf.org',31779)
elif args.GDB:
	p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
	p = process(elf.path)



p.interactive()

