#!/usr/bin/env python3
import pwn

if __name__ == '__main__':
    server = "140.113.24.241"
    port   = 30170
    conn   = pwn.remote(server, port)

    conn.recv().decode("utf-8")
    conn.sendline(b'1')
    conn.recvline().decode("utf-8")
    conn.sendline(b'3000')

    print(conn.recvline().decode("utf-8"), end = "")
    print(conn.recvline().decode("utf-8"), end = "")
