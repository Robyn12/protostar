#!/usr/bin/env python

from pwn import *

def conn(ipAddr):
    s = remote(ipAddr, 2998)
    u = make_unpacker(32, endian='little', sign='unsigned')
    res = s.recv().rstrip()
    res = int(u(res))
    print(res)
    s.send(str(res) + "\n")
    print(s.recv())
    s.close()

if len(sys.argv) < 2:
    print("usage: %s <ipAddr>")

else:
    conn(sys.argv[1])
