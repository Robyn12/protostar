#!/usr/bin/env python

from pwn import *

def up(bString):
    u = make_unpacker(32, endian='little', sign='unsigned')
    return int(u(bString))

def conn(ipAddr):
    s = remote(ipAddr, 2997)
    res = s.recv().rstrip()
    print(len(res))
    iArr = [ up(res[0:4]), up(res[4:8]), up(res[8:12]), up(res[12:16]) ]
    result = 0
    for i in iArr:
        result += i
    
    s.send(p32(result) + "\n")
    print(s.recv())
    s.close()

if len(sys.argv) < 2:
    print("usage: %s <ipAddr>")

else:
    conn(sys.argv[1])
