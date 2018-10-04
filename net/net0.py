#!/usr/bin/env python

import re
from pwn import *

def conn(ipAddr):
    s = remote(ipAddr, 2999)
    res = s.recv()
    pattern = r'send \'(.*)\' as'
    match = re.search(pattern, res)
    uInt = match.group(1).rstrip()
    uInt = int(uInt)
    wanted = p32(uInt)
    s.send(wanted + "\r")
    print(s.recv())
    s.close()

if len(sys.argv) < 2:
    print("usage: %s <ipAddr>")

else:
    conn(sys.argv[1])
