---
title: 
date: "2022-03-27"
template: "post"
draft: true
slug: "rev-practical-binary"
category: ""
tags:
  - ""
  - ""
  - ""
description: ""
socialImage: "/media/cards/no-image.png"

---

バイナリ解析の色々に関するメモ書き。

<!-- omit in toc -->

## もくじ



## objdumpのメモ

オプション一覧はこんな感じ。

``` bash
$ objdump -v
GNU objdump (GNU Binutils for Ubuntu) 2.34
Copyright (C) 2020 Free Software Foundation, Inc.
This program is free software; you may redistribute it under the terms of
the GNU General Public License version 3 or (at your option) any later version.
This program has absolutely no warranty.

$ objdump
Usage: objdump <option(s)> <file(s)>
 Display information from object <file(s)>.
 At least one of the following switches must be given:
  -a, --archive-headers    Display archive header information
  -f, --file-headers       Display the contents of the overall file header
  -p, --private-headers    Display object format specific file header contents
  -P, --private=OPT,OPT... Display object format specific contents
  -h, --[section-]headers  Display the contents of the section headers
  -x, --all-headers        Display the contents of all headers
  -d, --disassemble        Display assembler contents of executable sections
  -D, --disassemble-all    Display assembler contents of all sections
      --disassemble=<sym>  Display assembler contents from <sym>
  -S, --source             Intermix source code with disassembly
      --source-comment[=<txt>] Prefix lines of source code with <txt>
  -s, --full-contents      Display the full contents of all sections requested
  -g, --debugging          Display debug information in object file
  -e, --debugging-tags     Display debug information using ctags style
  -G, --stabs              Display (in raw form) any STABS info in the file
  -W[lLiaprmfFsoRtUuTgAckK] or
  --dwarf[=rawline,=decodedline,=info,=abbrev,=pubnames,=aranges,=macro,=frames,
          =frames-interp,=str,=loc,=Ranges,=pubtypes,
          =gdb_index,=trace_info,=trace_abbrev,=trace_aranges,
          =addr,=cu_index,=links,=follow-links]
                           Display DWARF info in the file
  --ctf=SECTION            Display CTF info from SECTION
  -t, --syms               Display the contents of the symbol table(s)
  -T, --dynamic-syms       Display the contents of the dynamic symbol table
  -r, --reloc              Display the relocation entries in the file
  -R, --dynamic-reloc      Display the dynamic relocation entries in the file
  @<file>                  Read options from <file>
  -v, --version            Display this program's version number
  -i, --info               List object formats and architectures supported
  -H, --help               Display this information
  
The following switches are optional:
  -b, --target=BFDNAME           Specify the target object format as BFDNAME
  -m, --architecture=MACHINE     Specify the target architecture as MACHINE
  -j, --section=NAME             Only display information for section NAME
  -M, --disassembler-options=OPT Pass text OPT on to the disassembler
  -EB --endian=big               Assume big endian format when disassembling
  -EL --endian=little            Assume little endian format when disassembling
      --file-start-context       Include context from start of file (with -S)
  -I, --include=DIR              Add DIR to search list for source files
  -l, --line-numbers             Include line numbers and filenames in output
  -F, --file-offsets             Include file offsets when displaying information
  -C, --demangle[=STYLE]         Decode mangled/processed symbol names
                                  The STYLE, if specified, can be `auto', `gnu',
                                  `lucid', `arm', `hp', `edg', `gnu-v3', `java'
                                  or `gnat'
      --recurse-limit            Enable a limit on recursion whilst demangling.  [Default]
      --no-recurse-limit         Disable a limit on recursion whilst demangling
  -w, --wide                     Format output for more than 80 columns
  -z, --disassemble-zeroes       Do not skip blocks of zeroes when disassembling
      --start-address=ADDR       Only process data whose address is >= ADDR
      --stop-address=ADDR        Only process data whose address is < ADDR
      --prefix-addresses         Print complete address alongside disassembly
      --[no-]show-raw-insn       Display hex alongside symbolic disassembly
      --insn-width=WIDTH         Display WIDTH bytes on a single line for -d
      --adjust-vma=OFFSET        Add OFFSET to all displayed section addresses
      --special-syms             Include special symbols in symbol dumps
      --inlines                  Print all inlines for source line (with -l)
      --prefix=PREFIX            Add PREFIX to absolute paths for -S
      --prefix-strip=LEVEL       Strip initial directory names for -S
      --dwarf-depth=N        Do not display DIEs at depth N or greater
      --dwarf-start=N        Display DIEs starting with N, at the same depth
                             or deeper
      --dwarf-check          Make additional dwarf internal consistency checks.
      --ctf-parent=SECTION       Use SECTION as the CTF parent
      --visualize-jumps          Visualize jumps by drawing ASCII art lines
      --visualize-jumps=color    Use colors in the ASCII art
      --visualize-jumps=extended-color   Use extended 8-bit color codes
      --visualize-jumps=off      Disable jump visualization

objdump: supported targets: elf64-x86-64 elf32-i386 elf32-iamcu elf32-x86-64 pei-i386 pei-x86-64 elf64-l1om elf64-k1om elf64-little elf64-big elf32-little elf32-big pe-x86-64 pe-bigobj-x86-64 pe-i386 srec symbolsrec verilog tekhex binary ihex plugin
objdump: supported architectures: i386 i386:x86-64 i386:x64-32 i8086 i386:intel i386:x86-64:intel i386:x64-32:intel i386:nacl i386:x86-64:nacl i386:x64-32:nacl iamcu iamcu:intel l1om l1om:intel k1om k1om:intel

The following i386/x86-64 specific disassembler options are supported for use
with the -M switch (multiple options should be separated by commas):
  x86-64      Disassemble in 64bit mode
  i386        Disassemble in 32bit mode
  i8086       Disassemble in 16bit mode
  att         Display instruction in AT&T syntax
  intel       Display instruction in Intel syntax
  att-mnemonic
              Display instruction in AT&T mnemonic
  intel-mnemonic
              Display instruction in Intel mnemonic
  addr64      Assume 64bit address size
  addr32      Assume 32bit address size
  addr16      Assume 16bit address size
  data32      Assume 32bit data size
  data16      Assume 16bit data size
  suffix      Always display instruction suffix in AT&T syntax
  amd64       Display instruction in AMD64 ISA
  intel64     Display instruction in Intel64 ISA
```

### objdumpによる逆アセンブル

`-M intel`オプションを付けて実行すると、Intel構文で逆アセンブルすることができます。

この出力結果にgrepを行うことで、特定の命令セットを検索することもできます。

``` bash
# 特定の命令セットを検索する場合
objdump -M intel -d binary | egrep "pop\s+rdi"
objdump -M intel -d binary | grep " 5f" -A 1
```

## 特定のセクションのダンプ

`-j`オプションを使うことで、指定したセクションのデータを抽出できます。

以下の例では、`-Sj .rodata`を付けることで、`.rodata`セクションの情報を取得しています。

``` bash
$ objdump -Sj .rodata vuln
vuln:     file format elf32-i386
Disassembly of section .rodata:

080b4000 <_fp_hw>:
 80b4000:       03 00 00 00                                         ....

080b4004 <_IO_stdin_used>:
 80b4004:       01 00 02 00 48 6f 77 20 73 74 72 6f 6e 67 20 69     ....How strong i
 80b4014:       73 20 79 6f 75 72 20 52 4f 50 2d 66 75 3f 20 53     s your ROP-fu? S
 80b4024:       6e 61 74 63 68 20 74 68 65 20 73 68 65 6c 6c 20     natch the shell
 80b4034:       66 72 6f 6d 20 6d 79 20 68 61 6e 64 2c 20 67 72     from my hand, gr
 80b4044:       61 73 73 68 6f 70 70 65 72 21 00 2e 2e 2f 63 73     asshopper!.../cs
 80b4054:       75 2f 6c 69 62 63 2d 73 74 61 72 74 2e 63 00 69     u/libc-start.c.i
 80b4064:       36 38 36 00 69 35 38 36 00 46 41 54 41 4c 3a 20     686.i586.FATAL:
 80b4074:       6b 65 72 6e 65 6c 20 74 6f 6f 20 6f 6c 64 0a 00     kernel too old..
 80b4084:       5f 5f 65 68 64 72 5f 73 74 61 72 74 2e 65 5f 70     __ehdr_start.e_p
 80b4094:       68 65 6e 74 73 69 7a 65 20 3d 3d 20 73 69 7a 65     hentsize == size
 80b40a4:       6f 66 20 2a 47 4c 28 64 6c 5f 70 68 64 72 29 00     of *GL(dl_phdr).
```

## バイト配列

### リトルエンディアンとビッグエンディアンの変換

ビッグエンディアンは左側に先頭バイトがあり、可読性が高いバイナリ形式です。TCP/IPなどではビッグエンディアンが使用されます。

一方、リトルエンディアンはデータの先頭バイトが右側に配置されます。Intel CPUアーキテクチャではこの方式が使用されます。

例えば[pwntools](https://docs.pwntools.com/en/stable/util/packing.html)を使って変換する場合、それぞれ以下のようになります。

``` python
from pwn import *

p32(0x12345678).hex()
# '78563412'
p32(0x12345678, endian='big').hex()
# '12345678'

p64(0x12345678aabbccdd).hex()
# 'ddccbbaa78563412'
p64(0x12345678aabbccdd, endian='big').hex()
# '12345678aabbccdd'
```

参考：[pwnlib.util.packing — Packing and unpacking of strings — pwntools 4.7.0 documentation](https://docs.pwntools.com/en/stable/util/packing.html)

標準ライブラリを使う場合はこんな感じです。

`struct.pack`関数を使って、フォーマットとして`<`を使用する場合はリトルエンディアン、`>`を使用した場合はビッグエンディアンになります。

``` python
from struct import *

struct.pack("<L", 0x12345678).hex()
# '78563412'
struct.pack(">L", 0x12345678).hex()
# '12345678'
```

参考：[struct --- バイト列をパックされたバイナリデータとして解釈する — Python 3.10.0b2 ドキュメント](https://docs.python.org/ja/3/library/struct.html)





``` bash

```





``` bash

```







