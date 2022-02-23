---
title: 
date: "2022-02-20"
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

[はじめてのOSコードリーディング ~UNIX V6で学ぶカーネルのしくみ](https://amzn.to/3q8TU3K)にインスパイアされて[xv6 OS](https://github.com/mit-pdos/xv6-public)を読んでます。

リバースエンジニアリングに強くなりたいのと、カーネルとかOSに詳しくなりたいと思っています。

[詳解 Linuxカーネル](https://amzn.to/3I6fkVt)が結構重かったので、もう少し軽めのところから始めたいと思っていたところ、UNIX V6というOSがトータルで1万行くらいのコード量で、人類でもギリギリ理解できるということを知り、興味を持ちました。

ただ、UNIX V6自体はx86CPUでは動作しないため、基本的には、UNIXv6をX86アーキテクチャで動くようにした[xv6 OS](https://github.com/mit-pdos/xv6-public)のリポジトリをForkした[kash1064/xv6-public: xv6 OS](https://github.com/kash1064/xv6-public)のソースコードを読んでいくことにしました。

[前回](https://yukituna.com/3850/)に引き続きxv6OSのソースコードを読んでいきます。

https://yukituna.com/3850/

前回の記事では、xv6OSのブートストラップのコードを読んで、カーネル本体をロードする手前まで追っていきました。

今回は実際に読み込まれるカーネルの動きを追っていきます。

<!-- omit in toc -->
## もくじ
- [カーネルのロード](#カーネルのロード)
- [カーネルプログラムのビルド](#カーネルプログラムのビルド)
  - [リンカスクリプト](#リンカスクリプト)
  - [リンカスクリプトの構造](#リンカスクリプトの構造)
  - [エントリポイントの定義](#エントリポイントの定義)
  - [SECTIONS：textセクションの定義](#sectionstextセクションの定義)
  - [SECTIONS：rodataセクションの定義](#sectionsrodataセクションの定義)
  - [SECTIONS：stab,stabstrセクションの定義](#sectionsstabstabstrセクションの定義)
  - [SECTIONS：dataセクションの定義](#sectionsdataセクションの定義)
  - [SECTIONS：bssセクションの定義](#sectionsbssセクションの定義)
  - [SECTIONS：DISCARD](#sectionsdiscard)
- [カーネルのエントリポイント](#カーネルのエントリポイント)
  - [マルチブートヘッダ](#マルチブートヘッダ)
  - [エントリポイントの物理アドレスを定義](#エントリポイントの物理アドレスを定義)
  - [カーネルのエントリポイントのロード](#カーネルのエントリポイントのロード)
  - [ページングとは](#ページングとは)
  - [スタックポインタの設定](#スタックポインタの設定)
  - [main関数に移行](#main関数に移行)
- [まとめ](#まとめ)
- [参考書籍](#参考書籍)

## カーネルのロード

ブートストラップの中でカーネルのロードを行っていた箇所を振り返っておきます。

カーネルの読み込みは、以下のようにメモリの`0x10000`番地に読み込まれました。

その後、プログラムヘッダがロードされ、`entry()`関数が呼び出されてカーネルに処理が移行します。

``` c
void bootmain(void)
{
  struct elfhdr *elf;
  struct proghdr *ph, *eph;
  void (*entry)(void);
  uchar* pa;

  elf = (struct elfhdr*)0x10000;  // scratch space

  // Read 1st page off disk
  readseg((uchar*)elf, 4096, 0);

  // Is this an ELF executable?
  if(elf->magic != ELF_MAGIC)
    return;  // let bootasm.S handle error

  // Load each program segment (ignores ph flags).
  ph = (struct proghdr*)((uchar*)elf + elf->phoff);
  eph = ph + elf->phnum;
  for(; ph < eph; ph++){
    pa = (uchar*)ph->paddr;
    readseg(pa, ph->filesz, ph->off);
    if(ph->memsz > ph->filesz)
      stosb(pa + ph->filesz, 0, ph->memsz - ph->filesz);
  }

  // Call the entry point from the ELF header.
  // Does not return!
  entry = (void(*)(void))(elf->entry);
  entry();
}
```

そのため、今回は`entry()`関数を探すところから始めていきたいと思います。

## カーネルプログラムのビルド

カーネルプログラムのビルドの流れを追います。

最終的なイメージファイルである`xv6.img`は、以下のコマンドで生成されていました。

`0x10000`の空領域に`bootblock`と`kernel`を埋め込んだものが`xv6.img`になります。

``` bash
xv6.img: bootblock kernel
	dd if=/dev/zero of=xv6.img count=10000
	dd if=bootblock of=xv6.img conv=notrunc
	dd if=kernel of=xv6.img seek=1 conv=notrunc
```

`bootblock`については前回追ったので、今回は`kernel`を追っていきます。

``` bash
kernel: $(OBJS) entry.o entryother initcode kernel.ld
	$(LD) $(LDFLAGS) -T kernel.ld -o kernel entry.o $(OBJS) -b binary initcode entryother
	$(OBJDUMP) -S kernel > kernel.asm
	$(OBJDUMP) -t kernel | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > kernel.sym
```

`kernel`の依存関係は`$(OBJS) entry.o entryother initcode kernel.ld`になってます。

`$(OBJS)`の一覧は結構数が多いので割愛します。`main.o`など、カーネルのモジュールが含まれます。

下の2行はバイナリの逆アセンブル結果とシンボル情報を出力しているのみで、実際にバイナリを作成しているのは`$(LD) $(LDFLAGS) -T kernel.ld -o kernel entry.o $(OBJS) -b binary initcode entryother`の行です。

`LD`は、前回説明した`GCC`と同じく`$(TOOLPREFIX)ld`の形式で使用されます。

今回はクロスコンパイルは行わないので、普通に`ld`コマンドが実行されます。

``` bash
LD = $(TOOLPREFIX)ld

# FreeBSD ld wants ``elf_i386_fbsd''
LDFLAGS += -m $(shell $(LD) -V | grep elf_i386 2>/dev/null | head -n 1)
```

`LDFLAGS`は、`ld -V`の結果から`elf_i386`を抽出して`-m elf_i386`オプションとして表示させています。

`ld -V`は、`ld`コマンドのバージョン確認コマンドのうち、サポートしているエミュレータの一覧を表示するオプション付きのコマンドです。

実際にビルド時に実行されるコマンドは以下のようになります。

`-T`オプションは`-c`オプションと同じく、リンカスクリプト(`kernel.ld`)からリンクコマンドを読み込むオプションです。

また、`-b`オプションは以降にインプットするオブジェクトファイルのバイナリフォーマットを指定するコマンドで、今回は`binary`を指定しているようです。

以降に続く`initcode`と`entryother`はアセンブリファイルからアセンブルされたバイナリです。

``` bash
ld -m elf_i386 -T kernel.ld -o kernel \
entry.o bio.o console.o exec.o file.o fs.o ide.o ioapic.o kalloc.o kbd.o lapic.o log.o main.o mp.o picirq.o pipe.o proc.o sleeplock.o spinlock.o string.o swtch.o syscall.o sysfile.o sysproc.o trapasm.o trap.o uart.o vectors.o vm.o  \
-b binary initcode entryother
```

参考：[LD、GNUリンカーの使用-オプション](https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_node/ld_3.html)

次にリンカスクリプト`kernel.ld`の中身を見てみます。

### リンカスクリプト

そもそもリンカスクリプトについてですが、リンカがオブジェクトファイルをリンクして実行形式を作成する際に、オブジェクトのメモリ配置を指定するためのファイルです。

通常は、リンカに内臓されているデフォルトのリンカスクリプトが使用されるため、明示的に指定する必要はありません。

ちなみに、リンカに内臓されているデフォルトのリンカスクリプトは`ld`コマンドに`--verbose`オプションを付けると出力できます。

ただし、OSなど組込み系のプログラムの場合は、汎用OSの管理機能が使えないため、リンカスクリプトを独自に設定する必要があります。

参考：[Scripts (LD)](https://sourceware.org/binutils/docs/ld/Scripts.html#Scripts)

参考：[Basic Script Concepts (LD)](https://sourceware.org/binutils/docs/ld/Basic-Script-Concepts.html)

参考：[GNU Cを使いこなそう | 株式会社コンピューテックス](https://www.computex.co.jp/article/use_gcc_1.htm)

xv6OSでカーネルのビルドに使用するリンカスクリプトの全文は以下です。

``` c
/* Simple linker script for the JOS kernel.
   See the GNU ld 'info' manual ("info ld") to learn the syntax. */

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
	/* Link the kernel at this address: "." means the current address */
        /* Must be equal to KERNLINK */
	. = 0x80100000;

	.text : AT(0x100000) {
		*(.text .stub .text.* .gnu.linkonce.t.*)
	}

	PROVIDE(etext = .);	/* Define the 'etext' symbol to this value */

	.rodata : {
		*(.rodata .rodata.* .gnu.linkonce.r.*)
	}

	/* Include debugging information in kernel memory */
	.stab : {
		PROVIDE(__STAB_BEGIN__ = .);
		*(.stab);
		PROVIDE(__STAB_END__ = .);
	}

	.stabstr : {
		PROVIDE(__STABSTR_BEGIN__ = .);
		*(.stabstr);
		PROVIDE(__STABSTR_END__ = .);
	}

	/* Adjust the address for the data segment to the next page */
	. = ALIGN(0x1000);

	/* Conventionally, Unix linkers provide pseudo-symbols
	 * etext, edata, and end, at the end of the text, data, and bss.
	 * For the kernel mapping, we need the address at the beginning
	 * of the data section, but that's not one of the conventional
	 * symbols, because the convention started before there was a
	 * read-only rodata section between text and data. */
	PROVIDE(data = .);

	/* The data segment */
	.data : {
		*(.data)
	}

	PROVIDE(edata = .);

	.bss : {
		*(.bss)
	}

	PROVIDE(end = .);

	/DISCARD/ : {
		*(.eh_frame .note.GNU-stack)
	}
}
```

### リンカスクリプトの構造

リンカスクリプトとして最低限必須となる記述は、`SECTIONS`要素です。

`MEMORY`要素を定義する場合が多いですが、必須ではありません。

`SECTIONS`要素ではセクションを定義し、任意のアドレスに配置します。

このアドレスは、物理アドレスと仮想アドレスのどちらも定義可能です。

参考：[GNU Cを使いこなそう | 株式会社コンピューテックス](https://www.computex.co.jp/article/use_gcc_1.htm)

参考：[リンカスクリプトの書き方](http://blueeyes.sakura.ne.jp/2018/10/31/1676/)

`SECTIONS`要素のみが定義された最も単純なリンカスクリプトは以下の例のようになります。

``` c
SECTIONS
{
  . = 0x10000;
  .text : { *(.text) }
  . = 0x8000000;
  .data : { *(.data) }
  .bss : { *(.bss) }
}
```

参考：[Simple Example (LD)](https://sourceware.org/binutils/docs/ld/Simple-Example.html)

xv6OSのリンカスクリプトでは、以下のセクションが定義されています。

- .text : 実行バイナリが配置される。通常は読み取り/実行権限のみ。
- .rodata : 読み取り専用データが配置される。
- .stab : スタブと呼ばれる固定長構造体の配列が配置される。
- .stabstr : スタブから参照される可変長文字列が配置される。
- .data : 読み書き可能なデータが配置される。
- .bss : ブロック開始記号(宣言されているがまだ値が割り当てられていないオブジェクト)が配置される。

参考：[STABS - Using Stabs in Their Own Sections](https://opensource.apple.com/source/gdb/gdb-292/doc/stabs.html/stabs_13.html)

参考：[STABS: Stab Section Basics](https://doc.ecoscentric.com/gnutools/doc/stabs/Stab-Section-Basics.html)

参考：[.bss - Wikipedia](https://en.wikipedia.org/wiki/.bss)

リンカスクリプトの内容について順に見ていきます。

### エントリポイントの定義

リンカスクリプトの先頭行を見ると、3つの定義がされています。

``` c
/* Simple linker script for the JOS kernel.
   See the GNU ld 'info' manual ("info ld") to learn the syntax. */

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)
```

`OUTPUT_FORMAT`では、出力バイナリのフォーマットを定義しています。

`OUTPUT_ARCH`では、出力されるバイナリがどのアーキテクチャに対応するかを指定しています。

`ENTRY`では、一番初めに実行される関数のシンボル名を指定しています。

参考：[Entry Point (LD)](https://sourceware.org/binutils/docs/ld/Entry-Point.html)

ここで指定されている`_start`は、`entry.S`の中で以下のように定義されています。

``` assembly
# By convention, the _start symbol specifies the ELF entry point.
# Since we haven't set up virtual memory yet, our entry point is
# the physical address of 'entry'.
.globl _start
_start = V2P_WO(entry)

# Entering xv6 on boot processor, with paging off.
.globl entry
entry:
  # Turn on page size extension for 4Mbyte pages
  movl    %cr4, %eax
  orl     $(CR4_PSE), %eax
  movl    %eax, %cr4
  # Set page directory
  movl    $(V2P_WO(entrypgdir)), %eax
  movl    %eax, %cr3
  # Turn on paging.
  movl    %cr0, %eax
  orl     $(CR0_PG|CR0_WP), %eax
  movl    %eax, %cr0

  # Set up the stack pointer.
  movl $(stack + KSTACKSIZE), %esp

  # Jump to main(), and switch to executing at
  # high addresses. The indirect call is needed because
  # the assembler produces a PC-relative instruction
  # for a direct jump.
  mov $main, %eax
  jmp *%eax

.comm stack, KSTACKSIZE
```

`entry.S`の詳細については後述します。

参考：[xv6: OSはどうメモリを参照、管理するのか（前編） - yohei.codes](https://yohei.codes/ja/post/xv6-memory-1/#kernelld)

### SECTIONS：textセクションの定義

まずはtextセクションの定義を行っている箇所を見ていきます。

``` c
/* Link the kernel at this address: "." means the current address */
/* Must be equal to KERNLINK */
. = 0x80100000;

.text : AT(0x100000) {
	*(.text .stub .text.* .gnu.linkonce.t.*)
}

PROVIDE(etext = .);	/* Define the 'etext' symbol to this value */
```

最初の行で定義されている`. = 0x80100000;`では、特殊記号`.`の値を設定します。

これは、ロケーションカウンタとして使用されます。

以降に定義されたセクションは、ロケーションカウンタの指すアドレスから開始されます。

セクションが定義されると、ロケーションカウンタはそのサイズ分インクリメントされます。

参考：[Simple Example (LD)](https://sourceware.org/binutils/docs/ld/Simple-Example.html)

xv6OSでは、ロケーションカウンタの初期値として`0x80100000`が定義されています。

これによって、リンカによって出力されるバイナリの命令アドレスは`0x80100000`から開始されることになります。

セクションの定義は、以下の構造で行われます。

``` c
section [address] [(type)] :
  [AT(lma)]
  [ALIGN(section_align) | ALIGN_WITH_INPUT]
  [SUBALIGN(subsection_align)]
  [constraint]
  {
    output-section-command
    output-section-command
    …
  } [>region] [AT>lma_region] [:phdr :phdr …] [=fillexp] [,]
```

参考：[Output Section Description (LD)](https://sourceware.org/binutils/docs/ld/Output-Section-Description.html)

`AT(0x100000)`は、セクションのロードアドレスを`0x100000`と定義しています。

参考：[Using LD, the GNU linker - Section Options](https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_node/ld_21.html)

`*(.text .stub .text.* .gnu.linkonce.t.*)`の行は何をしているのか正直全くわからなかったのですが、セクションのコンテンツを定義している行のようです。

いくつか定義の方法がありますが、基本的には`ファイル名(シンボル)`の形式で定義されます。

複数行に渡って定義することが可能です。

`*()`のように、ファイル名の代わりに`*`を使用した場合は、リンク時に与えられたオブジェクトファイルの全てが対象になります。

つまり、`*(.text .stub .text.* .gnu.linkonce.t.*)`の行は、入力されたオブジェクトファイルの持つ`.text .stub .text.* .gnu.linkonce.t.*`の各セクションのデータをリンカが作成する実行ファイルの`.text.`セクションに配置する、という命令です。

参考：[Using LD, the GNU linker - Section Placement](https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_node/ld_19.html#SEC19)

リンカの入力で与えられている`entry.o`や`bio.o`などのファイルは、いずれも32bitELF形式でコンパイルされているため、それぞれがヘッダや`.text`セクションを持っています。

これらを一つの実行ファイルとして統合するために上記のような定義がされているんですね。

続いて`.text`セクションの定義が完了したため、セグメントの終了を示す`etext`を定義する必要があります。

``` c
PROVIDE(etext = .);	/* Define the 'etext' symbol to this value */
```

参考：[Man page of END](https://linuxjm.osdn.jp/html/LDP_man-pages/man3/end.3.html)

ここでは、`PROVIDE`を使って、カレントロケーションに`etext`を設定しています。

`PROVIDE`は、シンボルがコード上で未定義の場合にのみシンボルを作成する命令です。

参考：[PROVIDE (LD)](https://sourceware.org/binutils/docs/ld/PROVIDE.html)

### SECTIONS：rodataセクションの定義

続いて`.rodata`セクションを定義します。

`rodata`は`Read Only Data`の意味です。

``` c
.rodata : {
	*(.rodata .rodata.* .gnu.linkonce.r.*)
}
```

リンカの定義は`.text`セクションと同じ記法なので割愛します。

### SECTIONS：stab,stabstrセクションの定義

続いて、デバッグ用の`stab`セクションが定義されます。

``` c
/* Include debugging information in kernel memory */
.stab : {
	PROVIDE(__STAB_BEGIN__ = .);
	*(.stab);
	PROVIDE(__STAB_END__ = .);
}

.stabstr : {
	PROVIDE(__STABSTR_BEGIN__ = .);
	*(.stabstr);
	PROVIDE(__STABSTR_END__ = .);
}
```

`ld`は、リンカスクリプトで定義されたコンテンツが空となるセクションは作成しません。

デフォルトのコードでは各バイナリは`.stab`セクションを持たないため、`kerel`にも`.stab`セクションは存在しませんでした。

しかし、Makefileで定義されたgccのコンパイルオプションに`-gstabs`を追加して`.stab`セクションを作成することで、リンクされた`kernel`にも`.stab`セクションが作成されることを確認しました。

### SECTIONS：dataセクションの定義

`.data`セクションには読み書き可能なデータが格納されます。

``` c
/* Adjust the address for the data segment to the next page */
. = ALIGN(0x1000);

/* Conventionally, Unix linkers provide pseudo-symbols
	* etext, edata, and end, at the end of the text, data, and bss.
	* For the kernel mapping, we need the address at the beginning
	* of the data section, but that's not one of the conventional
	* symbols, because the convention started before there was a
	* read-only rodata section between text and data. */
PROVIDE(data = .);

/* The data segment */
.data : {
	*(.data)
}

PROVIDE(edata = .);
```

まずは`. = ALIGN(0x1000);`の行でカレントロケーションを`0x1000`の境界にアラインメントしてます。

この行は先ほどの`. = 0x80100000;`のように、ロケーションカウンタに特定のアドレスを割り当てているわけではありません。

`ALIGN`を実行した時点のカレントロケーションをもとに、指定した値の境界にカレントロケーションをアラインメントしています。

実際に生成された`kernel`のバイナリを見ると、バイナリデータが`0x80107aa9`まで連続していたところから、`.data`セクションの先頭アドレスが`0x80108000`になっていることがわかります。

``` bash
$ objdump -D kernel | grep -5 "Disassembly of section .data:"
80107aa6:	67 6e                	outsb  %ds:(%si),(%dx)
80107aa8:	65                   	gs
80107aa9:	64                   	fs
	...

Disassembly of section .data:

80108000 <ctlmap>:
	...
80108010:	11 17                	adc    %edx,(%edi)
80108012:	05 12 14 19 15       	add    $0x15191412,%eax
```

これはカレントロケーションが`0x80107aaa`までインクリメントされていたところから`0x1000`の境界にアラインメントされた結果です。

参考：[Using LD, the GNU linker - Arithmetic Functions](https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_node/ld_14.html#IDX239)

以降の定義は、これまで紹介した内容と同一なので割愛します。

### SECTIONS：bssセクションの定義

`.bss`セクションは以下のように定義します。

ここについてもこれまでと同様ですので割愛します。

``` c
PROVIDE(edata = .);
.bss : {
	*(.bss)
}
PROVIDE(end = .);
```

### SECTIONS：DISCARD

`/DISCARD/`に記述されたセクションは生成オブジェクトにリンクされません。

``` c
/DISCARD/ : {
	*(.eh_frame .note.GNU-stack)
}
```

`.eh_frame `はgccによって生成される、スタックバックトレースを取得するための情報が格納されるセクションです。

`.note.GNU-stack`は、Linuxのオブジェクトファイルでスタック属性を宣言する際に使用されます。

## カーネルのエントリポイント

続いて、リンク時にカーネルのエントリポイントとして定義されていた`_start`関数を見ていきます。

`_start`関数が定義された`entry.S`は以下のコードです。

``` assembly
# The xv6 kernel starts executing in this file. This file is linked with
# the kernel C code, so it can refer to kernel symbols such as main().
# The boot block (bootasm.S and bootmain.c) jumps to entry below.
        
# Multiboot header, for multiboot boot loaders like GNU Grub.
# http://www.gnu.org/software/grub/manual/multiboot/multiboot.html
#
# Using GRUB 2, you can boot xv6 from a file stored in a
# Linux file system by copying kernel or kernelmemfs to /boot
# and then adding this menu entry:
#
# menuentry "xv6" {
# 	insmod ext2
# 	set root='(hd0,msdos1)'
# 	set kernel='/boot/kernel'
# 	echo "Loading ${kernel}..."
# 	multiboot ${kernel} ${kernel}
# 	boot
# }

#include "asm.h"
#include "memlayout.h"
#include "mmu.h"
#include "param.h"

# Multiboot header.  Data to direct multiboot loader.
.p2align 2
.text
.globl multiboot_header
multiboot_header:
  #define magic 0x1badb002
  #define flags 0
  .long magic
  .long flags
  .long (-magic-flags)

# By convention, the _start symbol specifies the ELF entry point.
# Since we haven't set up virtual memory yet, our entry point is
# the physical address of 'entry'.
.globl _start
_start = V2P_WO(entry)

# Entering xv6 on boot processor, with paging off.
.globl entry
entry:
  # Turn on page size extension for 4Mbyte pages
  movl    %cr4, %eax
  orl     $(CR4_PSE), %eax
  movl    %eax, %cr4
  # Set page directory
  movl    $(V2P_WO(entrypgdir)), %eax
  movl    %eax, %cr3
  # Turn on paging.
  movl    %cr0, %eax
  orl     $(CR0_PG|CR0_WP), %eax
  movl    %eax, %cr0

  # Set up the stack pointer.
  movl $(stack + KSTACKSIZE), %esp

  # Jump to main(), and switch to executing at
  # high addresses. The indirect call is needed because
  # the assembler produces a PC-relative instruction
  # for a direct jump.
  mov $main, %eax
  jmp *%eax

.comm stack, KSTACKSIZE
```

### マルチブートヘッダ

`entry.S`の先頭行からコードを見ていくと、次のようなコードがありました。

まず先頭行、`.p2align 2`ではバイナリを4バイト境界にアラインメントしています。

参考：[P2align (Using as)](https://sourceware.org/binutils/docs/as/P2align.html#P2align)

参考：[gcc - What does .p2align do in asm code? - Stack Overflow](https://stackoverflow.com/questions/21546946/what-does-p2align-do-in-asm-code)

その後`.text`ディレクティブの直下に`multiboot_header`が定義されています。

ここでは、マルチブート仕様に対応するためのマルチブートヘッダの定義を行っています。

``` assembly
# Multiboot header.  Data to direct multiboot loader.
.p2align 2
.text
.globl multiboot_header
multiboot_header:
  #define magic 0x1badb002
  #define flags 0
  .long magic
  .long flags
  .long (-magic-flags)
```

マルチブート仕様とは、ブートローダがx86オペレーティングシステムカーネルをロードする方法を標準化したものです。

[前回](https://yukituna.com/3850/)の記事では、xv6OSのブートローダのコードを見ていきましたが、例えばxv6OSのカーネルをGRUBでブートしたい場合には、このマルチブート仕様にカーネルを対応させる必要があります。

GRUBなどのブートローダは、Linuxシステムなどで標準的に採用されています。(通常はGRUB2を使用)

参考：[マルチブート仕様](https://wiki2th.com/ja/Multiboot_Specification)

参考：[GRUBでOSを起動する - OSのようなもの](https://wocota.hatenadiary.org/entry/20090607/1244389534)

参考：[GRUBで簡単なOSカーネルを動かしてみる - ももいろテクノロジー](https://inaz2.hatenablog.com/entry/2015/12/31/221319)

実際にxv6OSをGRUBによる起動に対応させるのはカーネルの読解が一通り終わってからやろうと考えているので、コードの詳細は追わずに先に進みます。

### エントリポイントの物理アドレスを定義

続いてのコードは以下です。

``` assembly
# By convention, the _start symbol specifies the ELF entry point.
# Since we haven't set up virtual memory yet, our entry point is
# the physical address of 'entry'.
.globl _start
_start = V2P_WO(entry)
```

`.globl`ディレクティブは、シンボルをリンクされているすべてのファイルから参照可能にするための宣言です。

`_start`はエントリポイントとしてリンカスクリプトなどから参照されていたシンボルですが、この宣言によって`entry.S`の外部からの呼び出しが可能になっています。

参考：[.globl - Google Search](https://www.google.com/search?q=.globl&rlz=1C1GCEA_enJP959JP959&oq=.globl&aqs=chrome..69i57j0i512j0i10i512j0i10l7.483j0j7&sourceid=chrome&ie=UTF-8)

続いて、`_start = V2P_WO(entry)`の行を見てみます。

`V2P_WO`は、`memlayout.h`で定義されている以下のマクロです。

``` assembly
// Memory layout

#define EXTMEM  0x100000            // Start of extended memory
#define PHYSTOP 0xE000000           // Top physical memory
#define DEVSPACE 0xFE000000         // Other devices are at high addresses

// Key addresses for address space layout (see kmap in vm.c for layout)
#define KERNBASE 0x80000000         // First kernel virtual address
#define KERNLINK (KERNBASE+EXTMEM)  // Address where kernel is linked

#define V2P(a) (((uint) (a)) - KERNBASE)
#define P2V(a) ((void *)(((char *) (a)) + KERNBASE))

#define V2P_WO(x) ((x) - KERNBASE)    // same as V2P, but without casts
#define P2V_WO(x) ((x) + KERNBASE)    // same as P2V, but without casts
```

引数として受け取ったアドレスから`KERNBASE`として設定されている`0x80000000`を引いて返すだけのマクロのようです。

もともと、リンカではカーネルの`.text`セクションは`0x80100000`をベースにしてリンクされていました。

これはユーザモードとカーネルモードの仮想メモリ範囲を切り分けて、x86CPUのページング機構によってCPUがカーネルの仮想アドレスをロードするための仕組みです。

参考：[xv6: OSはどうメモリを参照、管理するのか（前編） - yohei.codes](https://yohei.codes/ja/post/xv6-memory-1/)

しかし、`_start = V2P_WO(entry)`が実行される段階では、カーネル側で仮想メモリの設定が行われていないため、エントリポイント`_start`を物理アドレスに割り当てるために、`0x80100000`の減算が行われています。

### カーネルのエントリポイントのロード

残りの`entry.S`の処理を追っていきます。

まずは`.globl entry`で`entry`を外部から参照可能なシンボルとしています。

この`entry`で行っている処理は、簡単に言うとページングを利用してカーネルの仮想アドレスを読み込んでいます。

`entry`ラベルが呼び出しされる時点では、まだページング機構は有効化されていないので、まずはこれを有効化していきます。

``` assembly
# Entering xv6 on boot processor, with paging off.
.globl entry
entry:
  # Turn on page size extension for 4Mbyte pages
  movl    %cr4, %eax
  orl     $(CR4_PSE), %eax
  movl    %eax, %cr4
  # Set page directory
  movl    $(V2P_WO(entrypgdir)), %eax
  movl    %eax, %cr3
  # Turn on paging.
  movl    %cr0, %eax
  orl     $(CR0_PG|CR0_WP), %eax
  movl    %eax, %cr0

  # Set up the stack pointer.
  movl $(stack + KSTACKSIZE), %esp

  # Jump to main(), and switch to executing at
  # high addresses. The indirect call is needed because
  # the assembler produces a PC-relative instruction
  # for a direct jump.
  mov $main, %eax
  jmp *%eax

.comm stack, KSTACKSIZE
```

### ページングとは

コードを追う前に、ページングについて簡単にまとめます。

ページングとは、メモリ領域を固定長のサイズ(ページ)に分割して管理する方法です。

これによって、分割されたメモリ領域をリニアなメモリ空間として扱うことができたり、SSDなどの補助記憶装置に仮想的なページ領域を確保することで、物理メモリの容量以上のメモリ領域を扱うことができます。

ページングにおいて、主記憶装置から補助記憶装置にページを書き出すことを「ページアウト」、逆に補助記憶装置から主記憶装置にページを書き戻すことを「ページイン」または「スワップイン」と呼びます。

ページング機構によって、使用されていないメモリ領域はページアウトによって補助記憶装置に保存されます。

次にそのメモリ領域が必要となる場合、OSは物理メモリ上に存在しないアドレスに対して「ページフォールト」という例外を発生させ、割込みによってスワップインを行い、物理メモリ上にページを書き戻すという挙動が発生します。

参考：[x86_64アーキテクチャ - ばびろん's すたっく メモリアクセス](https://babyron64.hatenablog.com/entry/2017/12/22/210124)

参考：[x86_64アーキテクチャ - ばびろん's すたっく メモリアクセス(続き)](https://babyron64.hatenablog.com/entry/2017/12/22/232423)

参考：[ページング（paging）とは - IT用語辞典 e-Words](https://e-words.jp/w/%E3%83%9A%E3%83%BC%E3%82%B8%E3%83%B3%E3%82%B0.html)

ページング機構を有効化するためには、x86CPUでは`CR0(コントロールレジスタ0)`のPGフラグを1にする必要があります。

実際にページングを有効化している箇所を見ます。

[前回の記事](https://yukituna.com/3850/)でプロテクトモード移行時に`CR0(コントロールレジスタ0)`のPEフラグをセットしましたが、この時とやり方はほぼ同じです。

``` assembly
entry:
  # Turn on page size extension for 4Mbyte pages
  movl    %cr4, %eax
  orl     $(CR4_PSE), %eax
  movl    %eax, %cr4
  # Set page directory
  movl    $(V2P_WO(entrypgdir)), %eax
  movl    %eax, %cr3
  # Turn on paging.
  movl    %cr0, %eax
  orl     $(CR0_PG|CR0_WP), %eax
  movl    %eax, %cr0
```

最後の`# Turn on paging.`以降の処理が、`CR0(コントロールレジスタ0)`のPGフラグをセットしている箇所です。

各フラグの演算に使っている定数はそれぞれ以下のように定義されています。

``` c
// Control Register flags
#define CR0_PE          0x00000001      // Protection Enable
#define CR0_WP          0x00010000      // Write Protect
#define CR0_PG          0x80000000      // Paging

#define CR4_PSE         0x00000010      // Page size extension
```

ここから、PGフラグだけでなく、WPフラグもセットしていることがわかります。

WPフラグがセットされると、CPUはリング0のスーパーバイザレベルのプロシージャが読み取り専用ページに時書き込みを行うことを禁止することができます。

これによってOSで新しいプロセスを作成する際のコピーオンライト方式の実装を容易にすることができます。

これについては今後の記事で書きます。

ただ、x86CPUではデフォルトでWPフラグがセットされているはずなので、なぜ明示的に設定しているのかは疑問に感じる点です。

参考：[Control register - Wikipedia](https://en.wikipedia.org/wiki/Control_register)

参考：[assembly - whats the purpose of x86 cr0 WP bit? - Stack Overflow](https://stackoverflow.com/questions/15275059/whats-the-purpose-of-x86-cr0-wp-bit)

次に、CR0の設定より少しさかのぼった以下の箇所を見ていきます。

``` assembly
# Turn on page size extension for 4Mbyte pages
movl    %cr4, %eax
orl     $(CR4_PSE), %eax
movl    %eax, %cr4
```

ここでは`CR4(コントロールレジスタ4)`のPSEフラグをセットしています。

このフラグは、1ページのサイズをコントロールすることができます。

CR4のPSEフラグがセットされていない(デフォルト)場合、ページのサイズは4KiBになります。

逆にPSEフラグがセットされている場合、ページサイズは4MiBに拡張されます。

参考：[Control register - Wikipedia](https://en.wikipedia.org/wiki/Control_register)

ページサイズに2つのサイズが設定されている詳しい背景などは機会があれば別の記事にまとめます。

xv6OSでは、4MiBのページサイズが設定されていることまでわかりました。

最後は以下の箇所です。

``` assembly
# Set page directory
movl    $(V2P_WO(entrypgdir)), %eax
movl    %eax, %cr3
```

xv6OSにおけるページング機構は、この次の行で有効化しているため、この時点ではまだページングが有効になっていません。

そのため、`$(V2P_WO(entrypgdir))`マクロによって`entrypgdir`のアドレスを物理アドレスに変換してからCR3に書き込んでいます。

CR3は、ページング機構が有効な場合に使用されるレジスタで、x86CPUがページディレクトリとページテーブルを参照し、リニアアドレスを物理アドレスに変換するために使用されます。

`entrypgdir`は、`main.c`で定義されている構造体配列です。

``` c
// main.c
pde_t entrypgdir[];  // For entry.S

// The boot page table used in entry.S and entryother.S.
// Page directories (and page tables) must start on page boundaries,
// hence the __aligned__ attribute.
// PTE_PS in a page directory entry enables 4Mbyte pages.

__attribute__((__aligned__(PGSIZE)))
pde_t entrypgdir[NPDENTRIES] = {
  // Map VA's [0, 4MB) to PA's [0, 4MB)
  [0] = (0) | PTE_P | PTE_W | PTE_PS,
   
  // Map VA's [KERNBASE, KERNBASE+4MB) to PA's [0, 4MB)
  [KERNBASE>>PDXSHIFT] = (0) | PTE_P | PTE_W | PTE_PS,
};
```

配列のサイズは`NPDENTRIES`ですが、これは`mmu.h`で以下の通り1024と定義されています。

``` c
// Page directory and page table constants.
#define NPDENTRIES      1024    // # directory entries per page directory
#define NPTENTRIES      1024    // # PTEs per page table
#define PGSIZE          4096    // bytes mapped by a page
```

`entrypgdir`には2つの要素があります。

正直何をしているのか雰囲気でしか理解していないですが、ここでは単にページディレクトリのエントリを初期化しているようです。

まず、2つの要素に共通している`(0) | PTE_P | PTE_W | PTE_PS`の行は、以下の定義を行っています。

- `0` - すべてのビットを0にする
- `PTE_P` - present をセットする
- `PTE_W` - read\write をセットする
- `PTE_PS` - 4MiB page size bit をセットする

1つ目の要素`[0] = (0) | PTE_P | PTE_W | PTE_PS,`では、0番目の要素のページディレクトリエントリをこの値に初期化しています。

次の要素では、`KERNBASE>>PDXSHIFT` = `0x80000000 >> 22` = 512番目の要素のページディレクトリエントリをこの値に初期化しています。

この初期化は、次にページング機構を有効化してメイン関数に移行する際に使用するようです。

参考：[xv6: OSはどうメモリを参照、管理するのか（前編） - yohei.codes](https://yohei.codes/ja/post/xv6-memory-1/)

参考：[what does this code mean in xv6 entrypgdir? - Stack Overflow](https://stackoverflow.com/questions/58576065/what-does-this-code-mean-in-xv6-entrypgdir)

### スタックポインタの設定

最後にスタックポインタの設定を行って、main関数に移行します。

``` assembly
# Set up the stack pointer.
movl $(stack + KSTACKSIZE), %esp
```

`KSTACKSIZE`は、`param.h`で4096と定義されています。

``` c
#define NPROC        64  // maximum number of processes
#define KSTACKSIZE 4096  // size of per-process kernel stack
#define NCPU          8  // maximum number of CPUs
#define NOFILE       16  // open files per process
#define NFILE       100  // open files per system
#define NINODE       50  // maximum number of active i-nodes
#define NDEV         10  // maximum major device number
#define ROOTDEV       1  // device number of file system root disk
#define MAXARG       32  // max exec arguments
#define MAXOPBLOCKS  10  // max # of blocks any FS op writes
#define LOGSIZE      (MAXOPBLOCKS*3)  // max data blocks in on-disk log
#define NBUF         (MAXOPBLOCKS*3)  // size of disk block cache
#define FSSIZE       1000  // size of file system in blocks
```

Cのコードに移行するためにスタックポインタの設定が必要なのですが、ここは正直よくわかりませんでした。

というのも、変数`stack`は、`main.c`で定義されているものであり、この時点ではまだ値が格納されていません。

結果として`.comm`シンボルとして定義され、あとで再定義される想定とされているようです。

参考：[c - assembly - mov unitialized variable? - Stack Overflow](https://stackoverflow.com/questions/29008035/assembly-mov-unitialized-variable)

難解ですね。。

### main関数に移行

ブートストラップから続く一連の処理がようやく終わり、ここからカーネル本体となる`main.c`の関数に移行していきます。

``` c
# Jump to main(), and switch to executing at
# high addresses. The indirect call is needed because
# the assembler produces a PC-relative instruction
# for a direct jump.
mov $main, %eax
jmp *%eax

.comm stack, KSTACKSIZE
```

結構長くなってしまったので続きはまた次回の記事にて。

## まとめ

今回はカーネルプログラムのビルドとリンカスクリプト、そしてエントリポイントの処理の流れを追っていきました。

次回は今度こそようやくカーネル本体の動きを追っていくことができそうです。

## 参考書籍

- [30日でできる! OS自作入門](https://amzn.to/3qZSCY7)
- [ゼロからのOS自作入門](https://amzn.to/3qXYsZX)
- [はじめてのOSコードリーディング ~UNIX V6で学ぶカーネルのしくみ](https://amzn.to/3q8TU3K)
- [詳解 Linuxカーネル](https://amzn.to/3I6fkVt)
- [作って理解するOS x86系コンピュータを動かす理論と実装](https://amzn.to/3JRUdI2)