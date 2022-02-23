---
title: GOT/PLTを経由したライブラリ関数呼び出しの流れを追う
date: "2022-01-06"
template: "post"
draft: false
slug: "linux-got-plt"
category: "Linux"
tags:
  - "Linux"
  - "OS"
  - "Kernel"
description: "GOTとPLTの概要についてまとめるとともに実際に検証してみた内容をまとめています。"
socialImage: "/media/cards/linux-got-plt.png"
---

今回は、GOTとPLTの概要についてまとめるとともに実際に検証を行っていきます。

この記事を書き始めたきっかけとしては、位置独立コード(PIC)について調べていく中でGOTがよくわからなくなってしまったことです。

<!-- omit in toc -->
## もくじ
- [共有ライブラリと動的リンク](#共有ライブラリと動的リンク)
- [共有ライブラリ関数呼び出しの流れ](#共有ライブラリ関数呼び出しの流れ)
- [GOT](#got)
- [PLT](#plt)
- [GOTとPLTの動きを追う](#gotとpltの動きを追う)
  - [ソースコードとビルド](#ソースコードとビルド)
  - [仮想メモリの出力](#仮想メモリの出力)
  - [call命令](#call命令)
  - [共有ライブラリ関数の呼び出し](#共有ライブラリ関数の呼び出し)
- [まとめ](#まとめ)
- [参考書籍](#参考書籍)

## 共有ライブラリと動的リンク

多くのELFバイナリではライブラリ関数(あらかじめ定義されているよく使う便利な関数)が動的リンクによってリンクされています。

動的リンクとは、プログラムの実行に必要なライブラリ関数などの本体を、プログラムの実行時にリンクする仕組みのことです。

動的リンクと対になる方式としては、必要なライブラリ関数などをすべて1つのプログラムにあらかじめリンクしておく静的リンクがあります。

ライブラリ関数などのように複数のプログラムが共通して使用する関数やモジュールを動的リンクにすることで、プログラム自体のファイルサイズの削減や、実行時のメモリ使用量を効率化できるといったメリットがあります。

ELFバイナリがどの共有ライブラリに依存しているかは、`ldd`コマンドで調べることができます。

``` bash
$ ldd test.o
	linux-vdso.so.1 (0x00007ffdb417f000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f02af5ca000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f02af7d7000)
```

参考：[Man page of LDD](https://linuxjm.osdn.jp/html/ld.so/man1/ldd.1.html)

この記事では、動的リンクされた共有ライブラリをプログラムの実行時にリンクする仕組みについてまとめます。

## 共有ライブラリ関数呼び出しの流れ

ライブラリ関数が動的リンクされたELFバイナリを実行する場合、ライブラリ関数は実際に処理の中で呼び出されるタイミングまでバインドされません。

このような仕組みは遅延バインドと呼ばれ、PLT(Procedure Linkage Table)によってサポートされます。

プログラムの実行時に共有ライブラリ関数が呼び出されるとき、最初に呼び出されるアドレスは共有ライブラリ関数の実態ではなく、`.plt`セクションのエントリになります。

呼び出されたPLTのエントリは、その後GOT(Global Offset Table)と呼ばれる領域にジャンプします。

参考：[詳解セキュリティコンテスト](https://amzn.to/3zwc6Y6)

## GOT

GOT(Global Offset Table)はELFファイルとしてコンパイルされたプログラムを正しく実行できるようにするために使用されるコンピュータプログラム（実行可能ファイルおよび共有ライブラリ）メモリのセクションを指します。

参考：[Global Offset Table - Wikipedia](https://en.wikipedia.org/wiki/Global_Offset_Table)

簡潔に言うと、GOTはライブラリ関数のアドレス一覧を保持するための領域です。

この領域は、プログラムの実行時に使用するライブラリ関数のアドレスが設定されます。

GOTによて、ライブラリ関数をプロセスメモリ空間の中に再配置することが容易になります。

## PLT

PLT(Procedure Linkage Table)は、ライブラリ関数を呼び出すための小さなコードの集合です。

PLTには、GOTが保持するライブラリ関数と同数のコードが配置されています。

PLTの持つコードの挙動は、GOTに設定されている値にジャンプすることです。

PLTのコードが呼び出されたとき、GOTにまだ呼び出し先の関数のアドレスが設定されていない場合は、アドレスをGOTに設定してからジャンプを行います。

参考：[PLTとGOTってなんだっけ · Keichi Takahashi](https://keichi.dev/post/plt-and-got/)

## GOTとPLTの動きを追う

ここからは、実際にGDBを使ってメモリマップを見ていきます。

### ソースコードとビルド

今回検証に使用するのは以下のコードです。

``` c
#include <stdio.h>
#include <stdlib.h>

int test()
{
    return 0;
}

int main()
{
    int a = test();
    int b = rand();
    int c = rand();
    return a * b;
}
```

次のコマンドでコンパイルし、gdbで起動しておきます。

``` bash
gcc -fcf-protection=none -no-pie -g test.c -o test.o
gdb ./test.o
```

### 仮想メモリの出力

Linuxには、現在稼働しているプロセスのための疑似ディレクトリとして`/proc`ディレクトリが容易されています。

`/proc`ディレクトリの直下には稼働中のプロセスのPIDに対応した数字のディレクトリがあり、その中にプロセス制御テーブルがマッピングされています。

参考：[プロセスのメモリマップについて (Linux)](http://uralowl.my.coocan.jp/unix/job/ORACLE/oracle/pmap_linux.html)

参考：[embedded - Understanding Linux /proc/pid/maps or /proc/self/maps - Stack Overflow](https://stackoverflow.com/questions/1401359/understanding-linux-proc-pid-maps-or-proc-self-maps)

今回は、プロセスのメモリマップを確認するため、以下のコマンドを使用しました。

``` bash
$ cat /proc/`pidof test.o`/maps
address           	permission offset   device inode   				   pathname
00400000-00401000 r--p 00000000 fd:00 786517                             /home/ubuntu/gottest/test.o
00401000-00402000 r-xp 00001000 fd:00 786517                             /home/ubuntu/gottest/test.o
00402000-00403000 r--p 00002000 fd:00 786517                             /home/ubuntu/gottest/test.o
00403000-00404000 r--p 00002000 fd:00 786517                             /home/ubuntu/gottest/test.o
00404000-00405000 rw-p 00003000 fd:00 786517                             /home/ubuntu/gottest/test.o
7ffff7dc3000-7ffff7de8000 r--p 00000000 fd:00 945235                     /lib/x86_64-linux-gnu/libc-2.31.so
7ffff7de8000-7ffff7f60000 r-xp 00025000 fd:00 945235                     /lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f60000-7ffff7faa000 r--p 0019d000 fd:00 945235                     /lib/x86_64-linux-gnu/libc-2.31.so
7ffff7faa000-7ffff7fab000 ---p 001e7000 fd:00 945235                     /lib/x86_64-linux-gnu/libc-2.31.so
7ffff7fab000-7ffff7fae000 r--p 001e7000 fd:00 945235                     /lib/x86_64-linux-gnu/libc-2.31.so
7ffff7fae000-7ffff7fb1000 rw-p 001ea000 fd:00 945235                     /lib/x86_64-linux-gnu/libc-2.31.so
7ffff7fb1000-7ffff7fb7000 rw-p 00000000 00:00 0 
7ffff7fcb000-7ffff7fce000 r--p 00000000 00:00 0                          [vvar]
7ffff7fce000-7ffff7fcf000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fcf000-7ffff7fd0000 r--p 00000000 fd:00 945231                     /lib/x86_64-linux-gnu/ld-2.31.so
7ffff7fd0000-7ffff7ff3000 r-xp 00001000 fd:00 945231                     /lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ff3000-7ffff7ffb000 r--p 00024000 fd:00 945231                     /lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffc000-7ffff7ffd000 r--p 0002c000 fd:00 945231                     /lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffd000-7ffff7ffe000 rw-p 0002d000 fd:00 945231                     /lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

`maps`は、プロセスまたはスレッド内の連続する仮想メモリの領域を示しています。

`address`にはプロセスのアドレス空間内の領域の開始アドレスと終了アドレスが、`permission`にはその領域の権限が記録されています。

上記の結果から、この`/lib/x86_64-linux-gnu/libc-2.31.so`と`/lib/x86_64-linux-gnu/ld-2.31.so`の2つの共有ライブラリが使用されていることがわかります。

ここで、共有ライブラリ`/lib/x86_64-linux-gnu/ld-2.31.so`は`7ffff7fcf000`にマッピングされていますが、これは固定されたアドレスではありません。

共有ライブラリが展開されるメモリアドレスは、プログラムの実行時に決定され、場合によっては異なるアドレスに展開されることもあります。

ここで、プログラムの実行時に、共有ライブラリが実際にどのメモリアドレスに展開されたのかを調べて呼び出すための仕組みがPLTとGOTです。

### call命令

アセンブリソースから、関数を呼び出す`call`命令の箇所を抜粋しました。

``` bash
$ disas main
Dump of assembler code for function main:
   0x000000000040113e <+13>:	call   0x401126 <test>
   0x0000000000401146 <+21>:	call   0x401030 <rand@plt>
   0x000000000040114e <+29>:	call   0x401030 <rand@plt>
End of assembler dump.
```

`call`命令は以下の2つの処理を組み合わせた処理を実行する命令です。

- `call`命令の次のアドレス(関数がreturnした後に実行する命令)をスタックにプッシュする
- 呼び出し先の関数のアドレスにジャンプする

参考：[x86アセンブリ言語での関数コール](https://vanya.jp.net/os/x86call/)

ここで、2つの`call`命令のアセンブリをそれぞれ出力してみます。

``` bash
# 0x401126 <test>
$ disas 0x401126
Dump of assembler code for function test:
   0x0000000000401126 <+0>:	push   rbp
   0x0000000000401127 <+1>:	mov    rbp,rsp
   0x000000000040112a <+4>:	mov    eax,0x0
   0x000000000040112f <+9>:	pop    rbp
   0x0000000000401130 <+10>:	ret    
End of assembler dump.
```

``` bash
# 0x401030 <rand@plt>
$ disas 0x401030
Dump of assembler code for function rand@plt:
   0x0000000000401030 <+0>:	jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <rand@got.plt>
   0x0000000000401036 <+6>:	push   0x0
   0x000000000040103b <+11>:	jmp    0x401020
End of assembler dump.
```

これを見比べたときに、ユーザ関数の`test`は直接関数が`call`されているのに対して、`rand`を呼び出す際は`rand@plt`が呼び出されていることがわかります。

そして、`rand@plt`が呼び出された場合は最初の`JMP`命令で`rand@got.plt`が呼び出されます。

これはまだGOTに呼び出し先のアドレスが設定されていないためです。

### 共有ライブラリ関数の呼び出し

次に、1回目と2回目の`rand`関数の呼び出し点にそれぞれブレークポイントを設定して、PLTからGOTを経て共有ライブラリ関数のバインドが行われる前後のGOTの変化を見ていきます。

``` bash
$ b *0x401146
$ b *0x40114e
$ run
```

これで、1回目の`rand`関数の呼び出し点に到達しました。

ここで、`rand@plt`のディスアセンブル結果から、対応するGOTのアドレスは`0x404018`であることがわかっています。

つまり、最終的に`0x404018`に`rand`関数本体のアドレスが格納される想定になります。

しかし、現時点ではまだ`rand`関数はプログラムの実行時に一度も呼び出されていないため、GOTには`rand@plt+6`のアドレスが格納されています。

``` bash
$ telescope 0x404018
0000| 0x404018 --> 0x401036 (<rand@plt+6>:	push   0x0)
```

参考：[Command dereference - GEF - GDB Enhanced Features documentation](https://gef.readthedocs.io/en/master/commands/dereference/)

`rand@plt+6`のアドレスの処理は、スタックに値(0x0)を積んだ後に`0x401020`へのジャンプを行っています。

``` bash
$ disas 0x401030
Dump of assembler code for function rand@plt:
   0x0000000000401030 <+0>:	jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <rand@got.plt>
   0x0000000000401036 <+6>:	push   0x0
   0x000000000040103b <+11>:	jmp    0x401020
End of assembler dump.
```

この後の処理は、以下のようにさらにスタックに値を格納した後、`0x404010`に格納されているアドレスにジャンプする処理が続きます。

``` bash
$ x/16 0x401020
   0x401020:	push   QWORD PTR [rip+0x2fe2]        # 0x404008
   0x401026:	jmp    QWORD PTR [rip+0x2fe4]        # 0x404010
```

`0x401036`にブレークポイントを設定し、その後の処理を追ってみると次のようになりました。

``` bash
=> 0x401026:	jmp    QWORD PTR [rip+0x2fe4]        # 0x404010
 | 0x40102c:	nop    DWORD PTR [rax+0x0]
 | 0x401030 <rand@plt>:	jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <rand@got.plt>
 | 0x401036 <rand@plt+6>:	push   0x0
 | 0x40103b <rand@plt+11>:	jmp    0x401020
 |->   0x7ffff7fe7bb0:	endbr64 
       0x7ffff7fe7bb4:	push   rbx
       0x7ffff7fe7bb5:	mov    rbx,rsp
       0x7ffff7fe7bb8:	and    rsp,0xffffffffffffffc0
       0x7ffff7fe7bbc:	sub    rsp,QWORD PTR [rip+0x14b45]        # 0x7ffff7ffc708 <_rtld_global_ro+232>
```

ここで呼び出している関数は`_dl_runtime_resolve`です。

詳しくは以下が参考になりました。

参考：[Ret2dl_resolve x64](https://syst3mfailure.io/ret2dl_resolve)

この関数では、呼び出し先の`rand`関数のアドレスを解決して、`rand`関数を呼び出します。

この際にGOTが更新されるため、次回以降の`rand`関数の呼び出し時には、解決された`rand`関数のアドレスがGOTから直接呼び出されます。

実際に2回目の`rand`関数の呼び出し時点で停止させ、先ほどと同じように`rand@plt`が参照するGOTの中身を確認すると、`rand`関数本体のアドレスが格納されています。

``` bash
$ telescope 0x404018
0000| 0x404018 --> 0x7ffff7e0de90 (<rand>:	endbr64)
```

そのため、2回目の実行時には`_dl_runtime_resolve`は呼び出されず、直接`rand`関数が実行されます。

## まとめ

UNIXのコードを読んでいたはずが、気づいたらGOTとPLTのことを調べてました。

[詳解セキュリティコンテスト](https://amzn.to/3zwc6Y6)読むともっと詳しく書いてあったので、GOT Overwriteなども試しつつもう少し深掘りしてみようと思います。

## 参考書籍

- [詳解セキュリティコンテスト](https://amzn.to/3zwc6Y6)
- [Debug Hacks -デバッグを極めるテクニック&ツール](https://amzn.to/3n114Fn)
