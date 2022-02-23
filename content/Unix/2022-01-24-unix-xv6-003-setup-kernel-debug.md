---
title: xv6OSを真面目に読みこんでカーネルを完全に理解する -GDBデバッグ環境構築編-
date: "2022-01-24"
template: "post"
draft: false
slug: "unix-xv6-003-setup-kernel-debug"
category: "Unix"
tags:
  - "Unix"
  - "xv6"
  - "Kernel"
description: "教育用OSのxv6OSのソースコードを読んでカーネルについて学んでいきます。この記事ではxv6OSのカーネルをロードする挙動を読み解きます。"
socialImage: "/media/cards/unix-xv6-003-setup-kernel-debug.png"
---

[はじめてのOSコードリーディング ~UNIX V6で学ぶカーネルのしくみ](https://amzn.to/3q8TU3K)にインスパイアされて[xv6 OS](https://github.com/mit-pdos/xv6-public)を読んでます。

リバースエンジニアリングに強くなりたいのと、カーネルとかOSに詳しくなりたいと思っています。

[詳解 Linuxカーネル](https://amzn.to/3I6fkVt)が結構重かったので、もう少し軽めのところから始めたいと思っていたところ、UNIX V6というOSがトータルで1万行くらいのコード量で、人類でもギリギリ理解できるということを知り、興味を持ちました。

ただ、UNIX V6自体はx86CPUでは動作しないため、基本的には、UNIXv6をX86アーキテクチャで動くようにした[xv6 OS](https://github.com/mit-pdos/xv6-public)のリポジトリをForkした[kash1064/xv6-public: xv6 OS](https://github.com/kash1064/xv6-public)のソースコードを読んでいくことにしました。

[前回](https://kashiwaba-yuki.com/Unix/unix-xv6-002-load-kernel)まででxv6OSのビルドと起動プロセスまで読み進めました。

早速カーネル本体の動きを読み進めようと思ったのですが、コードを読むだけだとわからない箇所があったので、理解を深めるためにデバッグ環境を先に構成しようと思います。

<!-- omit in toc -->
## もくじ
- [xv6OSをQEMU-GDBでデバッグする](#xv6osをqemu-gdbでデバッグする)
  - [デバッグ時のQEMUのオプション引数](#デバッグ時のqemuのオプション引数)
  - [デバッグを試す](#デバッグを試す)
- [まとめ](#まとめ)

## xv6OSをQEMU-GDBでデバッグする

基本的な手順は以下の記事が参考になりました。

参考：[xv6のデバッグ環境をつくる - Qiita](https://qiita.com/ksky/items/974ad1249cfb2dcf5437)

僕の環境ではQEMUのコンソールはGUIの別ウィンドウで使用したかったので、上記の記事とは異なり、`qemu-nox-gdb`ではなく`qemu-gdb`を使用しています。

デバッガの接続方法は非常に簡単で、以下のコマンド実行するだけです。

``` bash
# Makefileと同じディレクトリで実行する
make qemu-gdb
```

続いて、別のターミナルを開き、以下のコマンドを入力するとデバッグが可能になります。

``` bash
# gdbでkernelバイナリをデバッグ対象に指定
gdb kernel

# gdbでリモートデバッグ
target remote localhost:26000
```

まず、`make qemu-gdb`は、xv6OSをビルドした上で`qemu-system-i386 -serial mon:stdio -drive file=fs.img,index=1,media=disk,format=raw -drive file=xv6.img,index=0,media=disk,format=raw -smp 2 -m 512  -S -gdb tcp::26000`を呼び出します。

QEMUのオプション引数については以下で順に見ていきます。

### デバッグ時のQEMUのオプション引数

`make qemu-gdb`実行時に使用されるオプション引数は以下の通りです。

|  オプション引数  |                             用途                             |
| :--------------: | :----------------------------------------------------------: |
|  -serial <dev>   | 仮想シリアルデバイスをホストにリダイレクトする<br />`mon:stdio`の設定ではターミナルにコンソールとQEMU monitorを表示させる |
| -drive <options> | ブロックデバイスやインターフェースなどの新しいデバイスを追加する<br />今回は`xv6.img`と`fs.img`をそれぞれdiskとして読み込んでいる |
|   -smp <cpus>    | 指定した数のCPUを使用してSMP(マルチプロセッサシステム)をエミュレーションする |
|  -m <MB or GB>   | 仮想マシン起動時のメモリサイズを指定(デフォルト単位：MB)<br />`1G`のように接頭辞を付けることでギガバイト単位に変更可能 |
|        -S        | 起動時にCPUを使用しない(=電源投入直後の時点で停止し、gdbの接続を待機させる) |
| -gdb <tcp::port> |        GDB接続を指定のプロトコル、ポートで受け入れる         |

参考：[Invocation — QEMU documentation](https://www.qemu.org/docs/master/system/invocation.html#hxtool-0)

参考：[カーネルデバッグで使うQEMUオプションチートシート - Qiita](https://qiita.com/wataash/items/174b454d4478898a556b)

### デバッグを試す

xv6カーネルのシンボル情報は、ビルド時に`kernel.sym`に格納されています。

実際にgdb側でシンボルのアドレスを検索してみても同等の結果になります。

``` bash
$ info address main
Symbol "main" is a function at address 0x80103040.
```

main関数にブレークポイントを仕掛けます。

``` bash
$ main
$ c
Continuing.
[----------------------------------registers-----------------------------------]
EAX: 0x80103040 --> 0xfb1e0ff3 
EBX: 0x10094 --> 0x0 --> 0xf000ff53 
ECX: 0x0 --> 0xf000ff53 
EDX: 0x1f0 --> 0xf000ff53 
ESI: 0x10094 --> 0x0 --> 0xf000ff53 
EDI: 0x0 --> 0xf000ff53 
EBP: 0x7bf8 --> 0x0 --> 0xf000ff53 
ESP: 0x8010b5c0 --> 0x0 --> 0xf000ff53 
EIP: 0x80103040 --> 0xfb1e0ff3
EFLAGS: 0x86 (carry PARITY adjust zero SIGN trap interrupt direction overflow)
[-------------------------------------code-------------------------------------]
   0x80103034 <mpenter+20>:	call   0x801027a0 <lapicinit>
   0x80103039 <mpenter+25>:	call   0x80102fe0 <mpmain>
   0x8010303e:	xchg   ax,ax
=> 0x80103040 <main>:	endbr32 
   0x80103044 <main+4>:	lea    ecx,[esp+0x4]
   0x80103048 <main+8>:	and    esp,0xfffffff0
   0x8010304b <main+11>:	push   DWORD PTR [ecx-0x4]
   0x8010304e <main+14>:	push   ebp
[------------------------------------stack-------------------------------------]
0000| 0x8010b5c0 --> 0x0 --> 0xf000ff53 
0004| 0x8010b5c4 --> 0x0 --> 0xf000ff53 
0008| 0x8010b5c8 --> 0x0 --> 0xf000ff53 
0012| 0x8010b5cc --> 0x0 --> 0xf000ff53 
0016| 0x8010b5d0 --> 0x0 --> 0xf000ff53 
0020| 0x8010b5d4 --> 0x0 --> 0xf000ff53 
0024| 0x8010b5d8 --> 0x0 --> 0xf000ff53 
0028| 0x8010b5dc --> 0x0 --> 0xf000ff53 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 1 hit Breakpoint 1, main () at main.c:19
```

僕の環境ではgdb-pedaを有効化しているので色々でてきました。

これでカーネルのデバッグができるようになりました。

## まとめ

はじめはbochsでやろうと思ったのですが、トラシューが上手くいかなかったのでgdbを使ってデバッグすることにしました。

こっちの方が設定が簡単で使い慣れているので結果としてよかったです。

今度こそほんとのほんとにカーネル本体を読み進めます。
