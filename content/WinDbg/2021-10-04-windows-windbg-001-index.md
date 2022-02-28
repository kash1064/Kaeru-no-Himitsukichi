---
title: WinDbgを用いたデバッグとトラブルシューティングのテクニック
date: "2021-10-04"
template: "post"
draft: false
slug: "windows-windbg-001-index"
category: "Windows"
tags:
  - "WinDbg"
  - "Kernel"
  - "Reversing"
description: ""
socialImage: "/media/cards/windows-windbg-001-index.png"
---

今回は、WinDbgを用いたWindowsのデバッグやダンプの解析方法について0から学べる情報を整理したいと思い、この記事を書き始めました。

私は、本業の中でしばしばメモリダンプやプロセスダンプを解析してトラブルシューティングをしなければならないことがあるのですが、各問題の原因特定のために有効な調査方法についてわかりやすい情報が非常に少ないと感じています。

そのため、常に手探りでの解析になることに苦しい思いをしており、WinDbgを用いた解析手法について充実したナレッジがないものかと常に思案していました。

しかし、中々有効な情報源が見つからなかったこともあり、「まずは自分が情報を発信しよう」という考えのもと、WinDbgを用いた解析手法について整理した情報を公開していくことにしました。

現時点(2021/10/02)ではまだ記事数は少ないですが、最終的にはWinDbgを用いた各種解析手法や、トラブルシューティングに有効なテクニックについて目的別に整理した記事を書いていこうと考えています。

公開した記事はすべて以下に整理しています。


## 記事カテゴリ一覧

### はじめてのWinDbg

1. [WinDbgのユーザモードデバッグチュートリアルを試してみた](/windows-windbg-002-tutorial)
2. [WinDbgでWindows10環境のカーネルデバッグを行う最初の一歩](/windows-windbg-004-kernel-debug)
3. [WinDbgの各ウィンドウについてまとめてみた](/windows-windbg-003-ui)
4. [Windows環境でカーネルメモリダンプを手動で取得し、WinDbgで解析する方法](/windows-windbg-005-kernel-dump)
5. [Time Travel Debuggingで始める新しいデバッグ手法](/windows-windbg-008-time-travel-debugging)


### WinDbgによるユーザモードデバッグ

1. [WinDbgのユーザモードデバッグチュートリアルを試してみた](/windows-windbg-002-tutorial)
2. [WinDbgでスタックポインタの指すメモリの情報を書き換えて任意の関数を実行させてみる](/windows-windbg-007-memory-spoofing)
3. [C言語で実装したBase64プログラムをWinDbgのTime Travel Debuggingで解析してみる](/windows-windbg-009-base64)
4. [Windows SocketsでTCP通信とUDP通信を実装したプログラムをリバーシングしてみる](/windows-windbg-010-socket)


### WinDbgによるカーネルモードデバッグ

1. [WinDbgでWindows10環境のカーネルデバッグを行う最初の一歩](/windows-windbg-004-kernel-debug)
2. [Windowsカーネルドライバを自作してWinDbgで解析してみる](/windows-windriver-001-tutorial)
3. [Windowsカーネルドライバを自作してWinDbgでIRP要求をのぞいてみる](/windows-windriver-002-irp)


### WinDbgによるプロセスダンプ解析

まだこのカテゴリの記事がありません。


### WinDbgによるメモリダンプ解析

1. [Windows環境でカーネルメモリダンプを手動で取得し、WinDbgで解析する方法](/windows-windbg-005-kernel-dump)

### WinDbg Previewによる Time Trabel Debugging

1. [Time Travel Debuggingで始める新しいデバッグ手法](/windows-windbg-008-time-travel-debugging)
2. [C言語で実装したBase64プログラムをWinDbgのTime Travel Debuggingで解析してみる](/windows-windbg-009-base64)
3. [Windows SocketsでTCP通信とUDP通信を実装したプログラムをリバーシングしてみる](/windows-windbg-010-socket)

## ユースケース別の解説記事

### WinDbgでメモリ情報を参照/編集する

1. [WinDbgでスタックポインタの指すメモリの情報を書き換えて任意の関数を実行させてみる](/windows-windbg-007-memory-spoofing)

### アプリケーションエラーの原因調査

1. [Time Travel Debuggingで始める新しいデバッグ手法](/windows-windbg-008-time-travel-debugging)

## 補足

各記事で解析のために使用しているサンプルプログラムは、いずれも以下のリポジトリに置いてあります。

サンプルプログラム：[kash1064/Try2WinDbg](https://github.com/kash1064/Try2WinDbg)

リポジトリ内のサンプルプログラムをシンボルファイル（.pdb）付きでコンパイルする方法については、以下の記事にまとめています。

参考：[llvm-mingwを使ってLinux環境でもシンボルファイル（.pdb）を作成する方法](/windows-windbg-006-symbol)

## 外部参考資料

- [Debugging Tools for Windows (WinDbg、KD、CDB、NTSD) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/)
- [WinDbg - マイクロソフト系技術情報 Wiki](https://techinfoofmicrosofttech.osscons.jp/index.php?WinDbg)
- [WinDbg. From A to Z!](http://windbg.info/download/doc/pdf/WinDbg_A_to_Z_color_JP.pdf)
- [Welcome to WinDbg.info](http://windbg.info/)
- [Windowsカーネルドライバプログラミング](https://amzn.to/3KTG0e9)