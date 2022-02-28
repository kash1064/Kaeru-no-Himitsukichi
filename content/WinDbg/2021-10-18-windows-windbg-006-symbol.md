---
title: llvm-mingwを使ってLinux環境でもシンボルファイル（.pdb）を作成する方法
date: "2021-10-18"
template: "post"
draft: false
slug: "windows-windbg-006-symbol"
category: "Windows"
tags:
  - "WinDbg"
  - "Kernel"
  - "Reversing"
description: ""
socialImage: "/media/cards/windows-windbg-006-symbol.png"
---

WinDbgによるWindowsデバッグやダンプ解析によるトラブルシューティングに習熟することを目指しています。

WinDbgを用いたWindowsのデバッグやダンプの解析方法について公開している情報については、以下のページに一覧をまとめているので、よければご覧ください。

参考：[WinDbgを用いたデバッグとトラブルシューティングのテクニック](/windows-windbg-001-index)

今回は、上記のWinDbgまとめ記事で解析のために使用するサンプルプログラムをビルドする環境について紹介します。

以下の要件を実現できる環境を、WSL2上のUbuntu20.04で構築していきます。
基本的にはDockerコンテナを使用するので、Dockerが動くならどの環境でも問題ないと思います。

1. **Linux環境でEXEファイルをクロスコンパイルできる**
2. **Linux環境でシンボルファイル（.pdbファイル）を生成できる**

<!-- omit in toc -->
## もくじ
- [ビルド環境を整える](#ビルド環境を整える)
- [シンボルファイル（.pdbファイル）とは](#シンボルファイルpdbファイルとは)
- [Linux環境でコンパイル時にシンボルファイルを生成する方法](#linux環境でコンパイル時にシンボルファイルを生成する方法)
- [llvm-mingwの環境を用意する](#llvm-mingwの環境を用意する)
- [llvm-mingwでPDBファイル付きでC++ファイルをコンパイルする](#llvm-mingwでpdbファイル付きでcファイルをコンパイルする)
- [まとめ](#まとめ)


## ビルド環境を整える

WinDbgテスト用のプログラムは、以下のリポジトリに置いてあります。

参考：[kash1064/Try2WinDbg](https://github.com/kash1064/Try2WinDbg)

まずは、Dockerが利用可能なOS上の任意のディレクトリに上記のリポジトリをcloneします。

``` bash
git clone https://github.com/kash1064/Try2WinDbg
```

続いて、コンパイル用の以下のコンテナイメージをpullします。

``` bash 
docker pull kashiwabayuki/try2windbg:1.0
```

参考：[kashiwabayuki/try2windbg](https://hub.docker.com/r/kashiwabayuki/try2windbg)

このコンテナイメージは、[mstorsjo/llvm-mingw](https://hub.docker.com/r/mstorsjo/llvm-mingw/)のコンテナイメージを一部カスタマイズしたイメージです。

詳細については後述します。

サンプルプログラムのリポジトリとコンテナイメージの取得が完了したら、ダウンロードした`Try2WinDbg`ディレクトリに移動します。

続いて、以下のコマンドを入力することで、`Try2WinDbg/src`直下に、コンパイルされたEXEファイルとシンボルファイルが生成されます。

``` bash
cd Try2WinDbg

# ビルドに使用するコンテナイメージを指定
CONTAINER=kashiwabayuki/try2windbg:1.0
docker run --rm -it -v `pwd`/src:/try2windbg $CONTAINER bash -c "cd /try2windbg && make"
```

これで、環境構築は完了です。

## シンボルファイル（.pdbファイル）とは

拡張子`.pdb`を持つファイルは、シンボルファイルと呼ばれるファイルです。

PDBは、「プログラムデータベース」の略称で、プロジェクトのソースコード内の識別子とステートメントをコンパイル済みアプリの対応する識別子と命令にマッピングしています。

このシンボルファイルを利用することで、デバッガを用いてアプリケーションやプロセスの解析を行う際に、非常に効率的な解析を行うことができます。

シンボルファイルがなくても、デバッガによる解析は可能です。

しかし、適切なシンボルファイルが読み込まれている場合と読み込まれていない場合には、同じアドレスを指し示す場合にも、デバッガ上で次のような表示の差異が発生します。

``` bash
sample+0x110     # シンボルファイルなし
sample!main+0x10 # シンボルファイルあり
```

シンボルファイルを適切に読み込ませることで、被疑箇所をスムーズに特定したり、関数名から挙動を類推したりと、より効率的にデバッグを行うことができるようになります。

参考：[デバッガーでシンボル (.pdb) ファイルとソース ファイルを設定する | Microsoft Docs](https://docs.microsoft.com/ja-jp/visualstudio/debugger/specify-symbol-dot-pdb-and-source-files-in-the-visual-studio-debugger?view=vs-2019)

## Linux環境でコンパイル時にシンボルファイルを生成する方法

Windowsアプリケーションのデバッグ時に非常に重要なシンボルファイルですが、Microsoftコンパイラの場合はビルド時に自動的に作成されます。

しかし、MinGWなどを用いてLinux環境でクロスコンパイルを行う場合は、シンボルファイルは通常生成されません。

MinGWでクロスコンパイルしたEXEファイルのシンボルファイルを作成する方法については、以下のStackOverFlowのように、`cv2pdb`を用いた方法が案内されるケースもありますが、この方法ではLinux環境ではシンボルファイルの作成ができません。

参考：[c++ - how to generate pdb files while building library using mingw? - Stack Overflow](https://stackoverflow.com/questions/19269350/how-to-generate-pdb-files-while-building-library-using-mingw/28627790)

そこで今回は、[llvm-mingw](https://github.com/mstorsjo/llvm-mingw)を用いた方法を利用しました。

[llvm-mingw](https://github.com/mstorsjo/llvm-mingw)とは、[LLVM](https://llvm.org/)/[Clang](https://clang.llvm.org/)/[LLD](https://lld.llvm.org/) をベースにした`mingw-w64`のツールチェーンです。

参考：[mstorsjo/llvm-mingw: An LLVM/Clang/LLD based mingw-w64 toolchain](https://github.com/mstorsjo/llvm-mingw)

LLVMとは、一言で言うとプラットフォームに依存せずに任意のプログラミング言語のコンパイルを行うことができる基盤です。

また、ClangとLLDは、LLVM用のC言語とリンカです。

[llvm-mingw](https://github.com/mstorsjo/llvm-mingw)は、通常のMinGWがGNUベースのbinutilsをLLVMベースのbinutilsに置き換えたものです。

これによって、様々なコンピュータアーキテクチャ（i686、x86_64、armv7、arm64）に対して単一のツールチェーンでのコンパイルを実現しています。
また、PDB形式でのシンボルファイルの生成もできるようになります。

## llvm-mingwの環境を用意する

LLVMベースのMinGWを利用できる環境を用意するために最も簡単な方法は、公式の用意している[Dockerイメージ](https://hub.docker.com/r/mstorsjo/llvm-mingw/)を使用することです。

基本的には、このイメージをDockerhubからpullするだけで、簡単に利用できるようになります。

もしDockerコンテナではなく、Linuxのホスト上にllvm-mingwの環境を構築する必要がある場合は、以下のDockerfile内のスクリプトを参考にするとよいです。

参考：[llvm-mingw/Dockerfile.cross at master · mstorsjo/llvm-mingw](https://github.com/mstorsjo/llvm-mingw/blob/master/Dockerfile.cross)

## llvm-mingwでPDBファイル付きでC++ファイルをコンパイルする

llvm-mingwの使い方は以下の通りです。

公式のDockerイメージの場合は、すでにLLVMベースのMinGWに対して、`x86_64-w64-mingw32-g++`としてパスが通っています。

これを利用して、`-Wl,-pdb=<filename>.pdb`というオプションを付けてコンパイルを実行することで、EXEファイルのコンパイルと同時にシンボルファイルも作成されます。

``` bash
x86_64-w64-mingw32-g++ -Wl,-pdb=sample.pdb sample.cpp -o sample.exe
```

## まとめ

今回は、Linux環境でWindows向けのEXEファイルをクロスコンパイルする際に、デバッグ用のシンボルファイルを作成する方法についてまとめました。