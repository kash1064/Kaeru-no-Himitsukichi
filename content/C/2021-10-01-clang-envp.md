---
title: main関数の3つ目の引数*envp[]で環境変数を取得する
date: "2021-10-01"
template: "post"
draft: false
slug: "clang-envp"
category: "C"
tags:
  - "C"
description: "C言語でmain関数を定義する際に使用できる3つ目の引数についてまとめます。"
socialImage: "/media/cards/no-image.png"
---

## C 言語のmain関数の 3 つ目の引数 *envp[] について

今回は、C 言語でmain関数を定義する際に使用できる3つ目の引数についてまとめます。

先日、某CTFのデコンパイル結果を眺めていたところ、`int main(int argc, char *argv[], char *envp[]) `のように、引数を3つ取るmain関数に出会いました。

この3つ目の環境変数`*envp[]`は、C標準にて以下のように定義されており、実行環境の環境変数に対してのポインタが格納されるものであるようです。

>ホスト環境において、main 関数は第3引数 `char *envp[]` を取る。
>
>この引数は `char` へのポインタの null 終端配列を指す。`char` への各ポインタは、このプログラム実行環境に関する情報を提供する文字列を指す。

よく目にするC言語のmain関数は、以下のように2つの引数を取ります。

``` C
#include <stdio.h>

int main(int argc, char *argv[]) {
    printf("%d\n", argc);
    while(*argv)
    {
        printf("%s\n", *argv++);
    }
    return 0;
}
```

これらはそれぞれ、次のような引数です。

- argc : 引数の個数
- *argv[] : 実行時の引数のポインタ

実際に、このソースコードを`test.o`という実行ファイルにコンパイルして実行すると、次のような結果が出力されます。

``` bash
$ ./test.o arg1 arg2 arg2
4
./test.o
arg1
arg2
arg2
```

一方で、3つめの引数`*envp[]`を取る以下のようなmain関数を見てみます。

``` c
#include <stdio.h>

int main(int argc, char *argv[], char *envp[]) {
    while(*envp)
    {
        printf("%s\n", *envp++);
    }
    return 0;
}
```

このコードを実行すると、すべての環境変数が一行ずつ出力されました。

``` bash
$ ./test.o 
SHELL=/bin/bash
SESSION_MANAGER=local/parrot:@/tmp/.ICE-unix/1393,unix/parrot:/tmp/.ICE-unix/1393
{{ 中略 }}
PATH=/home/parrot/.local/bin:/snap/bin
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
UID=1000
QT_SCALE_FACTOR=1
_=./test.o
OLDPWD=/home/parrot
```

これは、`env`コマンドを実行した場合と同等の出力になります。

ちなみに、`env -i`で環境変数をすべて無視した状態で、実行時に`Test=Test`という環境変数を明示的に与えて実行すると、`Test=Test`のみが出力されます。

``` bash
$ env -i Test=Test ./test.o 
Test=Test
```

このことから、3つめの引数`*envp[]`は、あくまでそのプログラムが実行される環境の環境変数を取得する引数であることがわかります。

## セキュアコーディングにおける *envp[]

さて、3つめの引数`*envp[]`について調べていたところ、1つ面白い記事を見つけました。

> 何らかの方法で環境に変更を加えると、環境のメモリ領域が再割り当てされることになり、結果として `envp` が間違った場所を参照することになる場合がある。
>
> 参考：[ENV31-C. 環境変数へのポインタを無効にするかもしれない操作の後で、そのポインタを参照しない](https://www.jpcert.or.jp/sc-rules/c-env31-c.html)

上記のJPCERT/CCの記事のとおり、プログラムの実行後に何らかの方法で環境変数を改ざんした場合、`*envp[]`が環境変数の参照のために使用するメモリ領域が再割り当てされます。

つまり、何らかの方法で環境を変更した後に、3つめの引数`*envp[]`のポインタを使用すると、問題を引き起こす可能性があります。

上記より、プログラム内部で環境変数を利用する場合は、Linux環境では`extern char **environ;`、Windows環境なら`_CRTIMP extern char **_environ;`が定義されているのであれば、そちらを利用することが推奨されるようです。

## まとめ

この仕様は初めて知ったので、C言語の入門書としては個人的に一番推してる[猫でもわかるC言語プログラミング](https://amzn.to/3wlYyLJ)を 読み返してみたのですが、main関数の引数については、`argc`と`*argv[]`についてしか書かれておらず、3つめの引数`*envp[]`については一切触れられていませんでした。

入門書レベルでは扱われないような少しマニアックな仕様なんですかね。

### 追記（2021年 7月 7日）

3つ目の環境変数`*envp[]`が定義されている[J.5 Common extensions](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1124.pdf)は、厳密にはC言語の仕様ではなく拡張機能として定められており、すべての実装に移植できるものではないようです。  

理解があいまいな部分がありますが、「C言語の仕様」という理解は間違っていたようです。