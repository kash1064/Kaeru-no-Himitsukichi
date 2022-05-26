---
title: 【Reversing解説】Infinity Gauntlet (ångstromCTF 2021)
date: "2021-10-04"
template: "post"
draft: false
slug: "ctf-angstromctf-2021"
category: "CTF"
tags:
  - "CTF"
  - "Reversing"
description: "今回は解けた問題の中から特に学びになった点の多いInfinity GauntletについてWriteUpを書きます。"
socialImage: "/media/cards/no-image.png"
---

## はじめに

ångstromctf2021に参加しました。
今回もReversing全完を目指して参加したものの、残念ながら11問中3問しか解けず…。

今回は何とか解けた問題の中から特に学びになった点の多い`Infinity Gauntlet`についてWriteUpを書きます。

### この記事について

**本記事の内容は社会秩序に反する行為を推奨することを目的としたものではございません。**

自身の所有する環境、もしくは許可された環境以外への攻撃の試行は、「不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）」に違反する可能性があること、予めご留意ください。

またすべての発言は所属団体ではなく個人に帰属します。

### CTF解説シリーズについて

自分の勉強も兼ねて、CTFの問題を初心者でも解るように丁寧に解説していきます。

というのも、CTFは正直、初めての人がいきなりチャレンジするには結構難しいジャンルだと思ってます。
僕自身、初めて参加したコンテストでは一問も解けなかった上、ベテランCTFerの方のWriteUpを読んでもなお、何も理解できない状態でした。

そこでこのシリーズでは自分の勉強も兼ねて、Flag取得までのステップが分かりやすいように可能な限り丁寧に解説することを目指しています。

一方で僕自身まだCTF歴は浅い身なので、もし誤った記載などあれば、ぜひご指摘いただけるとありがたいです。

##  問題概要

> All clam needs to do is snap and finite will turn into infinit...
>
> https://2021.ångstromctf.com/challenges



問題文の意味はよくわかりませんが、ダウンロードした実行ファイルを起動すると、下記のような問題文が表示され、入力を要求されます。

``` bash
$./infinity_gauntlet 

Welcome to the infinity gauntlet!
If you complete the gauntlet, you'll get the flag!
=== ROUND 1 ===
bar(?, 108, 377) = 102484
100
Wrong!
```

出題される問題は次の7パターンがあります。

``` bash
// foo関数
foo(?, %u) = %u
foo(%u, ?) = %u
foo(%u, %u) = ?

// bar関数
bar(?, %u, %u) = %u
bar(%u, ?, %u) = %u
bar(%u, %u, ?) = %u
bar(%u, %u, %u) = ?
```

この問題に正解するとROUNDの値が更新されて、次の問題が出題されます。

## 今回学んだこと

1. Pythonを使って対話的なプログラムの実行を自動化する
2. アセンブリがちょっと読めるようになる

## 解法

先に問題全体の解法を記載しておきます。
特に3番のFLAGの取得に関しては今回苦戦しました。

1. 与えられた実行ファイルを静的解析して、FLAGの文字列の格納先と格納方法を理解する
2. GDBを使って、foo関数とbar関数の詳細を理解する
3. 与えられた実行ファイルを静的解析して、FLAGの取得方法を理解する
4. 問題の解答とFLAGの取得を自動化するSolverを書く

## 1．FLAGの文字列の格納先と格納方法を理解する

まず、与えられた実行ファイルをローカルで動かそうとすると、次のようなエラーが返ってきます。

``` bash
$./infinity_gauntlet 
Couldn't find a flag file.
```

Ghidraでデコンパイルしてみると、どうやら実行時に同一ディレクトリ内のflag.txtを読み込んでいることが分かります。

``` c
local_40 = *(long *)(in_FS_OFFSET + 0x28);
setvbuf(stdout,(char *)0x0,2,0);
__stream = fopen("flag.txt","r");

// flag.txtの読み込みに失敗した場合
if (__stream == (FILE *)0x0) {
  puts("Couldn\'t find a flag file.");
  uVar6 = 1;
}
```

flag.txtの読み込みに成功すると、次のような処理を実行するようです。
※変数名は適当に修正してます。

```c
__s = FLAG;
fgets((char *)__s,0x100,__stream);
fclose(__stream);
sVar4 = strcspn((char *)__s,"\n");
iVar1 = (int)sVar4;
FLAG[iVar1] = 0;
if (iVar1 != 0) {
  bVar7 = 0;
  do {
    *__s = *__s ^ bVar7;
    bVar7 = bVar7 + 0x11;
    __s = __s + 1;
  } while (bVar7 != (byte)((char)sVar4 * '\x11'));
    
・・・
}
```

デコンパイルされたコードを読めばわかる通り、以下のような処理を実行しているようです。

1. flag.txtから取得した文字列を一文字ずつ取得
2. flagの一文字 XOR (0x11 * (文字の添え字 - 1))を計算
3. 暗号化されたflagの格納先に保存

この格納先のアドレスは、後々再登場するので覚えておくとよいです。
Ghidraでラベル名を付けておくとわかりやすいと思います。

## 2．foo関数とbar関数の詳細を理解する

次に出される問題を解くために、問題の性質を把握していきます。
便宜上関数と呼んでますが、処理自体はmain関数の内部に書かれてました。

どちらも、アセンブリソースから追っていくと大変なので、GDBを使って解析していきます。

まず、ディスアセンブルした結果から、以下の処理が入力値の受け取りと正解不正解の判定を行っていることがわかります。
そのため、このアドレスにbreakpointを仕掛けてGDBで解析していきます。

```assembly
0010125a e8 71 fe        CALL       __isoc99_scanf                                   undefined __isoc99_scanf()
          ff ff
0010125f 39 5c 24 0c     CMP        dword ptr [RSP + local_14c],EBX
00101263 0f 85 c7        JNZ        LAB_00101430
          01 00 00
00101269 83 c5 01        ADD        ebp,0x1
0010126c 48 8d 3d        LEA        RDI,[s_Correct!_Maybe_round_%d_will_get_001021   = "Correct! Maybe round %d will 
          bd 0e 00 00
00101273 31 c0           XOR        EAX,EAX
00101275 89 ee           MOV        ESI,ebp
00101277 e8 e4 fd        CALL       printf                                           int printf(char * __format, ...)

```

各問題の正解不正解を判断する部分をゼロフラグの書き換えで突破しながら何度か動かしてみると、上のアセンブルソースと合わせて次のことがわかります。

1. 0x0010125f で、入力された値とEBXレジスタの値を比較して、正解か不正解かを判定している。
2. 正解した場合は、EBPレジスタの値に1が加算される。

ここで、GDBを使って問題の正誤判定時のEBXレジスタの値を読むことで、問題の正解を知ることができ、各関数のルールを見つける手がかりとすることができます。
(残念ながら各計算式を逆算していく流れはボリュームが大きくなるので割愛します。)

なんやかんやすると、foo関数とbar関数がどのようなロジックで問題文の各要素の値を決定しているか知ることができました。

```
foo(A, B) = C
C = A ^ (B + 1) ^ 0x539
```

```
bar(A, B, C) = D
D = B * (C + 1) + A
```

プログラムから与えられる問題は、すべてfooかbarのどちらかの式の虫食い問題なので、この式を使用することで、すべての問題に正解することができます。

自動化スクリプトを作成して問題を解いてみました。

``` bash
=== ROUND 44 ===
bar(1160, ?, 58) = 124529
2091
Correct! Maybe round 45 will get you the flag ;)

=== ROUND 45 ===
foo(?, 355) = 38988
39953
Correct! Maybe round 46 will get you the flag ;)

=== ROUND 46 ===
foo(39, ?) = 41440
42237
Correct! Maybe round 47 will get you the flag ;)
```

しかし、10000問以上の問題に正解しても、FLAGが取得できませんでしたので、さらにプログラムの解析を進めて、FLAGがどのように取得できるのかを考える必要がありました。

## 3．FLAGの取得方法を理解する

さて、どうしたらFLAGが取得できるかというのを考えていきます。

問題に正解するとebpレジスタがインクリメントされることを先ほど確認したので、これが関係しているとあたりを付けてコードを追っていきました。

すると、ebpレジスタの値と0x31を比較して、大きい時に0x1504にジャンプすることがわかりました。

```assembly
0x00001291      83fd31         cmp ebp, 0x31
0x00001294      0f8f6a020000   jg 0x1504
```

そこで、0x1504以降の処理を見てみます。
どうやら、本来はランダムに生成されるはずの問題の解答(EBXレジスタの値)が、50問以上正解するとランダムではなく、以下の処理によって作成されるようになるようです！

````assembly
0x00001504      99             cdq
0x00001505      41f7fe         idiv r14d
0x00001508      8d1c2a         lea ebx, [rdx + rbp]
0x0000150b      4863d2         movsxd rdx, edx
0x0000150e      0fb6441410     movzx eax, byte [rsp + rdx + 0x10]
0x00001513      0fb6db         movzx ebx, bl
0x00001516      c1e308         shl ebx, 8
0x00001519      09c3           or ebx, eax
0x0000151b      e98bfdffff     jmp 0x12ab ;次の問題の準備開始地点
````

このままだと読みづらいので、Ghidraのデコンパイル結果を見てみます。

```c
EBX = (FlagLength % iVar1 + 現在の正解数 & 0xff) << 8 | \
	(uint)FLAGARR[FlagLength % iVar1];
```

どうやら、初めに暗号化したflagの文字列を利用してEBXに値を格納しているようです。
具体的には、`「現在までの正解数 + flag文字の位置」下位8ビットを取り出し、左に8bitシフトしたもの`と`「暗号化されたフラグをint変換したもの」`のORを取ったものがEBXに格納されています。

つまり、EBXが`0x9c3f`で、現在までの正解数が152回である時は、以下のようにしてFlagの文字を求めることができます。

```
EBX   0x9c3f
正解数 0x98(152) のとき

1. 0x9c - 0x98 = 4 から、下位バイトは4番目の文字
2. 下位の1バイトは3fなので、Flagの4番目の暗号化された文字は 0x3f とわかる
3. 暗号化は Flagの文字 XOR (0x11 * Flagの添え字)なので4番目の場合は 
   0x3f XOR 0x33 となる
4. 4番目のFlagの文字は { であるとわかる
```

ここまでわかればあとは簡単で、`現在までの正解数`を保持しつつ自動的に問題を解くスクリプトを作成し、正解数が50問を超えたタイミングから上記のデコード処理を実施していくだけで、Flagの文字列が取得できます。



・・・、嘘でした！！
このままだと、16番目以降の文字が文字化けしてしまいます。

これ、最初なんでこんな事態になるのか全く分からなくて結構ハマりました。

しばらく悩んだ結果、Flagの文字を0x11の倍数でXOR暗号化するこの部分で、実際に暗号化に使っているのがclレジスタであることに気づきました。

```assembly
0x00001190      300a           xor byte [rdx], cl
0x00001192      83c111         add ecx, 0x11
```

clレジスタはecxレジスタの下位8bitのレジスタなので、ここでXOR演算に使用しているのも1Byteの値ということが分かります。

0x11の倍数について計算したところ、ちょうど15倍目が0xFFであり、16倍以降は8bitに収まらない桁数になります。
最初にSolverを回した段階でFlagの文字数が26文字なのはわかっていたので、16文字目から26文字目までの文字化けが発生しないように、256でXORを取ってあげるようにSolverを修正することでFlagが取得できました。

## 4． 問題の解答とFLAGの取得を自動化するSolverを書く

ここからは完全にWriteUpとしては蛇足ですが、PythonスクリプトでELFの対話的な実行を自動化するのは今回が初めてだったので追記しておきます。

Pythonでプログラムの対話的な実行を実現するには、[pyexpect](https://pexpect.readthedocs.io/en/stable/)を使います。

使い方は非常に簡単で、CLIコマンドを指定して実行するプロセスを呼び出し、特定の文字列が出力されるタイミングで、任意の入力を与えることができます。

以下に今回利用したTipsについてまとめます。

### プログラムを起動する

```python
child = pexpect.spawn ('起動するコマンド', logfile=sys.stdout.buffer)
・・・
child.close()
```

`起動するコマンド`の欄に、`nc shell.actf.co 21700`や`./実行ファイル名`を入力することで、対話的なコマンド処理を自動化するためのプロセスを立ち上げます。

このとき、`logfile=sys.stdout.buffer`で出力を吐き出す先を標準出力にしておくことで、普通にコンソールからプログラムを実行したときと近い使用感で処理を自動化できます。

### 任意のタイミングで入力を与える

```python
child.expect(r'待ち受ける文字（正規表現）')
child.sendline('送信する文字')
```

`expect()`に与えた正規表現にマッチする文字列が現れるまで、プログラムを待機します。

`sendline`は、プロセスに文字列を改行付きで送信します。

`expect()`は、マッチする文字列が現れると以下の

1. before: 正規表現にマッチした文字列より前に標準出力されていた文字列
2. after: 正規表現にマッチした文字列
3. buffer: 正規表現マッチ時、マッチした文字列より後に標準出力されていた文字列

今回作成したSolverでは、`\n`ですべての行にマッチさせた上で、直前に表示されていた文字列（問題文）にfooかbarが含まれるかで条件分岐し、処理を設定しています。

## 作成したSolver

```python
import io
import os
import sys
import time
import re
import pexpect

arr = ["-1" for i in range(50)]
x11 = [i * 17 for i in range(50)]

def revflag(ans, rounds):
    pos = (ans >> 8) - rounds
    pos = pos
    flag = (ans & 0x00ff)
    if pos > 15:
        flag = chr(flag ^ x11[pos] ^ 256)
    else:
        flag = chr(flag ^ x11[pos])

    print("ans {}".format(hex(ans)))
    print("pos {}".format(pos))
    print("flag {}".format(flag))

    arr[pos] = flag
    return

def getfoo(S):
    # foo(?, 13) = 11231
    reA = r"^foo\(([0-9]{1,9}|\?),"
    reB = r",\s([0-9]{1,9}|\?)\)"
    reC = r"=\s([0-9]{1,9}|\?)"

    A = re.findall(reA, S)[0]
    B = re.findall(reB, S)[0]
    C = re.findall(reC, S)[0]

    return A, B, C

def getbar(S):
    # bar(?, 305, 449) = 138744
    reA = r"^bar\(([0-9]{1,9}|\?),"
    reB = r",\s([0-9]{1,9}|\?),"
    reC = r",\s([0-9]{1,9}|\?)\)"
    reD = r"=\s([0-9]{1,9}|\?)"

    A = re.findall(reA, S)[0]
    B = re.findall(reB, S)[0]
    C = re.findall(reC, S)[0]
    D = re.findall(reD, S)[0]

    return A, B, C, D

def foo(A, B, C):
    ans = 0    
    if A == '?':
        cd = int(C) ^ 1337
        ans = (int(B) + 1) ^ cd
         
    if B == '?':
        cd = int(C) ^ 1337
        ans = (int(A) ^ cd) - 1

    if C == '?':
        ans = int(A) ^ (int(B) + 1) ^ 1337

    return int(ans)  


def bar(A, B, C, D):
    ans = 0
    if A == '?':
        bd = int(B) * (int(C) + 1)
        ans = int(D) - bd
         
    if B == '?':
        dd = int(D) - int(A)
        ans = (dd // (int(C) + 1))
         
    if C == '?':
        dd = int(D) - int(A)
        ans = (dd // int(B)) - 1
         
    if D == '?':
        ans = int(B) * (int(C)+1) + int(A)

    return int(ans)


child = pexpect.spawn ('nc shell.actf.co 21700', logfile=sys.stdout.buffer)

counter = 1
while(True):
    try:
        child.expect(r'\n')
        S = str(child.before)
        # print(S[2:-3])

        if counter < 50:            
            if "bar" in S:
                counter += 1
                A, B, C, D = getbar(S[2:-3])
                # print(A, B, C, D)

                ans = bar(A, B, C, D)
                child.sendline(str(ans))
                
            if "foo" in S:
                counter += 1
                A, B, C = getfoo(S[2:-3])

                ans = foo(A, B, C)
                child.sendline(str(ans))
        
        else:
            if "bar" in S:
                A, B, C, D = getbar(S[2:-3])
                # print(A, B, C, D)

                ans = bar(A, B, C, D)
                revflag(ans, counter)
                print("Count : {} Ans : {}".format(hex(counter), hex(ans)))

                child.sendline(str(ans))
                counter += 1
                
            if "foo" in S:
                A, B, C = getfoo(S[2:-3])

                ans = foo(A, B, C)
                revflag(ans, counter)
                print("Count : {} Ans : {}".format(hex(counter), hex(ans)))

                child.sendline(str(ans))
                counter += 1

        if counter > 254:
            break

    except Exception as e:
        print(e)
        break

child.close()
print("".join(arr))
```


## まとめ

というわけで、ångstromCTF 2021のReversing問題から、Infinite Gauntletに挑戦したWriteUpを書きました。

解き切るまでに結構時間がかかりました（5時間くらい）が、この問題にじっくり取り組んだことで、アセンブリやレジスタなどの知識と理解がかなり深まったように感じます。

今後もいろんなReversing問題にチャレンジしていこうと思います。

### 参考＆問題を解く際に使った書籍

### Books

- [大熱血！ アセンブラ入門](https://amzn.to/3mceJHH)
  - アセンブリ読むときはとりあえずこの本を適宜参照してます。
- [解析魔法少女 美咲ちゃん マジカル・オープン!](https://amzn.to/2PsWQbI)
  - PEモジュール向けですが、プログラムの流れを追うのにいつも参考にしてます。
  - 2004年の本なので内容が少し古いことに注意。
- [リバースエンジニアリングツールGhidra実践ガイド ~セキュリティコンテスト入門からマルウェア解析まで~](https://amzn.to/3t4Lolh)
  - Ghidraについて日本語で書かれた書籍としてはほぼ唯一の書籍。
  - CTFつよつよのメンバーが書いていて、内容も非常にわかりやすい(わかるとは言ってない)。

### Web

- [radare2 覚書 - /var/log/Sawada.log](https://takuzoo3868.hatenablog.com/entry/radare2_love)

- [Pexpect version 4.8 — Pexpect 4.8 documentation](https://pexpect.readthedocs.io/en/stable/)
