---
title: Herekaze mini CTF 2021 Writeup
date: "2021-12-29"
template: "post"
draft: false
slug: "ctf-harekazectf-2022"
category: "CTF"
tags:
  - "CTF"
  - "Reversing"
  - "Security"
description: ""
socialImage: "/media/cards/ctf-harekazectf-2022.png"
---

12/24に開催されていた[Harekaze mini CTF 2021](https://harekaze.com/ctf/2021.html)に参加してました。

0neP@addingとして参加して29位でした。

難しめのReversing問題が中々解けないので要精進です。

## Crackme(Rev)

デコンパイル結果を見ると、入力された文字に対して一文字ずつ計算を行い、演算結果が0より大きくなる文字がFlagの文字になることがわかりました。

Reversingして逆算することもできそうでしたが、総当たり攻撃でも数分でFlagが特定できそうだったため、以下のスクリプトでGDBの解析を自動化してFlagを特定しました。

``` python
import gdb

BINDIR = "~/Downloads"
BIN = "crackme"
INPUT = "./in.txt"
BREAK = "0x55555555523f"

gdb.execute('file {}/{}'.format(BINDIR, BIN))
gdb.execute('b *{}'.format(BREAK))

Flag = list("HarekazeCTF{quadrat1c_3quati0n}")
counter = len(Flag)
Flag += ["." for i in range(0x1f-len(Flag))]

table = "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!#$=}{"
print("".join(Flag))

while True:
    print("===============================================")

    for t in table:
        Flag[counter] = t
        gdb.execute('run {}'.format("".join(Flag)))

        if counter > 0:
            for i in range(counter):
                print("next")
                gdb.execute('c')
        
        r = gdb.parse_and_eval("$al")
        print(r)
        if r != 0x0:
            counter += 1
            # print("".join(Flag))
            break
        print("".join(Flag))

gdb.execute('quit')
print("".join(Flag))
```

## まとめ

年内最後のCTFでしたが、来年はもっと難しい問題も解けるように勉強したいと思います。