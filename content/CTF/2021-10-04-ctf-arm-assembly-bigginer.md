---
title: CTFで学ぶARMアセンブリ
date: "2021-10-04"
template: "post"
draft: false
slug: "ctf-arm-assembly-bigginer"
category: "CTF"
tags:
  - "CTF"
  - "Reversing"
  - "picoCTF"
description: "picoCTF2021のReversing問題、ARMssemblyシリーズを通して、ARM向けのアセンブリを学んでいきます。"
socialImage: "/media/cards/no-image.png"
---

## はじめに

2021/3/31まで行われていた[picoCTF2021](https://play.picoctf.org/practice)にチャレンジしてました。
Reversingカテゴリの問題に対象を絞って全完を目指していたのですが、残念ながら悔しい結果に終わりました。

今回は、picoCTF2021のReversing問題の中から、「ARMssembly」シリーズの問題が非常に勉強になったので、WriteUpを書いていこうと思います。

## 今回学んだこと

1. ARM向けアセンブリのニーモニック
2. アセンブリコードから手動でデコンパイルするポイント

## ARMssembly シリーズの解法

さて、「ARMssembly」シリーズは全部で5問出題されてましたが、すべての問題において解き方は共通でしたので、先に書いておこうとおもいます。

「ARMssembly」シリーズの問題は、以下の手順で解くことができました。

1. 問題として提供されたアセンブリコードを眺める
2. main 関数からの流れを追っていく
   - ググる
   - ARMベースのCPUを搭載した環境（ラズパイを使用）でCのソースコードからアセンブリを生成し、問題コードと比較する
3. 解く

ではさっそく一問目から順に解いていきます。

## ARMssembly 0
### 問題

変数が2つ与えられるので、最終的な出力を答えよ、という問題でした。

>Description
>
>What integer does this program print with arguments `4112417903` and `1169092511`? 

```assembly
; 問題コード
	.arch armv8-a
	.file	"chall.c"
	.text
	.align	2
	.global	func1
	.type	func1, %function
func1:
	sub	sp, sp, #16
	str	w0, [sp, 12]
	str	w1, [sp, 8]
	ldr	w1, [sp, 12]
	ldr	w0, [sp, 8]
	cmp	w1, w0
	bls	.L2
	ldr	w0, [sp, 12]
	b	.L3
.L2:
	ldr	w0, [sp, 8]
.L3:
	add	sp, sp, 16
	ret
	.size	func1, .-func1
	.section	.rodata
	.align	3
.LC0:
	.string	"Result: %ld\n"
	.text
	.align	2
	.global	main
	.type	main, %function
main:
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	x19, [sp, 16]
	str	w0, [x29, 44]
	str	x1, [x29, 32]
	ldr	x0, [x29, 32]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	mov	w19, w0
	ldr	x0, [x29, 32]
	add	x0, x0, 16
	ldr	x0, [x0]
	bl	atoi
	mov	w1, w0
	mov	w0, w19
	bl	func1
	mov	w1, w0
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	printf
	mov	w0, 0
	ldr	x19, [sp, 16]
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
```

### main関数を読む
とりあえずmain関数から追っていきます。
結構長いですが、次の項目に着目しました。

- `bl atoi`
- `bl atoi`
- `bl func1`
- `bl printf`

`bl`は、”Branch with Link.”の略で、いわゆるCALL命令のようなものと認識してます。
詳細については[Arm64(ARMv8) Assembly Programming (08) 分岐命令](https://www.mztn.org/dragon/arm6408cond.html)を参照しました。

一言で表すと、「`bl`の直後に書かれたアドレスにジャンプし、`RET`命令にぶつかったら戻ってくる」という動きをします。

今回は`atoi`関数が2つあることから、受け取った変数を数値に変換して`func1`関数の引数として送り、戻り値を`printf`で表示する処理をしていることが分かります。

### Cのコードに落とし込んで確認
ここまで読めたところで、main関数部分をリバースエンジニアリングしたCのコードを書いて、想定があっているか確認しましょう。

こんなコードを書いてみました。

```c
#include <stdio.h>
#include <stdlib.h>

unsigned int func1(unsigned int n1, unsigned int n2)
{
    return 0;
}

int main(char a[128], char b[128]) {
    unsigned int n1 = atoi(a);
    unsigned int n2 = atoi(b);
    unsigned int ans = func1(n1, n2);
    printf("%u", ans);

    return 0;
}
```

これをラズパイ上のGCCで`gcc -S sample.c -o sample.lst`のようにして、オブジェクトファイルにしてみます。

長いのでmain関数部分のみ抜き出したところ、次のようなアセンブリコードが生成されました。
問題コードと比較しても、ほぼほぼ一致してますね！

```assembly
main:
.LFB7:
      .cfi_startproc
      stp     x29, x30, [sp, -48]!
      .cfi_def_cfa_offset 48
      .cfi_offset 29, -48
      .cfi_offset 30, -40
      mov     x29, sp
      str     x0, [sp, 24]
      str     x1, [sp, 16]
      ldr     x0, [sp, 24]
      bl      atoi
      str     w0, [sp, 36]
      ldr     x0, [sp, 16]
      bl      atoi
      str     w0, [sp, 40]
      ldr     w1, [sp, 40]
      ldr     w0, [sp, 36]
      bl      func1
      str     w0, [sp, 44]
      ldr     w1, [sp, 44]
      adrp    x0, .LC0
      add     x0, x0, :lo12:.LC0
      bl      printf
      mov     w0, 0
      ldp     x29, x30, [sp], 48
      .cfi_restore 30
      .cfi_restore 29
      .cfi_def_cfa_offset 0
      ret
      .cfi_endproc
```

### func1関数を読む

では、続いて2つの引数が渡された後のfunc1関数を見ていきます。
問題コードのこの部分ですね。

```assembly
func1:
	sub	sp, sp, #16
	str	w0, [sp, 12]
	str	w1, [sp, 8]
	ldr	w1, [sp, 12]
	ldr	w0, [sp, 8]
	cmp	w1, w0
	bls	.L2
	ldr	w0, [sp, 12]
	b	.L3
.L2:
	ldr	w0, [sp, 8]
.L3:
	add	sp, sp, 16
	ret
	.size	func1, .-func1
	.section	.rodata
	.align	3
```

まずは`str`と`ldr`命令についてみていきます。

簡単に言えば、`str`はいわゆるストア命令でレジスタの内容を指定したアドレスに格納します。
一方、`ldr`はいわゆるロード命令で、指定したアドレスの情報をレジスタに読み込みます。

`[sp, 12]`の部分は、レジスタ間接という、CPUがメモリにアクセスする際のアドレス指定方法の一つで、スタックポインタに指定のオフセット分加算したアドレスを指定しています。

というわけで、`func1`は引数として受け取った値を呼び出して比較し、その結果によって分岐していることがわかります。

ここで分岐命令`bls`について確認します。
`ls`は、"lower or same（<=）"を意味します。

ここから、func1について次のようなCコードに落とし込むことができます。

```c
#include <stdio.h>
#include <stdlib.h>

unsigned int func1(unsigned int n1, unsigned int n2)
{
    if (n2 > n1)
    {
        return n1;
    }
    else
    {
        return n2;
    }
}
```

`bls`は"lower or same（<=）"と書きましたが、ここで分岐先にジャンプするのは、IFの条件を「満たさなかった」時なので、Cのコードに落とし込むときの条件式は`n1 > n2`となります。

ちなみに、関数呼び出しの時の引数は「後ろから」スタックに積まれていくため、最初に呼び出されている`[sp, 12]`に格納された情報が一つ目の引数(=n1)であるとわかります。

それでは、このコードからオブジェクトファイルを生成してみましょう。

```assembly
func1:
.LFB6:
	.cfi_startproc
	sub	sp, sp, #16
	.cfi_def_cfa_offset 16
	str	w0, [sp, 12]
	str	w1, [sp, 8]
	ldr	w1, [sp, 8]
	ldr	w0, [sp, 12]
	cmp	w1, w0
	bls	.L2
	ldr	w0, [sp, 12]
	b	.L3
.L2:
	ldr	w0, [sp, 8]
.L3:
	add	sp, sp, 16
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
```

問題コードのアセンブリとほぼ一致し、想定が正しいことがわかりました。

最後は、このコードから生成した実行ファイルに引数を与えて実行すると、FLAGとなる数列が取得できます。

## ARMssembly1
### 問題

最終的にプログラムが”win”を出力するような引数を答えなさいという問題でした。
1問目より少しコード量が多いですね。

>Description
>
>For what argument does this program print `win` with variables `81`, `0` and `3`? 

```assembly
	.arch armv8-a
	.file	"chall_1.c"
	.text
	.align	2
	.global	func
	.type	func, %function
func:
	sub	sp, sp, #32
	str	w0, [sp, 12]
	mov	w0, 81
	str	w0, [sp, 16]
	str	wzr, [sp, 20]
	mov	w0, 3
	str	w0, [sp, 24]
	ldr	w0, [sp, 20]
	ldr	w1, [sp, 16]
	lsl	w0, w1, w0
	str	w0, [sp, 28]
	ldr	w1, [sp, 28]
	ldr	w0, [sp, 24]
	sdiv	w0, w1, w0
	str	w0, [sp, 28]
	ldr	w1, [sp, 28]
	ldr	w0, [sp, 12]
	sub	w0, w1, w0
	str	w0, [sp, 28]
	ldr	w0, [sp, 28]
	add	sp, sp, 32
	ret
	.size	func, .-func
	.section	.rodata
	.align	3
.LC0:
	.string	"You win!"
	.align	3
.LC1:
	.string	"You Lose :("
	.text
	.align	2
	.global	main
	.type	main, %function
main:
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	w0, [x29, 28]
	str	x1, [x29, 16]
	ldr	x0, [x29, 16]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	str	w0, [x29, 44]
	ldr	w0, [x29, 44]
	bl	func
	cmp	w0, 0
	bne	.L4
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	puts
	b	.L6
.L4:
	adrp	x0, .LC1
	add	x0, x0, :lo12:.LC1
	bl	puts
.L6:
	nop
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits

```

### main関数を読む
とりあえずmain関数から追っていきます。
これまでの問題で紹介した命令については割愛します。

main関数で注目すべき点は最後の処理ですね。

前の問題と同様、引数を受けとり、それをfunc1関数に渡しています。
その後、func1関数の戻り値と0を比較した結果で、winかloseのどちらを表示するかを決定しているようです。

そこで、まずはこの部分をCのソースコードに落としこんでいきたいと思います。

`bne .L4`は”not equal”を意味します。
つまり、func1の戻り値と0の比較をした時に、`func1の戻り値 != 0`の状態であれば、`.L4`によって指定されたアドレスにジャンプするというわけです。

### Cのコードに落とし込んで確認

ここまで読めたところで、main関数部分をリバースエンジニアリングしたCのコードを書いて、想定があっているか確認しましょう。

こんなコードを書いてみました。

```c
#include <stdio.h>
#include <stdlib.h>

unsigned int func1(unsigned int n1)
{
    return 0;
}

int main(char a[128]) {
    unsigned int n1 = atoi(a);
    unsigned int ret = func1(n1);

    if (ret == 0)
    {
        printf("win");
    }
    else
    {
        printf("lose");
    }

    return 0;
}
```

これをラズパイ上のGCCで`gcc -S sample.c -o sample.lst`のようにして、オブジェクトファイルにしてみます。

長いのでmain関数部分のみ抜き出したところ、次のようなアセンブリコードが生成されました。
問題コードと比較し、一致することがわかると思います。

```assembly
main:
.LFB7:
	.cfi_startproc
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	mov	x29, sp
	str	x0, [sp, 24]
	ldr	x0, [sp, 24]
	bl	atoi
	str	w0, [sp, 40]
	ldr	w0, [sp, 40]
	bl	func1
	str	w0, [sp, 44]
	ldr	w0, [sp, 44]
	cmp	w0, 0
	bne	.L4
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	printf
	b	.L5
.L4:
	adrp	x0, .LC1
	add	x0, x0, :lo12:.LC1
	bl	printf
.L5:
	mov	w0, 0
	ldp	x29, x30, [sp], 48
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
```

### func1関数を読む

これで勝利条件が分かりました。
プログラム実行時に取得した値をfunc1の引数とした際に、func1から返却される戻り値が0になれば、”win”が出力されます。

では、func1関数を見ていきましょう。

```assembly
func:
	sub	sp, sp, #32
	; 1. 引数を[sp, 12]に格納
	str	w0, [sp, 12]
	
	; 2. [sp, 16]に81を格納
	mov	w0, 81
	str	w0, [sp, 16]
	
	; 3．[sp, 20]に0を格納
	str	wzr, [sp, 20]
	
	; 4．[sp, 24]に3を格納
	mov	w0, 3
	str	w0, [sp, 24]
	
	; 5．[sp, 20] と [sp, 16] の情報を読み込んで左シフト
	ldr	w0, [sp, 20]
	ldr	w1, [sp, 16]
	lsl	w0, w1, w0
	str	w0, [sp, 28]
	
	; 6．5の結果を[sp, 24]で割る
	ldr	w1, [sp, 28]
	ldr	w0, [sp, 24]
	sdiv	w0, w1, w0
	str	w0, [sp, 28]
	
	;7. 6の結果から、func1に渡した引数を引いてreturn
	ldr	w1, [sp, 28]
	ldr	w0, [sp, 12]
	sub	w0, w1, w0
	
	str	w0, [sp, 28]
	ldr	w0, [sp, 28]
	add	sp, sp, 32
	ret
```

変数の流れが分かりやすいように、問題コードにコメントを入れてみました。

1. 引数を[sp, 12]に格納
2. [sp, 16]に81を格納
3. [sp, 20]に0を格納
4. [sp, 24]に3を格納

1と2と4は既出なので割愛します。

3の命令については、いわゆるゼロレジスタの表現です。
このゼロレジスタを使うことで、間にほかのレジスタを挟むことなく、指定したアドレスに直接0を格納することができます。

[参考：ARM Cortex-A Series Programmer's Guide for ARMv8-A](https://developer.arm.com/documentation/den0024/a/An-Introduction-to-the-ARMv8-Instruction-Sets/The-ARMv8-instruction-sets/Registers)

 さて、変数の代入が終わったところで、以降の処理を見てみます。

5. [sp, 20] と [sp, 16] の情報を読み込んで左シフト

`lsl`は、論理左シフト命令です。
データを左にずらし、空いたbitは0で穴埋めされます。

6、7については、この左シフトの結果に対して、3で割った後、与えた引数を引くという処理をしています。
つまり、最終的にこの演算結果が0になる引数が、今回のフラグです。

ここまで読めればもう簡単に解くことができますが、せっかくなのでfunc1についてもCのコードに落としこんでみましょう。
このままオブジェクトファイルを生成すると、なぜかsdivの部分が再現できませんでしたが、概ね正しい実装かなと 思います。

```c
unsigned int func1(unsigned int n1)
{
    unsigned int n2 = 81;
    unsigned int n3 = 0;
    unsigned int n4 = 3;

    int ret;
    ret = n2 << n3;
    ret = ret / 3;
    ret = ret - n1;

    return ret;
}
```

このコードのfunc1の戻り値が0になるような引数がFLAGとなる数列ということがわかります。

## まとめ
アセンブリコードとじっくり向き合って、自分の手でCのコードに書き換えていくのは非常に楽しい時間でした。
作問社の方に感謝を。

残りの問題については、そのうちWriteUpを追記するかもしれません。

ちなみに、余談ですが、アセンブリの勉強のためにおすすめの本について書いておきます。
良ければ参考にしてください。

### おすすめ書籍

- [大熱血！ アセンブラ入門](https://amzn.to/3mceJHH)
  - 長所：大体なんでも書いてある。ARMのアセンブリもこの本を参考にしつつ解きました。
  - 短所：分厚い、高い、難しい(そう)。まだ全部読めてません笑
  - 
- [解析魔法少女 美咲ちゃん マジカル・オープン!](https://amzn.to/2PsWQbI)
  - 長所：美咲ちゃんが可愛い。読み物感覚で読める。初心者にもわかりやすい。
  - 短所：古い（Windows XP とかの時代です）

- [[改訂3版]基本情報技術者らくらく突破CASL II](https://amzn.to/3fyymZo)
  - 長所：「まじでアセンブリなんもわからん」って人にこそおすすめ。8bitアセンブリで理解しやすく、問題（基本情報技術者試験）や解説が豊富に落ちてる。
  - 短所：自分で書いたCのソースから挙動を確認できない。32bitアセンブリとの違いについては別途勉強する必要がある。