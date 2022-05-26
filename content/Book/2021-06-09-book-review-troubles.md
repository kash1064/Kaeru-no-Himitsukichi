---
title: Re:VIEW Starterが何もしてないのに壊れたときの対処法
date: "2021-06-09"
template: "post"
draft: false
slug: "book-review-troubles"
category: "Book"
tags:
  - "Book"
  - "Note"
  - "Re:VIEW"
description: "この記事では、「まじで何もしてないのにRe:VIEW StarterでPDF生成ができなくなった」時の対処法について紹介します"
socialImage: "/media/cards/no-image.png"
---

この記事では、「まじで何もしてないのにRe:VIEW StarterでPDF生成ができなくなった」時の対処法について紹介します。

最近、新たなチャレンジとして、技術書典での頒布を目的とした技術同人誌の執筆を行っています。
執筆活動のために、Re:VIEW Starterというツールを使用しております。

参考：[技術系同人誌を書く人の味方「Re:VIEW Starter」の紹介 - Qiita](https://qiita.com/kauplan/items/d01e6e39a05be0b908a1)

ここで、突然PDF生成ができなくなる問題が発生したので、その解消方法について記録しておきます。

具体的にはRe:VIEW Starterの生成する“*-pdf”ディレクトリ直下の以下の拡張子を持つファイルをすべて削除しました。

- .tex
- .aux
- .dvi
- .log
- .maf
- .mtc*
- .out
- .toc

## 発生した問題

唐突に、Re:VIEW Starterが以下のようなエラーを吐いてPDFの生成に失敗するようになりました。

```
Package pagecolor Warning: Option nopagecolor=none requested but \nopagecolor u
nknown:
(pagecolor)                By option nopagecolor the "colour" to be used with\n
opagecolor
(pagecolor)                is set. The current value is "none" (maybe by defaul
t),
(pagecolor)                but command \nopagecolor is undefined.
(pagecolor)                Therefore the colour cannot be "none".
(pagecolor)                Please change the option accordingly!
(pagecolor)                As first aid nopagecolor is now set to white
(pagecolor)                 on input line 116.


Package pagecolor Warning: Option pagecolor=none (maybe by default) used,
(pagecolor)                but \nopagecolor is unknown.
(pagecolor)                Please use anotheroption value;
(pagecolor)                white
(pagecolor)                will be used now
(pagecolor)                 on input line 127.

)) (./mycolophon.sty) (./mystyle.sty) (./book.aux)
Runaway argument?
{\contentsline {subsection}{\nu
./book.tex:193: File ended while scanning use of \@writefile.
<inserted text>
                \par
l.193 \begin{document}

No pages of output.
Transcript written on book.log.
*
* ERROR (review-pdfmaker):
*  failed to run command: uplatex -halt-on-error -file-line-error book.tex
*
make: *** [Makefile:45: create_pdf] Error 1
```

このようなケースは、大抵の場合"*.re"ファイルの内容に問題があります。*
*しかしながら、今回発生した問題は、全く問題のない"*.re"ファイルを使用してもPDFの生成に失敗する問題でした。

結局原因の特定には至らなかったものの、どうやらTexによるコンパイルに問題がありそうだということで、下記のファイルをすべて削除したところ、無事問題が解消されました。

- .tex
- .aux
- .dvi
- .log
- .maf
- .mtc*
- .out
- .toc

本当に突然発生した事象で原因もわからず、1時間ほど浪費していましました。
とりあえずPDFの生成に失敗したら、過去に作成されたファイルを削除してみるとよさそうということで備忘録としてまとめておきました。