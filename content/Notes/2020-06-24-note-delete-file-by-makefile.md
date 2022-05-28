---
title: "TypescriptのコンパイルとJSファイルの削除を一括で簡単に実行するMakefileの備忘録"
date: "2020-06-23"
template: "post"
draft: false
slug: "note-delete-file-by-makefile"
category: "Notes"
tags:
  - "Notes"
  - "Makefile"
description: "ディレクトリ内のTypescriptのコンパイルを一括で実行したり、Githubにプッシュする前に、コンパイルされたJSファイルを削除するために僕が利用しているMakefileスクリプトの備忘録です。"
socialImage: "/media/cards/no-image.png"
---

ディレクトリ内の**Typescriptのコンパイルを一括で実行**したり、Githubにプッシュする前に、**コンパイルされたJSファイルを削除**したいと思ったことはありませんか？

今回は、その実現のために僕が利用しているMakefileスクリプトの備忘録です。  
使用するスクリプトは以下のとおりです。

**clearが、srcというディレクトリの配下のJavascriptをすべて削除**するスクリプトです。  
また、**ts_compileは、srcというディレクトリの配下のTypescriptをすべてコンパイル**するスクリプトです。

```makefile
SHELL=/bin/bash

clear:
	-find src/ -name *.js -exec rm {} \;

ts_compile:
	-find src/ -name *.ts -exec tsc {} \;
```

findで見つかったファイル名をexecに流すという形にすることで、もしも対象ファイルが見つからなかった場合は、**エラーを発生させずにスキップ**してくれるようになります。

## まとめ 

以上、僕がTypescript環境で使用しているMakefileのスクリプトでした。