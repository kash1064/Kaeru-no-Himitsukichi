---
title: ParrotOSでアップデートを実行したときに ”deb.parrot.sh error” で通信がタイムアウトして失敗する問題の解決方法
date: "2021-10-29"
template: "post"
draft: false
slug: "hackthebox-parrot-timeout"
category: "HackTheBox"
tags:
  - "HackTheBox"
  - "Linux"
  - "ParrotOS"
  - "備忘録"
description: "Hack The BoxやCTFで使っているParrotOSの環境を立て直すことにしたので、備忘録代わりにセットアップ方法についてまとめておこうと思い、この記事を書きました。"
socialImage: "/media/cards/no-image.png"
---

`apt update`コマンドを実行したときに、`deb.parrot.sh error`が出て接続がタイムアウトする場合の対処方法についての備忘録です。

僕の環境では、`sudo parrot-upgrade`コマンドでParrotOSのシステムをアップグレードしたら問題が解消されました、

``` bash
sudo parrot-upgrade
```

もしこのコマンドでも問題が解決しない場合は、以下の参考リンクのForumのスレッドを見てみると解決するかもしれません。

参考：[Cant access deb.parrot.sh - Support / Installation and Configuration - Parrot Community](https://community.parrotsec.org/t/cant-access-deb-parrot-sh/10893)
