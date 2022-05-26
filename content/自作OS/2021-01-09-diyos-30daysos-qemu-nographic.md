---
title: "30日OSのブートイメージをQemuのCUIで動かすnographicオプションの使い方"
date: "2021-01-09"
template: "post"
draft: false
slug: "diyos-30daysos-qemu-nographic"
category: "自作OS"
tags:
  - "自作OS"
  - "30日OS"
  - "QEMU"
  - "Notes"
description: "自作OSをCUIで動かしたい時に使うQemuのnographicオプションについて紹介します。"
socialImage: "/media/cards/no-image.png"
---

**自作OSをCUIで動かしたい時に使うQemuのnographicオプション**についてまとめます。

今回動かすバイナリは、30日OSの1日目で作成する、何もしないブートイメージです。

30日OSの書籍と異なる点として、30日OSを執筆された方の自作ツールではなく、汎用アセンブラのNASMを利用しています。  

## QemuをCUIで動かす

結論から書きますが、以下のコマンドでブートイメージをQemuのCUI実行することができました。

```bash
qemu-system-x86_64 -drive file=boot.img,format=raw -nographic
```

おそらくこれがQemuのCUIでバイナリを実行する際のミニマムなオプションかと思います。

それぞれのオプションの意味は以下のとおりです。

```
-drive:     
    ファイルをドライブイメージとして使用するためのオプション
    必須の引数として、[file=file]をとる

    [file=file][,if=type][,bus=n][,unit=m][,media=d][,index=i]
    [,cache=writethrough|writeback|none|directsync|unsafe][,format=f]
    [,snapshot=on|off][,rerror=ignore|stop|report]
    [,werror=ignore|stop|report|enospc][,id=name][,aio=threads|native]
    [,readonly=on|off][,copy-on-read=on|off]
    [,discard=ignore|unmap][,detect-zeroes=on|off|unmap]
    [[,bps=b]|[[,bps_rd=r][,bps_wr=w]]]
    [[,iops=i]|[[,iops_rd=r][,iops_wr=w]]]
    [[,bps_max=bm]|[[,bps_rd_max=rm][,bps_wr_max=wm]]]
    [[,iops_max=im]|[[,iops_rd_max=irm][,iops_wr_max=iwm]]]
    [[,iops_size=is]]
    [[,group=g]]

-nographic：
    GUIを無効にして、シリアルI/Oをコンソールにリダイレクトする
```

上記のとおり、-driveオプションは、NASMで作成したブートイメージ(boot.img)をドライブイメージに指定するためのオプションです。

fileとformatは、この-driveオプションの引数になります。

```bash
-drive file=boot.img,format=raw
```

-driveオプションに必須の引数は[file=file]のみですが、今回はformat=rawの指定も入れています。  
format=rawの指定がなくとも、CUIでQemuを起動することはできますが、次のような警告が出力されます。

    WARNING:
    Image format was not specified for '/haribote/boot.img' and probing guessed raw.Specify the 'raw' format explicitly to remove the restrictions.

次に、-nographicオプションですが、これがCUIでQemuを起動するためのオプションです。  
ヘルプに記載のとおり、シリアルI/O(デバイス間で通信されるデータ)をコンソールにリダイレクトしてくれます。


## QemuのCUI停止する 

QemuのCUIが起動できたら、元のコンソールに戻ります。  
コンソールに戻るには、次のキーを「連続して」入力します。

    Ctrl + A
    X

「Ctrl + A」を押したら、キーを離して「X」を入力してください。  
これでQemuが停止します。

## まとめ 

CUIで起動テストできると、作業がちょっとスムーズになった気がします。  
WSL上のDockerでそのまま動作確認ができるのがうれしい。

ちなみに上記の動作確認は以下のDockerイメージ上で行いました。  
参考までに。

```dockerfile
FROM python:3.8
ENV PYTHONUNBUFFERED 1

ENV TZ=Asia/Tokyo

RUN mkdir -p /haribote
ENV HOME=/haribote
WORKDIR $HOME

RUN useradd ubuntu
RUN dpkg --add-architecture i386
RUN apt update && apt upgrade -y

# デバッグ、開発用のツール
RUN apt install vim unzip zip gdb ltrace strace -y

# コンパイル用のツール
RUN apt install mtools nasm build-essential g++ make -y

# Qemu
RUN apt install qemu qemu-system-x86 qemu-utils qemu-system-arm -y
```