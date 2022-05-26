---
title: "docker run -it ~ /bin/bash で起動したコンテナでTab補完ができない問題の原因と解決方法"
date: "2021-01-11"
template: "post"
draft: false
slug: "docker-tabo-compleate"
category: "Docker"
tags:
  - "Docker"
  - "Bash"
  - "Notes"
description: "Dokcerコンテナの中でmakeを使う際に、引数のタブ補完ができない問題の解消法についてまとめます。"
socialImage: "/media/cards/no-image.png"
---

Dokcerコンテナの中でmakeを使う際に、引数のタブ補完ができない問題の解消法についてまとめます。

僕は自作OSの開発をDockerコンテナで行っているのですが、**docker runコマンドでログインしたコンテナの中で、Makefileの引数のタブ補完ができない問題**が発生しました。

本来であれば、次の画像のように「make build」といった形のMakefileの引数がTabキーで補完されてほしいのですが、接続したDokcerコンテナ内のシェルでは上手く起動しませんでした。

![img](assets/2021_01_11_2954.assets/image-1.png)

## 解決方法

MakefileのTab補完ができない場合は、以下のコマンドで**bash-completion**をインストールしたのち、/etc/bash_completionをBashのsourceコマンドで読み込ませます。

``` bash
sudo apt install bash-completion -y
source /etc/bash_completion
```

これで、Tab補完が有効になりました。

しかし、そもそも、bash-completionとはなんでしょうか。  
Readmeを読むと、**BashシェルのTab補完を強化するためのツール**のようです。

```
bash-completion は、Bash シェル用のコマンドラインコマンド補完のコレクション、新しい補完の作成を支援するヘルパー関数のコレクション、補完を自動的にロードしたりインストールしたりするための機能のセットです。
``

bash-completionを入れておくと、**Makefileの引数以外にも、systemctlなど、デフォルトのツールのオプション引数も出力できる**ようになります。  
非常に便利です。

ちなみに、bash-completionをインストールした後、bash-completionが有効になっているかは、以下のコマンドを実行したときに大量の出力があるかで確認できます。

​```bash
complete -p
```

詳しくは以下の記事が参考になりました。

[bash-completionを活用して、manやhelpを見ずに、バシバシ長いコマンドを打つ - Qiita](https://qiita.com/yamada-hakase/items/bf163f0924e4d925fefb)

## Dockerコンテナでbash-completionが有効にならない 

というわけで、Dokcerfileにbash-completionをインストールする記述を追加してからイメージをビルドすれば、Tab補完ができない問題は解消されそうです。

ここで、次のようなDockerfileを利用してイメージを作成しました。

```dockerfile
# Dokcerfile
FROM python:3.8
ENV PYTHONUNBUFFERED 1

ENV TZ=Asia/Tokyo

RUN mkdir -p /homedir
ENV HOME=/homedir
WORKDIR $HOME

# If you henge shell to Bash
# Shell &#91;"/bin/bash", "-c"]

RUN useradd ubuntu
RUN dpkg --add-architecture i386
RUN apt update && apt upgrade -y

# Utils
RUN apt install vim unzip zip gdb ltrace strace bash-completion -y

# Devtools
RUN apt install mtools nasm build-essential g++ make -y

# Qemu
RUN apt install qemu qemu-system-x86 qemu-utils qemu-system-arm -y
```

**しかし、作成したイメージに以下のコマンドでログインしたところ、Tab補完が機能しませんでした。**

```bash
docker run --rm -it -v mydir:/homedir mycontainer /bin/bash
```

**ログインしたコンテナ内で「source /etc/bash_completion」を実行した後であれば、Tab補完は正常に動いてくれるため、bash-completion自体は正常にインストールされているようです。**

また、/etc/profile.d 配下には、以下のようにbash_completion.shが配置されていました。

```bash
root@ab80c3738102:~# cat /etc/profile.d/bash_completion.sh

# Check for interactive bash and that we haven't already been sourced.
if [ -n "${BASH_VERSION-}" -a -n "${PS1-}" -a -z "${BASH_COMPLETION_VERSINFO-}" ]; then

    # Check for recent enough version of bash.
    if [ ${BASH_VERSINFO[0]} -gt 4 ] || \
       [ ${BASH_VERSINFO[0]} -eq 4 -a ${BASH_VERSINFO[1]} -ge 1 ]; then
        [ -r "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion" ] && \
            . "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion"
        if shopt -q progcomp && [ -r /usr/share/bash-completion/bash_completion ]; then
            # Source completion code.
            . /usr/share/bash-completion/bash_completion
        fi
    fi

fi
```

そのため、どうやら**シェル起動時に/etc/profileによって読み込まれるはずの/etc/profile.d/bash_completionが、上記の方法でコマンドにログインした際には読み込まれていないことが原因**のようです。

Docker run コマンドについて、ドキュメントを参照したところ次のような記述がありました。

> docker runコマンドは、まず指定されたイメージの上に書き込み可能なコンテナレイヤーを作成し、指定されたコマンドで起動します。
>
> つまり、docker run は API /containers/create と /containers/(id)/start と同等です。
> 停止しているコンテナは、docker start を使って以前の変更をすべてそのままにして再起動することができます。
>
> すべてのコンテナのリストを表示するには docker ps -a を参照してください。
>
> https://docs.docker.com/engine/reference/commandline/run/

つまり、**docker run -it コマンドで/bin/bashを呼び出すのは、起動したDokcerコンテナ内でインタラクティブなbashを呼び出し、そこに疑似TTYで呼び出し元の標準入出力を接続している**ということのようです。

ここで問題の原因は、Dockerコンテナ起動時(つまり、docker run で起動した bash に接続時)に /etc/profile によって読み込まれるはずのbash_completionが読み込まれないことでした。

それもそのはず、**/etc/profile はそもそも、シェルへの「ログイン時」に読み込まれます。**  
そのため、 run コマンドで bash を起動しただけでは、そもそも読み込まれないのです。

原因が特定できたので、Dockerコンテナの起動コマンドを次のように改変します。

`docker run --rm -it -v mydir:/homedir mycontainer /bin/bash -login`

この「-login」オプションは、環境設定(profileなど)を意図的に読み込ませて実行することを指示するオプションです。

このコマンドで起動したコンテナに接続することで、Tab補完がきちんと動いてくれるようになりました、

## まとめ 

ちょっとした備忘録のつもりの、軽い気持ちで書き始めた記事でしたが、BashのTab補完やDockerコマンド、Bashシェルの仕様などの理解が深まり、非常に勉強になりました。
