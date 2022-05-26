---
title: LinuxでVSCodeを使うとき、'apt upgrade'後にcodeコマンドが使えなくなる問題の原因と解決策
date: "2021-07-02"
template: "post"
draft: false
slug: "note-vscode-onlinux-aptissue"
category: "Notes"
tags:
  - "Notes"
  - "VSCode"
  - "備忘録"
description: "Linux環境で`apt update`コマンドを実行するとVSCodeが`code`コマンドで呼び出せなくなる問題についてのトラシューを行ったので原因と解消法について記録しておきます。"
socialImage: "/media/social_images/no-image.png"
---

<!-- omit in toc -->
## はじめに

Linux環境で`apt update`コマンドを実行するとVSCodeが`code`コマンドで呼び出せなくなる問題についてのトラシューを行ったので原因と解消法について記録しておきます。

VSCodeは、公式サイトからダウンロードしたdebファイルを用いて、`dpkg -i`コマンドでインストールを行っていました。

<!-- omit in toc -->
## もくじ

- [VSCodeの情報を確認する](#vscodeの情報を確認する)
- [VSCodeをアップグレードする](#vscodeをアップグレードする)
- [問題箇所を特定する](#問題箇所を特定する)
  - [VSCode本体の存在確認](#vscode本体の存在確認)
- [解決策](#解決策)
- [まとめ](#まとめ)

## VSCodeの情報を確認する

とりあえず、`code`パッケージが存在していることを確認しました。

```bash
$sudo dpkg -l | grep code
ii  code                                     1.57.0-1623259737                  amd64        Code editing. Redefined.
```

次に、`code`コマンドが何を呼び出しているのか確認します。

``` bash
$which code
/usr/bin/code
```

どうやら、`/usr/bin/code`は`/usr/share/code/bin/code`に対するシンボリックリンクのようです。

``` bash
$file /usr/bin/code
/usr/bin/code: symbolic link to /usr/share/code/bin/code
```

`/usr/share/code/bin/code`について調べてみたら、実行可能なシェルスクリプトだったので、中身を確認してみました。

``` bash
$cat /usr/share/code/bin/code 
#!/usr/bin/env sh
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.

# test that VSCode wasn't installed inside WSL
if grep -qi Microsoft /proc/version && [ -z "$DONT_PROMPT_WSL_INSTALL" ]; then
	echo "To use Visual Studio Code with the Windows Subsystem for Linux, please install Visual Studio Code in Windows and uninstall the Linux version in WSL. You can then use the \`code\` command in a WSL terminal just as you would in a normal command prompt." 1>&2
	printf "Do you want to continue anyway? [y/N] " 1>&2
	read -r YN
	YN=$(printf '%s' "$YN" | tr '[:upper:]' '[:lower:]')
	case "$YN" in
		y | yes )
		;;
		* )
			exit 1
		;;
	esac
	echo "To no longer see this prompt, start Visual Studio Code with the environment variable DONT_PROMPT_WSL_INSTALL defined." 1>&2
fi

# If root, ensure that --user-data-dir or --file-write is specified
if [ "$(id -u)" = "0" ]; then
	for i in "$@"
	do
		case "$i" in
			--user-data-dir | --user-data-dir=* | --file-write )
				CAN_LAUNCH_AS_ROOT=1
			;;
		esac
	done
	if [ -z $CAN_LAUNCH_AS_ROOT ]; then
		echo "You are trying to start Visual Studio Code as a super user which isn't recommended. If this was intended, please specify an alternate user data directory using the \`--user-data-dir\` argument." 1>&2
		exit 1
	fi
fi

if [ ! -L "$0" ]; then
	# if path is not a symlink, find relatively
	VSCODE_PATH="$(dirname "$0")/.."
else
	if command -v readlink >/dev/null; then
		# if readlink exists, follow the symlink and find relatively
		VSCODE_PATH="$(dirname "$(readlink -f "$0")")/.."
	else
		# else use the standard install location
		VSCODE_PATH="/usr/share/code"
	fi
fi

ELECTRON="$VSCODE_PATH/code"
CLI="$VSCODE_PATH/resources/app/out/cli.js"
ELECTRON_RUN_AS_NODE=1 "$ELECTRON" "$CLI" "$@"
exit $?
```

このスクリプトを読むことで、VSCodeの実行可能ファイルの本体は、`/usr/share/code/code`であることが確認できました。

試しに`file`コマンドをたたくと、ELFファイルであることが確認できます。

``` bash 
$file /usr/share/code/code 
/usr/share/code/code: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=09e8dc044d33f961bfddaa7b20750bdf7d1f3005, not stripped
```

## VSCodeをアップグレードする

さて、事前の情報収集が完了したところで、問題を再現していきます。

``` bash
sudo apt update && sudo apt upgrade code
```

これで、Linux環境のVSCodeがアップグレードされたので、ターミナルから`code`コマンドでVSCodeが起動できなくなりました。

``` bash
$code
bash: code: command not found
```

## 問題箇所を特定する

さて、先ほどの調査結果から、`code`コマンドでVSCodeを起動する際は、次のようなステップを踏んでいることがわかります。

- `code`コマンドは`/usr/bin/code`を呼び出す
- `/usr/bin/code`は、`/usr/share/code/bin/code`のシンボリックリンクである
- `/usr/share/code/bin/code`は実行可能シェルスクリプトであり、`/usr/share/code/code`を呼び出している

ここでは、上記のどのステップに問題が発生しているのかを特定します。

### VSCode本体の存在確認

ゴールから逆算していきます。

なんと、`apt upgrade code`を実行したら、`/usr/share/code/code`が消滅してしまっていました。

```bash
$file /usr/share/code/code
/usr/share/code/code: cannot open `/usr/share/code/code' (No such file or directory)
```

`apt install`を試してみたところ、どうやらアンインストールされたわけではなさそうです。

``` bash
$sudo apt install code
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
code is already the newest version (4.11.5).
0 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.
```

そして、いくつかディレクトリを探索したところ、`/usr/bin/codium`という実行ファイルを発見しました。

codiumとは、VSCodeを完全OSS化したアプリケーションで、Microsoftのロゴなどの見た目以外は、ほぼ完全にVSCodeと同一のものだそうです。
（なんかいつも使ってる拡張機能が一部使えないようですが・・・）

もともとMicrosoftのページからダウンロードしたdebファイルでインストールしていたVSCodeも、中身はcodiumと同一で、ガワだけが異なるものだったようです。

そして、`apt show code`のDescriptionに次のような記述を見つけました。

``` bash
Description: Free/Libre Open Source Software Binaries of VSCode (VSCodium)
Transitional package. Moved to codium.
```

どうやら、codeパッケージはcodiumに移行しているようです。

そのため、aptでcodeをアップグレードした際に、codeコマンドでアプリケーションが起動できなくなったようです。

## 解決策

シンプルにエイリアスを作成しました。

``` bash
alias code=codium
```

これでこれまでと同じ使用感でVSCode(codium)を呼び出すことができます。

## まとめ

今回は、公式サイトからダウンロードしたdebファイルを用いて、`dpkg -i`コマンドでインストールを行っていた環境で、アップグレード後に`code`コマンドが使えなくなる問題のトラシューを行いました。
