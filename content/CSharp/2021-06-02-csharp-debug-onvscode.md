---
title: WLSでC#をサクッと実行してVSCodeでデバッグするメモ
date: "2021-06-02"
template: "post"
draft: false
slug: "csharp-debug-onvscode"
category: "C#"
tags:
  - "C#"
  - "備忘録"
  - "VSCode"
description: ".Net を使って、ELF形式のコンソールアプリをビルドします。また、WLS接続したVSCode経由で、C#プログラムのデバッグも設定します。"
socialImage: "/media/cards/no-image.png"
---

この記事は、WLSでC#プログラムをサクッと実行する環境を準備するための備忘録です。

.Net を使って、ELF形式のコンソールアプリをビルドします。
また、WLS接続したVSCode経由で、C#プログラムのデバッグも設定します。

## .NET 5.0をWSL Ubuntuにインストールする

まずはC#でプログラムを作成するために、クロスプラットフォームの.NET 5.0をWSL上のUbuntuにインストールします。

[Download .NET (Linux, macOS, and Windows)](https://dotnet.microsoft.com/download#windowscmd)

インストールは、以下のドキュメントのDebian10向けの方法と同じコマンドでOKです。

[Install .NET on Debian - .NET | Microsoft Docs](https://docs.microsoft.com/en-us/dotnet/core/install/linux-debian)

```bash
wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb

# SDKのインストール
sudo apt-get update; \
  sudo apt-get install -y apt-transport-https && \
  sudo apt-get update && \
  sudo apt-get install -y dotnet-sdk-5.0
```

## VSCodeに拡張機能をインストールする

次に、VSCodeでC#のデバッグを行うために、拡張機能をインストールします。

C#で検索した時に一番上にでてくるこの拡張機能をインストールすればOKです。
ちゃんとWSLにVSCodeを接続した状態でインストールします。

![image-20210602195127867](assets/2021_06_02_cs_on_wsl.assets/image-20210602195127867.png)

## .Netプロジェクトを作成する

次に、WSL上で.NETプロジェクトを作成します。
コンソールアプリとして作成します。

```bash
dotnet new console -o <project_name>
```

プロジェクトの作成が完了すると、カレントディレクトリにproject_nameに指定した名前と同じディレクトリが作成されているはずです。

## コマンドから実行できることを確認する

作成したプロジェクトディレクトリに移動してrunコマンドを実行すると、Program.csのコードが実行されます。
C#プログラムを作成、デバッグする場合は、とりあえずこのファイルをいじっていきます。

``` bash
cd <project_name>
dotnet run
```

## VSCodeでデバッグ

コンソールからの実行が確認できたので、次はVSCodeからデバッグ実行してみます。
このとき使用するのは、次の2つのファイルです。

- launch.json
- tasks.json

どちらも.vscodeディレクトリ直下に作成します。

VSCodeからWSL上の.NETアプリケーションのデバッグを行う場合、通常自動生成される上記のファイルがうまく動作しません。
そのため、これらのファイルにC#デバッグのために必要な情報を手動で追記していく必要があります。

それぞれに記載が必要な内容は以下のとおりです。
いずれも、「project_name」には自分が作成したプロジェクトの名前にする必要がある点に注意です。

- launch.json

```bash 
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": ".NET Core Launch (console)",
            "type": "coreclr",
            "request": "launch",
            "preLaunchTask": "build",
            "program": "${workspaceFolder}/procon_cs/bin/Debug/net5.0/<project_name>.dll",
            "args": [],
            "cwd": "${workspaceFolder}/<project_name>",
            "console": "internalConsole",
            "stopAtEntry": false
        },
        {
            "name": ".NET Core Attach",
            "type": "coreclr",
            "request": "attach"
        }
    ]
}
```

- tasks.json

``` bash
{
    // See https://go.microsoft.com/fwlink/?LinkId=733558
    // for the documentation about the tasks.json format
    "version": "2.0.0",
    "tasks": [
        {
            "label": "build",
            "command": "dotnet",
            "type": "process",
            "args": [
                "build",
                "${workspaceFolder}/<project_name>/<project_name>.csproj",
                "/property:GenerateFullPaths=true",
                "/consoleloggerparameters:NoSummary"
            ],
            "problemMatcher": "$msCompile"
        }
    ]
}
```

これで準備が整ったので、VSCodeからC#プログラムをデバッグしてみます。

左側のタスクトレイからデバッグツールバーを開き、.NETプログラムのデバッグを実行します。

![image-20210602202737631](assets/2021_06_02_cs_on_wsl.assets/image-20210602202737631.png)

## まとめ

ちょっとした思いつきでWSL上でサクッとC#を書けるようにしたくなったので環境を作ってみました。

C#は大好きなのですが、毎回VisualStudioを立ち上げるのが結構めんどくさくてあまり書く機会がなかったですが、VSCodeから簡単に実行できるようになったことで今後はもっとC#についても色々勉強していければと思います。
