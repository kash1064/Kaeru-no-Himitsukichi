---
title: 
date: "2022-02-11"
template: "post"
draft: true
slug: "honeypot-setup-on-azure"
category: "HoneyPot"
tags:
  - "Security"
  - "HoneyPot"
  - "Azure"
  - "備忘録"
description: ""
socialImage: "/media/cards/honeypot-setup-on-azure.png"


---

## Azure Bot Serviceを使う







参考：[Create your first bot in Bot Framework Composer | Microsoft Docs](https://docs.microsoft.com/ja-jp/composer/quickstart-create-bot)



### Bot Framework Composerのインストール



参考：[Install Bot Framework Composer | Microsoft Docs](https://docs.microsoft.com/ja-jp/composer/install-composer?tabs=windows)





- [Node.js](https://nodejs.org/en/)
- [.NET Core 3.1 (Linux, macOS, and Windows)](https://dotnet.microsoft.com/en-us/download/dotnet/3.1)
- [Bot Framework Composer](https://docs.microsoft.com/ja-jp/composer/install-composer?tabs=windows)



### 新しいBOTを作成する

Composerを起動したら、[Create a new bot to get started]のボタンから[Empty Bot]を選択して新しいBOTを作成します。

このとき、「Azure Functions」か「Azure Web App」のどちらのタイプにするかを聞かれます。

今回は「Azure Web App」を選択しました。

![https://yukituna.com/wp-content/uploads/2022/02/image-41.png](https://yukituna.com/wp-content/uploads/2022/02/image-41.png)

作成が完了すると、以下の2つのテンプレートがすでに作成されていました。

- Greeting
- Unknown intent

### Unknown intent

`Unknown intent`は、`on intent recognition`というトリガーに一致しない入力が与えられたとき、もしくはユーザから入力が与えられないときに実行する処理です。

デフォルトでは、エラーメッセージを返す処理が定義されていました。

![https://yukituna.com/wp-content/uploads/2022/02/image-42.png](https://yukituna.com/wp-content/uploads/2022/02/image-42.png)





