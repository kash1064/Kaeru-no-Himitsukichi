---
title: "PowerShellで.NET Frameworkオブジェクトを参照してHTTPレスポンスを取得"
date: "2020-07-01"
template: "post"
draft: false
slug: "powershell-get-http-response"
category: "PowerShell"
tags:
  - "PowerShell"
  - "Windows"
description: "PowerShellから.NET Frameworkのオブジェクトを参照する方法についてまとめます。"
socialImage: "/media/cards/no-image.png"
---

## はじめに

今回は、PowerShellから.NET Frameworkのオブジェクトを参照する方法についてまとめます。

## PowerShellと.NET Framework 

PowerShellは、OSSで開発が進んでおり、Windows、Linux、MacOSで動作するパワフルなシェルであり、オブジェクト指向言語として設計されたスクリプト言語です。

PowerShellは.NET Frameworkを基盤としています。  
Bashなどでいうところのコマンドに相当する命令は、コマンドレットと呼ばれていますが、その実態は.NET Frameworkオブジェクトです。

Linuxなどで使用されるシェルと同様に、パイプを用いた処理結果の受け渡しが可能ですが、渡される情報は、テキストではなく.NET Frameworkのオブジェクトです。  
そのため、柔軟でパワフルな処理を実現できるというわけです。

次の項では、実際にPowerShellから.NET Frameworkのオブジェクトを読み込んでいきます。

## System.Net.WebClientを参照する 

例えば、PowerShellで以下のスクリプトを実行するだけで、$contentという変数には、指定したURLのHTTPレスポンスが格納されるというわけです。

```powershell
Add-Type -AssemblyName System.Net.Http
$webClient = New-Object System.Net.Http.HttpClient
$content = $webClient.GetAsync("https://kashiwaba-yuki.com")
```

具体的には、まず.NET Frameworkクラスを定義することができるAdd-Typeコマンドレットを用いて、System.Net.Httpクラスを参照します。  
次に、$webClientにSystem.Net.Httpクラスのインスタンスを格納し、GetAsyncメソッドを用いて、指定したURLのHTTPレスポンスを取得しています。

この$contentを実際に出力してみると、以下のような結果が確認できました。

```
$content

Result                 : StatusCode: 200, ReasonPhrase: 'OK', Version: 1.1, Content: System.Net.Http.StreamContent, Headers:
                         {
                           Transfer-Encoding: chunked
                           Connection: keep-alive
                           Link: https://kashiwaba-yuki.com/wp-json/; rel="https://api.w.org/"
                           Vary: Range
                           Vary: Accept-Encoding
                           X-Cache: MISS
                           Date: Wed, 01 Jul 2020 07:38:37 GMT
                           Server: Apache
                           X-Powered-By: PHP/7.4.4
                           Content-Type: text/html; charset=UTF-8
                         }
Id                     : 365
Exception              :
Status                 : RanToCompletion
IsCanceled             : False
IsCompleted            : True
CreationOptions        : None
AsyncState             :
IsFaulted              : False
AsyncWaitHandle        : System.Threading.ManualResetEvent
CompletedSynchronously : False
```

## まとめ 

というわけで、PowerShellでNET Frameworkのオブジェクトを参照できることについてまとめました。

.NET Frameworkのオブジェクトを参照できるということは、極端な話C#でできることってPowerShellでも実装できちゃう、って話ですね。  
PowerShellからC#プログラムを呼び出せるみたいなので、全部をPowerShellで書く必要はないかもしれませんが…。

## 参考 

- <a href="https://docs.microsoft.com/ja-jp/dotnet/api/system.net.webclient?view=netcore-3.1" target="_blank" rel="noopener noreferrer">WebClient クラス (System.Net) | Microsoft Docs</a>
- <a href="https://forsenergy.com/ja-jp/windowspowershellhelp/html/7c6ad475-d556-436e-841b-7e618f888644.htm" target="_blank" rel="noopener noreferrer">Add-Type</a>
