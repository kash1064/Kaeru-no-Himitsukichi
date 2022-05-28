---
title: "PowerShellでプロセスを管理する、Get-ProcessとStop-Processについて"
date: "2020-07-01"
template: "post"
draft: false
slug: "powershell-get-and-stop-process"
category: "PowerShell"
tags:
  - "PowerShell"
  - "Windows"
description: "今回は、トラブルシューティングにも役立つPowerShellを利用したプロセスリストの取得についてまとめます。"
socialImage: "/media/cards/no-image.png"
---

## Get-Processコマンドレットで、実行中のプロセスを表示する 

PowerShellで実行中のプロセスの一覧を取得するために、Get-Processコマンドが利用できます。

Get-Processコマンドを利用すると、以下のようにプロセス名やプロセスIDなどのパラメータを取得できます。

このGet-Processコマンドのエイリアスは、gpsとpsです。  
Linuxライクにも使えて便利ですね。

```
PS C:\Users\yuki> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    393      23    16348      30068       0.19   7836   2 ApplicationFrameHost
    569      28    65592      75100   5,603.98  10060   0 audiodg
    308      35    33364      82540       1.48   1308   2 Code
```

また、Get-Processでは以下のように、プロセスIDやプロセス名を使用して、表示するプロセスを指定することができます。  
これは通常、実行中の**既知のプロセスを取得するために、一致するプロセスが見つからないときはエラーが発生**します。

```
#プロセス名でプロセスを指定
PS C:\Users\yuki> Get-Process -Name code

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    821      44    38760      87176      12.59   1364   3 Code
    245      21    15188      27940       0.19   4216   3 Code
    531      82   158264     180296      37.78   4984   3 Code
    657      29   180360     197764       8.73   7232   3 Code
    400      51    43332      70696      13.98  10328   3 Code
    438      20     9688      25920       1.11  10820   3 Code
    311      35    33060      51808       1.48  11996   3 Code
    227      16     6896      14048       0.09  14204   3 Code

#IDでプロセスを指定
PS C:\Users\yuki> Get-Process -Id 4216
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    245      21    15188      27948       0.19   4216   3 Code
```

ちなみに、この**プロセス名の検索には以下のようにワイルドカードを用いることもできます。**  
この例では、note*を指定することによって、notepadプロセスの抽出に成功しています。

```
PS C:\Users\yuki> Get-Process -Name note*

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    290      17     4068      18728       0.17   4504   3 notepad
```

## Stop-Processコマンドで任意の文字列を停止する 

また、Stop-Processコマンドを用いることで、プロセス名やプロセスIDを指定して、特定のプロセスを停止することができます。  
Stop-Processコマンドのエイリアスはkillとsppsです。

killコマンドはBashと同じなので、非常に使いやすいですね。

以下の例では、Stop-Processを用いて、notepadプロセスを停止しています。

```
#notepadプロセスの実行を確認
PS C:\Users\yuki> Get-Process -Name note*

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    290      17     4068      18728       0.17   4504   3 notepad

#notepadプロセスを停止
PS C:\Users\yuki> Stop-Process -Name notepad

#再度notepadプロセスを確認すると、プロセスが見つからずにエラーがかえってくる
PS C:\Users\yuki> Get-Process -Name notepad
Get-Process : 名前 "notepad" のプロセスが見つかりません。プロセス名を確認し、コマンドレットを再度呼び出してください。
発生場所 行:1 文字:1
+ Get-Process -Name notepad
+ ~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (notepad:String) [Get-Process], ProcessCommandException
    + FullyQualifiedErrorId : NoProcessFoundForGivenName,Microsoft.PowerShell.Commands.GetProcessCommand
```

また、このフィルターの部分にコマンド出力を利用することで、より複雑な処理を実行させることが可能になります。

例えば、<a target="_blank" href="https://docs.microsoft.com/ja-jp/powershell/scripting/samples/managing-processes-with-process-cmdlets?view=powershell-7" rel="noopener noreferrer">公式ドキュメント</a>には、以下の**ワンライナーで、「応答なし」状態のプロセスをすべて停止する方法**が紹介されていました。

```
Get-Process | Where-Object -FilterScript {$_.Responding -eq $false} | Stop-Process
```

応答なしプロセスをサクッと停止できるのは結構便利ですね。  
いちいちタスクマネージャーからプロセスを目視で探す手間がなくなります。

## まとめ 

今回は、PowerShellのプロセスを確認するGet-Processコマンドと、任意のプロセスを停止するStop-Processコマンドについてまとめました。  
PowerShellの多くのコマンドには、使い慣れたBashのコマンドと同じエイリアスが割り当てられており、非常に快適に使えるなと感じています。

## 参考 
- <a target="_blank" href="https://docs.microsoft.com/ja-jp/powershell/module/Microsoft.PowerShell.Management/Get-Process?view=powershell-7" rel="noopener noreferrer">Get-Process</a>
- <a target="_blank" href="https://docs.microsoft.com/ja-jp/powershell/scripting/samples/managing-processes-with-process-cmdlets?view=powershell-7" rel="noopener noreferrer">Process コマンドレットによるプロセスの管理 - PowerShell | Microsoft Docs</a>

## 今回紹介したコマンド 

```powershell
名前
    Get-Process

構文
    Get-Process [[-Name] <string[]>]  [<CommonParameters>]

    Get-Process [[-Name] <string[]>]  [<CommonParameters>]

    Get-Process  [<CommonParameters>]

    Get-Process  [<CommonParameters>]

    Get-Process  [<CommonParameters>]

    Get-Process  [<CommonParameters>]


エイリアス
    gps
    ps
```

```powershell
名前
    Stop-Process

構文
    Stop-Process [-Id] <int[]>  [<CommonParameters>]

    Stop-Process  [<CommonParameters>]

    Stop-Process [-InputObject] <Process[]>  [<CommonParameters>]


エイリアス
    spps
    kill
```