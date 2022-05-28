---
title: "PowerShellのプロンプト表示を自由にカスタムする方法"
date: "2020-06-30"
template: "post"
draft: false
slug: "powershell-custom-prompt"
category: "PowerShell"
tags:
  - "PowerShell"
  - "Windows"
description: "PowerShellのプロンプト表示をカスタマイズする方法についてまとめます。"
socialImage: "/media/cards/no-image.png"
---

## PowerShellのプロンプト表示をカスタマイズする 

では早速ここからPowerShellに入門していきます。

まずは、プロンプトの表示をシンプルにしてあげましょう。  
初期状態では、以下のように "PS [カレントディレクトリ]"の表示になっているかと思います。

```
PS C:\Users\yuki> 
```

ここで、次のように入力することで、カレントディレクトリの表示を削除することができます。

```
PS C:\Users\yuki> function Prompt { "PS > " }
PS >
```

この状態から元に戻すには、以下のように入力します。

```
PS > function prompt { "PS " + $(Get-Location) + "> " }
```

これで、表記は元に戻ります。

次に、別のコマンドを使って表示をカスタマイズしてみましょう。

以下のコマンドを入力すると、$(echo "test") の出力がプロンプトに表示されるようになります。

```
PS C:\Users\yuki> function prompt { "PS " + $(echo "test") + "> " }
PS test>
```

上記の手法を用いることで、PowerShellのプロンプト表示を自由に変更することができるようになります。

**ちなみに、カレントディレクトリを表示するために使用したGet-Locationには、同様の命令を指すエイリアスが、ほかに2つあります。**

それは、**glとpwd**です。

そのため、以下のように入力しても、Get-Locationを使用した時と同様、プロンプトにはカレントディレクトリが表示されます。

```
PS C:\Users\yuki> function prompt {
>> "PS " + $(pwd) + "> " }

PS C:\Users\yuki> function prompt {
>> "PS " + $(gl) + "> " }

PS C:\Users\yuki>
```

これらのエイリアスですが、果たしてすべて知っておく必要があるのか、という疑問があります。  
実際に使用するのが自分だけであれば、正直1つだけでも十分かなと思います。

しかしながら、**セキュリティの領域でPowerShellを使っていこうという場合には、すべてのエイリアスを頭に入れておく必要がある**ようです。

**自分が使用しないエイリアスでも、攻撃者が使用しているかもしれない、攻撃者の狙いを把握するためにも理解が必要**、ということのようです。

詳しくは以下の記事を参照しました。

<a href="https://akaki.io/2019/learning_powershell.html" target="_blank" rel="noopener noreferrer">大和セキュリティ勉強会でPowerShellの基礎を学ぶ · Akaki I/O</a>

## まとめ 

今回はプロンプトの表記を変える方法と、エイリアスについて触れました。

PowerShellはOSS化されており、WindowsだけでなくLinuxやMacOSでもパワフルに使えるシェルスクリプトなので、今後もっともっと学んでいきたいと思います。