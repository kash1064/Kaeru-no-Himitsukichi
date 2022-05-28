---
title: Azure VM で Hyper-V を使おうとしたら、”one of the Hyper-V components is not running” となり、起動できない問題の原因と解決方法
date: "2020-12-27"
template: "post"
draft: false
slug: "azure-cannot-use-hyperv"
category: "Azure"
tags:
  - "Azure"
  - "Hyper-V"
  - "Notes"
description: "Azure の仮想マシン上に構築している Windows OS 上で Hyper-V による仮想マシンが起動できなくなるトラブルを解消する方法についての記事です。"
socialImage: "/media/cards/no-image.png"
---

## はじめに

今回は、 **Azure の仮想マシン上に構築している Windows OS 上で Hyper-V による仮想マシンが起動できなくなるトラブルを解消する方法**についての記事です。

先日、 Azure の VM として稼働していた Windows10 上の Hyper-V で Linux マシンを起動したところ、次のようなエラーメッセージが表示され、起動できなくなってしまいました。

`Failed to start the virtual machine 'MACHINE' because one of the Hyper-V components is not running.`

結論としては、 **Azure の VM 上で Hyper-V を利用する場合は、「ネストされた仮想化」に対応した CPU を利用可能なサイズを設定する**必要があり、「Standard D4s_v4」を指定することで無事起動に成功しました。


## 問題発生の原因 

上記の問題が発生した原因は、 Hyper-V のネストされた仮想化の設定が有効でなかったためでした。

そもそも、**Hyper-V で作成された仮想マシンの上で、さらに Hyper-V を利用して仮想マシンを起動する際には、色々と制限事項があった**ようです。  
ドキュメントを確認したところ、以下のような制限があることがわかりました。

> Hyper-V ホストとゲストの両方が Windows Server 2016/Windows 10 Anniversary Update 以降であること。・第 2 レベルの仮想マシンの仮想ネットワークとは、いくつかの違いがあります。
  [入れ子になった仮想化 | Microsoft Docs](https://docs.microsoft.com/ja-jp/virtualization/hyper-v-on-windows/user-guide/nested-virtualization)


このような制限がある理由としては、 Hyper-V が、 CPU の持つ仮想化のためのハードウェア機能に依存しているためです。  
Hyper-V は、Intel VT-x や AMD-V などと呼ばれる CPU の機能を利用しています。

これらの CPU 機能は排他的に利用されるもので、 Hyper-V が使用している場合には、他のソフトウェアがこの機能を使用することが通常できません。 

そのため、 **Hyper-V 上で稼働している仮想マシン上で、 CPU のこの機能を利用してさらに仮想化を行うことは本来はできない**ようです。  
(調べた限り、VM や VirtualBox もこの機能を利用しているので、同様に利用できなさそう)

しかしながら、 Hyper-V に関しては、ネストされた仮想化のサポートを有効にすることで、この CPU の機能自体を仮想化することで、階層的に Hyper-V を使った仮想マシンを構築できるようになるようです。

ここで、今回発生した問題を振り返ってみます。  
たまに忘れがちになりますが、 **Azure の VM サービスで利用しているインスタンスは、そもそもすでに Hyper-V で仮想化されている**ということです。

つまり、**Azure の VM 上で Hyper-V を利用することは、すでに Hyper-V で仮想化されたマシンの中で、さらに Hyper-V による仮想化を行うこととイコール**なわけです。

Azure の VM サービスにおいて、このネストされた仮想化をサポートする仮想マシンは、**特定のサイズの仮想マシン**のみとなっています。

Azure の VM サービスにおける、ネストされた仮想化のサポートについては、こちらの記事に情報がありました。  

<a rel="noopener" href="https://docs.microsoft.com/ja-jp/azure/virtual-machines/windows/nested-virtualization" target="_blank">Azure Virtual Machines で入れ子になった仮想化を有効にする方法 - Azure Virtual Machines | Microsoft Docs</a>

また、ネストされた仮想化を利用可能な Azure VM のサイズ一覧は、ここから確認できました。  

<a rel="noopener" href="https://docs.microsoft.com/en-us/azure/virtual-machines/acu" target="_blank">Overview of the Azure Compute Unit - Azure Virtual Machines | Microsoft Docs</a>

このページを見ると、以下のような記述があります。

`Hyper-threaded and capable of running nested virtualization`

この Hyper-threaded というのが、ネストされた仮想化を実現している仕組みみたいですね。（よくわかってない）

結果として、上記の Hyper-threaded を利用できるメモリ 16GB のサイズである Standard D4s_v4 を選択して仮想マシンを作成しなおしたことで、無事問題が解消されました。

## まとめ 

上記のとおり、今回の問題の原因はネストされた仮想化をサポートしていないリソースのサイズを選択して仮想マシンを作成していたことでした。

上記の原因を特定して解決に至るまで、次のようなことを試してました。

特に Hyper-V 仮想マシンを消して立て直したのは非常に時間と手間がかかったのでやらなきゃよかったです笑  
仮想化と CPU の機能の話とか、仮想マシンの上にさらに仮想マシンを構築するときに発生しうる問題とか、諸々理解不足でトラシューに手間取った印象。

エラー文で直接ググってもなかなか参考になるページが出てこなかったので、今回は自分で記事を書いてみました。  
最終的に CPU の問題っぽいなーということにたどり着き、「Azure Hyper-V サイズ」とか「Azure Hyper-V CPU」とかでググったら役に立つ記事がでてきました。

こういう、**知識があれば適切な検索ワードを見つけられて即解決できる**、みたいなことって結構多いですよね。  
ともあれ、クラウドサービスを使うのにも、インフラやらネットワークの知識が必要なんだというのを再確認したので真面目に勉強しようと思います。