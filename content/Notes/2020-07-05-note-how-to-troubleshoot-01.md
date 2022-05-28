---
title: "【トラブルシューティング入門 #1】エラー文でググる"
date: "2020-07-05"
template: "post"
draft: false
slug: "note-how-to-troubleshoot-01"
category: "Notes"
tags:
  - "Notes"
description: "本記事ではこの事例を利用してトラブルシューティングの基本的なやり方について解説していきます。"
socialImage: "/media/cards/no-image.png"
---

## はじめに

PythonのWEBアプリケーションフレームワークを使っていたところ、次のようなエラーが発生しました。

```
エラーの内容： 
django.core.management.base.SystemCheckError: SystemCheckError: System check identified some issues:

ERRORS:
auth.User.groups: (fields.E304) Reverse accessor for 'User.groups' clashes with reverse accessor for 'User.groups'.
        HINT: Add or change a related_name argument to the definition for 'User.groups' or 'User.groups'.
auth.User.user_permissions: (fields.E304) Reverse accessor for 'User.user_permissions' clashes with reverse accessor for 'User.user_permissions'.
        HINT: Add or change a related_name argument to the definition for 'User.user_permissions' or 'User.user_permissions'.
mocrat_user.User.groups: (fields.E304) Reverse accessor for 'User.groups' clashes with reverse accessor for 'User.groups'.
        HINT: Add or change a related_name argument to the definition for 'User.groups' or 'User.groups'.
mocrat_user.User.user_permissions: (fields.E304) Reverse accessor for 'User.user_permissions' clashes with reverse accessor for 'User.user_permissions'.
        HINT: Add or change a related_name argument to the definition for 'User.user_permissions' or 'User.user_permissions'.

System check identified 4 issues (0 silenced).
```

結論としては非常に初歩的な内容で、カスタムユーザを設定していたのにSettingsにAUTH\_USER\_MODELを設定し忘れていたよ、って話でした。

ちなみに解消方法は、Settings.pyに以下の一文を追記するだけです。

`AUTH_USER_MODEL = 'AppName.ClassName'`

ところで、このエラーはトラブルシューティングの初歩について説明する上でちょうどいいサンプルでしたので、本記事ではこの事例を利用してトラブルシューティングの基本的なやり方について解説していきます。

エラーが発生した場合の初歩的なググり方や考え方についてまとめます。

## まずはエラー文を読む 

さて、トラブルシューティングの初歩ですが、**まずは嫌がらずにエラー文を読みましょう。**

コンパイラやインタプリタは非常に賢いので、**ちょっとした問題であれば、エラー文を読むだけで解消するケースが多い**です。  
例えば、Pythonの文法エラーの場合、次のような出力が確認できます。

``` python
print(100 + "Hello")

Traceback (most recent call last):
File "stdin", line 1, in module
TypeError: unsupported operand type(s) for +: 'int' and 'str'
```

まず、Tracebackの直下に、エラーの原因となった場所が示されていますね。  
この例の場合は、1行目に問題があるようです。

次に、エラーの理由が書かれています。

`TypeError: unsupported operand type(s) for +: 'int' and 'str'`   
とあるので、どうやらint型とstr型の加算はサポートされていないとのことです。

この例の場合であれば、これを読めば100をクオテーションで囲い忘れていたことがエラーの原因だということがわかりましたね。

## エラー文でググる 

では、冒頭で引用したエラー文をもう一度見てみます。

色々書いてありますが、**エラーの原因となるファイルの名前や行数については書いてありません。**

また、**原因に関連しそうな記載として、SystemCheckError: System check identified some issues とあります**が、なんのことかよくわかりません。

```
エラーの内容：

django.core.management.base.SystemCheckError: SystemCheckError: System check identified some issues:

ERRORS:
auth.User.groups: (fields.E304) Reverse accessor for 'User.groups' clashes with reverse accessor for 'User.groups'.
        HINT: Add or change a related_name argument to the definition for 'User.groups' or 'User.groups'.
auth.User.user_permissions: (fields.E304) Reverse accessor for 'User.user_permissions' clashes with reverse accessor for 'User.user_permissions'.
        HINT: Add or change a related_name argument to the definition for 'User.user_permissions' or 'User.user_permissions'.
mocrat_user.User.groups: (fields.E304) Reverse accessor for 'User.groups' clashes with reverse accessor for 'User.groups'.
        HINT: Add or change a related_name argument to the definition for 'User.groups' or 'User.groups'.
mocrat_user.User.user_permissions: (fields.E304) Reverse accessor for 'User.user_permissions' clashes with reverse accessor for 'User.user_permissions'.
        HINT: Add or change a related_name argument to the definition for 'User.user_permissions' or 'User.user_permissions'.

System check identified 4 issues (0 silenced).
```

そんな時は、**エラー文をコピペしてググってあげましょう。**

その場合は、**全文コピペすると上手く検索できないので、1文くらいに絞って検索**します。

また、その際、**自作のファイル名などが入っていない部分を使用する**ようにしましょう。

今回のケースでは、"mocrat_user"というのが自作のファイル名なので、その部分は検索に含めないようにします。  
これは、自作のファイル名が検索ワードに含まれていると、それがノイズになって、期待する検索結果が得られない場合があるためです。

では検索をしていきます。  

まず、`SystemCheckError: System check identified some issues`でググってみました。

まずは上位3記事を開いてみましょう。

すると、内容が見事にバラバラでした。

1記事目は、MEDIA_URLの設定に失敗してSystemCheckErrorが出力されており、2記事目はadmin.pyの設定漏れ、最後はmigrationの仕組みについての記事でした。

ここから考えられることとして、**どうやらSystemCheckErrorは特定の事象ではなく、エラーに対して汎用的に用いられる出力ということが予想**できます。


## 原因を絞り込んでググる 

前項で、SystemCheckErrorはどうやら様々な事象に対して出力されるものであることがわかりました。

そのため、**検索ワードを変えたいのですが、その前にまず問題の原因を絞り込む作業**をしていきます。  
今回の場合は、エラー文にファイル名が出力されていないことや、SystemCheckErrorを検索した結果より、設定ファイルや権限のミスが原因かなという予想をすることができます。

また、エラーの詳細の記載より、Userモデルに関する問題の可能性が高そうに見えます。  
具体的には、Reverse accessor に関する記載がありました。

ここで、`Reverse accessor for 'User.groups' clashes with reverse accessor for 'User.groups'. `の一文で検索をかけてみましょう。

今度は、上位すべてに同じ問題に関する記事が表示されました。  
かなり確度が高そうです。

結果としてはこちらが正解で、カスタムユーザを定義しているにも関わらず、`AUTH_USER_MODEL`を記載していなかったために、モデルが衝突していたようです。


## エラーコードでググる 

さて、今回はエラー文の内容を検索することで上手く解決方法が見つかりましたが、そのほかのテクニックとして**エラーコードでググる**という方法もあります。

特に、**マイナーなシステムを使っていると、エラー文で検索しても思うように情報がヒットしない場合**があります。  
そんな時は、**表示されているエラーコードで検索をしてみると、公式のドキュメントなどから原因に関連する情報が取得できる**場合があるので、ぜひ試してみてください。

今回のケースでは、`fields.E304`というエラーコードが表示されています。

そのため、"Django fields.E304"という検索ワードでも、この問題の原因と解決方法に関するページがヒットしました。


## まとめ 

今回は、Djangoのトラブルシューティングを題材に、エラー文を読むことや、検索の方法など、初歩的なナレッジについてまとめました。

トラブルシューティングのプロセスについては意外と情報が少なく、個人のセンス任せな部分が多い分野なのかなと感じています。

今後も何かいい題材があれば、より詳細なトラブルシューティングのノウハウについて紹介していきますのでぜひご参照ください。