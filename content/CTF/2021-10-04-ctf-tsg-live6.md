---
title: Truth about PiのWriteUpと備忘録[TSG LIVE! 6 CTF]
date: "2021-10-04"
template: "post"
draft: false
slug: "ctf-tsg-live6"
category: "CTF"
tags:
  - "CTF"
  - "Web"
description: "TSG LIVE! 6 CTFのWEB問、Truth about Piがとても勉強になったのでWriteUpを兼ねて学んだことをまとめていこうと思います。"
socialImage: "/media/cards/ctf-elf-training.png"
---

## はじめに
TSG LIVE! 6 CTFのWEB問、"[Truth about Pi](https://github.com/tsg-ut/tsg-live-ctf-6/blob/main/web/truth-about-pi)"がとても勉強になったのでWriteUpを兼ねて学んだことをまとめていこうと思います。

最初は上手いことインジェクションする問題だと思っていたので、延々とRabbit Holeに入りこんでしまっていました。

自戒も込めて真面目に勉強した結果の備忘録です。

## WriteUp

問題サーバにアクセスすると、koaフレームワーク製のページにアクセスできます。

提供された問題コードを読むと、以下の部分で入力値に対して処理を行い、最終的に“digit”の値が0になったときにFLAGが出力されることがわかりました。

```javascript
if (ctx.method === 'POST') {
	const { index } = ctx.request.body; // 1
    const pi = Math.PI.toString(); 		// 2
    const digit = parseInt(get(pi, index)); //3
    content = `
		<h1>円周率の${index}桁目は${digit}です！</h1>
		${digit === 0 ? `<p>${process.env.FLAG}</p>` : ''}
	`;
}
```

ここで、最終的な解答として以下のようなリクエストでFLAGを取得することができます。

```
curl -X POST -d "index=toString.length" http://localhost:3000
```

では、なぜこのリクエストでFLAGの取得ができるのかを追っていきたいと思います。

## 1. POSTリクエストを受け取る

まずはPOSTリクエストを受け取った直後の`const { index } = ctx.request.body;`の処理についてみていきます。

ここで、送信されたPOSTリクエストのBody部分が、[**koa-bodyparser**](https://github.com/koajs/bodyparser)によってオブジェクトとして流されてきます。

このオブジェクト、モジュールのソースコードを読むと最終的にJSON形式でパースされたものが返されているようです。
そのため、分割代入で”index”の値がconst変数indexに格納されます。

パース処理の都合上、ユーザが入力した値は必ずStringsオブジェクトになり、Nunberオブジェクトを流すことはできません。

また、この問題とは関係ないですが、POSTリクエストに"index"を複数定義した場合は、Arrayオブジェクトとしてindexに格納されます。

## 2. 円周率の準備

円周率"3.141592653589793"をStringオブジェクトに変換して変数piに格納しています。

（Math.PIがもっと長い円周率を出力してくれれば何も悩むことなかったのに・・・）

## 3. digitを0にする

1,2のステップで、変数indexとpiのそれぞれにStringオブジェクトが格納されています。

ここから、これを利用して`parseInt(get(pi, index))`の結果を0にする方法を探っていきます。

まず、一番外側の'parseInt()'ですが、これは文字列を数値に変換するだけの関数なので深く考えなくてもよさそうです。
なので、`get(pi, index)`の結果が文字列'0'になる入力値を考えます。

問題コードを読むと`get`は、 `const get = require('lodash.get');`として定義されているので、`lodash.get`のコードを見てみます。

第3引数の`defaultValue`は、resultがNullになったときの戻り値を定義します。

しかし、残念ながら今回はここに値を入力する方法がありません。

```javascript
function get(object, path, defaultValue) {
  const result = object == null ? undefined : baseGet(object, path)
  return result === undefined ? defaultValue : result
}
```

上記のコードの`object`には変数piが、`path`には変数indexが入ります。

そのため、`baseGet`関数が呼び出されることがわかります。

`baseGet`関数のコードも見てみます。

```javascript
function baseGet(object, path) {
  path = castPath(path, object)

  let index = 0
  const length = path.length

  while (object != null && index < length) {
    object = object[toKey(path[index++])]
  }
  return (index && index == length) ? object : undefined
}
```

ここで1つ目の重要なポイントになるのは`castPath`関数です。

コードを見ると受け取った値が配列ではない場合、`stringToPath`に流して配列に変換していることがわかりました。

```javascript
var stringToPath = memoize(function(string) {
  string = toString(string);

  var result = [];
  if (reLeadingDot.test(string)) {
    result.push('');
  }
  string.replace(rePropName, function(match, number, quote, string) {
    result.push(quote ? string.replace(reEscapeChar, '$1') : (number || match));
  });

  return result;
});

function castPath(value) {
  return isArray(value) ? value : stringToPath(value);
}
```

そしてこの配列の変換の方法がポイントになります。

`stringToPath`では、'reLeadingDot'によって、'.'区切りで文字列を分割します。

そのため、'toString.length'のような文字列がvalueに代入された場合は、変換後の配列が`[toString, length]`のように2要素に分割されてしまうわけです！

さて、`baseGet`関数に戻ります。

この時点で変数pathには、ユーザが入力した文字列を配列に変換した値が格納されています。

```javascript
let index = 0
const length = path.length
while (object != null && index < length) {
	object = object[toKey(path[index++])]
}
return (index && index == length) ? object : undefined
```

変数objectは、`baseGet`関数の戻り値なので、すなわち`get(pi, index)`の戻り値となります。

whileループの処理を追いかけてみましょう。
次のようにコードを改変して出力を見てみました。

```javascript
let index = 0;
let object = Math.PI.toString();
const path = ["toString", "length"];
const length = path.length;
console.log("Before :" + object);
while (object != null && index < length) {
	object = object[toKey(path[index++])]
  	console.log("Count " + index.toString() + ": " + object);
}
console.log("After :" + object);
```

結果はこちらです。

```
> "Before :3.141592653589793"
> "Count 1: function toString() { [native code] }"
> "Count 2: 0"
> "After :0"
```

一体何が起こっているのかを説明します。

ループ内では、objectに対して、ブラケット表記法のプロパティアクセサを用いたプロパティの取得が行われています。

そのため、1度目の処理では、Stringオブジェクトである"3.14..."に対して、`toString`プロパティを参照したため、Functionオブジェクトが変数objectに格納されたのです。

そして、2度目の処理では、Functionオブジェクトとなった変数objectの`length`プロパティに対して参照を試みています。

これは今回初めて知ったのですが、JavascriptにおいてFunctionオブジェクトのlengthプロパティは引数の数を返すそうです。

参考：[Function.length - JavaScript | MDN](https://developer.mozilla.org/ja/docs/Web/JavaScript/Reference/Global_Objects/Function/length)

今回Functionオブジェクトとして利用したのは`toString`関数であり、その引数は0です。

そのため、`baseGet`関数の戻り値も0となり、最終的に`get(pi, index)`から返却される値も0となるため、FLAGが取得できるという流れです。

## まとめ

ちなみに、前述の理由により、`toString.length`以外にも、参照可能かつ期待される引数が0の関数名を指定してあげれば、すべてFLAG取得に利用することができます。
（例：valueOf, toLowerCaseなど）

WEB問は普段解かないものの、たまたま挑戦した問題でした。

ライブラリのコードはちゃんと追っていたのですが、残念ながらJavascriptのPrototypeの仕様への理解が浅く、自力でのFLAG取得には至りませんでしたものの、非常に学びの多い良問だと感じたため、今回記事にまとめさせていただきました。

作問者の方に感謝！

