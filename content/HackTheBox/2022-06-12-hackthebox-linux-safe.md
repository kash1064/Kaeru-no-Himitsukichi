---
title: 【Easy/Linux】Safe Writeup(HackTheBox)
date: "2022-06-12"
template: "post"
draft: true
slug: "hackthebox-linux-safe"
category: "HackTheBox"
tags:
  - "HackTheBox"
  - "Linux"
  - "EasyBox"
description: "HackTheBoxのリタイアマシン「Safe」のWriteUpです。"
socialImage: "/media/cards/no-image.png"

---

「Hack The Box」という、ペネトレーションテストの学習プラットフォームを利用してセキュリティについて学んでいます。
「Hack The Box」のランクは、本記事執筆時点でProHackerです。

<img src="../../static/media/2022-06-12-hackthebox-safe/327080.png" alt="Hack The Box">

今回は、HackTheBoxのリタイアマシン「Safe」のWriteUpです。

## 本記事について

**本記事の内容は社会秩序に反する行為を推奨することを目的としたものではございません。**

自身の所有する環境、もしくは許可された環境以外への攻撃の試行は、「不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）」に違反する可能性があること、予めご留意ください。

またすべての発言は所属団体ではなく個人に帰属します。

<!-- omit in toc -->
## もくじ

- [本記事について](#本記事について)
- [探索](#探索)
  - [BOFを悪用してシェルを取得する](#bofを悪用してシェルを取得する)


## 探索

とりあえずNmapスキャンをかけてみると、HTTPとSSHが開いていることがわかりました。

``` bash
Nmap scan report for targethost.htb (10.10.10.147)
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 6d:7c:81:3d:6a:3d:f9:5f:2e:1f:6a:97:e5:00:ba:de (RSA)
|   256 99:7e:1e:22:76:72:da:3c:c9:61:7d:74:d7:80:33:d2 (ECDSA)
|_  256 6a:6b:c3:8e:4b:28:f7:60:85:b1:62:ff:54:bc:d8:d6 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.89 seconds
```

gobusterの出力結果はあまり参考になりませんでした。

``` bash
gobuster dir -u http://targethost.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -t 40 | tee gobuster.txt

===============================================================
2022/06/12 01:36:47 Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 317] [--> http://targethost.htb/manual/]
/server-status        (Status: 403) [Size: 302] 
===============================================================
```

ドメイン制限されている可能性もありますが、現状では何もわからないのでアプローチを変えてApacheの脆弱性を探していきます。

ちょっと手詰まり感があったので、wellknownポート以外のポートスキャンも試してみたところ、1337ポートが解放されていることがわかりました。

``` bash
nmap -p- targethost.htb -Pn -sC -sV -A  | tee nmap_max.txt
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     05:43:45 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|   DNSVersionBindReqTCP: 
|     05:43:39 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|   GenericLines: 
|     05:43:26 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back?
|   GetRequest: 
|     05:43:33 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions: 
|     05:43:33 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help: 
|     05:43:50 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? HELP
|   NULL: 
|     05:43:26 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|   RPCCheck: 
|     05:43:34 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|   RTSPRequest: 
|     05:43:34 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? OPTIONS / RTSP/1.0
|   SSLSessionReq: 
|     05:43:50 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back?
|   TLSSessionReq, TerminalServerCookie: 
|     05:43:51 up 2:04, 0 users, load average: 0.00, 0.00, 0.00
|_    What do you want me to echo back?
```

1337ポートでは何かよくわからないサービスが稼働しているようですが、netcatでつないで見ると`What do you want me to echo back?`という出力が返ってきます。

![image-20220612190508371](../../static/media/2022-06-12-hackthebox-linux-safe/image-20220612190508371.png)

色々と試してみると、改行文字込みで120バイト分のデータを入力すると応答が返ってこなくなることから、BOFの脆弱性を持ったサービスであると考えられます。

![image-20220612193635553](../../static/media/2022-06-12-hackthebox-linux-safe/image-20220612193635553.png)

とはいえ、正直応答は返ってこないし裏で動いているバイナリも特定できていないので行き詰まりました。

ブラインドでBOFを通せるほどの経験はないですね。。

さすがにブラインドでやらせることはないだろうと思ったのでバイナリを探していたのですが、80番ポートの方のトップページに`myapp`でファイルがダウンロード可能だという情報がありました。

![image-20220612201908834](../../static/media/2022-06-12-hackthebox-linux-safe/image-20220612201908834.png)

手に入れたバイナリをデコンパイルしてみましたがかなりシンプルですね。

サーバ側にある`uptime`というプログラムを呼び出して、ユーザから受け取った入力をputするだけのプログラムのようです。

![image-20220612222939668](../../static/media/2022-06-12-hackthebox-linux-safe/image-20220612222939668.png)

ここではBOFを使って単純に`/bin/sh`のアドレスを呼び出せばよさそうです。

### BOFを悪用してシェルを取得する

シェルの取得に必要な`system`関数のPLTを特定します。

``` bash
$ objdump -d -M intel -j .plt myapp
0000000000401040 <system@plt>:
  401040:       ff 25 da 2f 00 00       jmp    QWORD PTR [rip+0x2fda]        # 404020 <system@GLIBC_2.2.5>
  401046:       68 01 00 00 00          push   0x1
  40104b:       e9 d0 ff ff ff          jmp    401020 <.plt>
```



``` bash
$ p system
$4 = {int (const char *)} 0x7ffff7e1f860 <__libc_system>
```





























