---
title: WinDbgのユーザモードデバッグチュートリアルを試してみた
date: "2021-10-05"
template: "post"
draft: false
slug: "windows-windbg-002-tutorial"
category: "Windows"
tags:
  - "WinDbg"
  - "Kernel"
  - "Reversing"
description: ""
socialImage: "/media/cards/windows-windbg-002-tutorial.png"
---

WinDbgによるWindowsデバッグやダンプ解析によるトラブルシューティングに習熟することを目指しています。

今回はとりあえず公式チュートリアル内の手順を再現して、WinDbgによるユーザモードプロセスのデバッグについて試してみました。

WinDbgを用いたWindowsのデバッグやダンプの解析方法について公開している情報については、以下のページに一覧をまとめているので、よければご覧ください。

参考：[WinDbgを用いたデバッグとトラブルシューティングのテクニック](/windows-windbg-001-index)

この記事では以下の内容についてまとめています。

<!-- omit in toc -->
## もくじ
- [WiDbgとは](#widbgとは)
- [WinDbgチュートリアル](#windbgチュートリアル)
  - [今回使用する環境](#今回使用する環境)
  - [Notepad.exeの起動](#notepadexeの起動)
  - [シンボルパスの設定と読み込み](#シンボルパスの設定と読み込み)
  - [シンボル一覧の出力](#シンボル一覧の出力)
  - [ブレークポイントの設定](#ブレークポイントの設定)
  - [Notepad.exeを実行する](#notepadexeを実行する)
  - [プロセスに読み込まれているコードモジュールの一覧を表示する](#プロセスに読み込まれているコードモジュールの一覧を表示する)
  - [スタックトレースを表示する](#スタックトレースを表示する)
  - [Notepad.exeを再開する](#notepadexeを再開する)
  - [ファイル書き込み時にプロセスを停止する](#ファイル書き込み時にプロセスを停止する)
  - [プロセス内のスレッド一覧を表示する](#プロセス内のスレッド一覧を表示する)
  - [特定のスレッドのスタックトレースを取得する](#特定のスレッドのスタックトレースを取得する)
  - [デバッグを終了して、プロセスからデタッチする](#デバッグを終了してプロセスからデタッチする)
- [まとめ](#まとめ)

## WiDbgとは

Windows環境のデバッグやトラブルシューティングに使用するツールです。

参考：[Windows のデバッグの概要 - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/getting-started-with-windows-debugging)

WinDbgは、主に以下の用途に利用されます。

* Windowsメモリダンプやプロセスダンプの解析
* カーネルモードのライブデバッグ
* ユーザモードのライブデバッグ

MicrosoftのWindows開発チームも使用している公式のデバッガです。

VisualStudioデバッガとの違いとして、WinDbgはカーネルモードのデバッグやスレッドスタックの分析まで実現することができます。

## WinDbgチュートリアル

WinDbgのはじめの一歩として、[公式ドキュメントのチュートリアル](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/getting-started-with-windbg)を実践していきます。

このチュートリアルでは、WinDbgを使用してユーザモードのプロセスにアタッチし、デバッグを行います。

### 今回使用する環境

今回使用している環境は以下の環境です。

- Windows10 20H2
- WinDbg 10.0.22000.1 AMD64（管理者権限で起動）

### Notepad.exeの起動

Windows環境でWinDbgを起動した後、[Ctrl+E]キーで[Open Executable File]を呼び出し、`C:\Windows\System32\notepad.exe`を選択します。

![image-20211002113631533](image-20211002113631533.png)

実行ファイルを開くと、Commandウィンドウが起動しました。

![image-20211002113723502](image-20211002113723502.png)

### シンボルパスの設定と読み込み

Commandウィンドウの下部にあるコンソールに、以下のコマンドを入力します。

``` powershell
.sympath srv*
```

`.sympath`コマンドは、シンボルパスを設定するコマンドです。
シンボルパスとは、デバッガがシンボルファイルを探す際の探索先を意味します。

シンボルファイルは、デバッガがコード モジュール (関数名、変数名など) に関する情報を取得するために必要です。

参考：[.sympath (シンボル パスの設定) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/-sympath--set-symbol-path-)

シンボルパスの設定が完了したので、以下のコマンドを実行します。

``` powershell
.reload
```

`.reload`コマンドによって、シンボル情報を削除した後、再読み込みします。

参考：[.reload (モジュールの再読み込み) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/-reload--reload-module-)

`.reload`コマンドを実行しても、特にレスポンスはない点に注意が必要です。
以下の出力が得られたら次に進みます。

``` powershell
0:000> .reload
Reloading current modules
................
```

### シンボル一覧の出力

上記の出力確認後に、`x notepad!*`コマンドを実行して`Notepad.exe`モジュールのシンボルを表示します。
※ ここで出力が得られない場合は`.reload`コマンドを再実行します。

参考：[x notepad!*](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/x--examine-symbols-)

出力結果は1500行近い数になりました。
かなり多いですね。

### ブレークポイントの設定

次に、上記の出力で確認したシンボル情報を用いて、wWinMain関数にブレークポイントを設定します。

``` powershell
bu notepad!wWinMain
```

特に出力は返ってきませんが、`bl`コマンドでブレークポイントの一覧を参照できます。
参考：[bl (ブレークポイントの一覧) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/bl--breakpoint-list-)

これで、`notepad!wWinMain`にブレークポイントが設定されたことが確認できました。

``` powershell
0:000> bu notepad!wWinMain
0:000> bl
     0 e Disable Clear  00007ff6`8402c0f8     0001 (0001)  0:**** notepad!wWinMain
```

### Notepad.exeを実行する

ブレークポイントの設定が完了したので、`g`コマンドで起動しているアプリケーションを実行します。
参考：[g (実行) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/g--go-)

ブレークポイントで設定されたwWinMain関数の呼び出し時点で停止しました。

``` powershell
0:000> g
ModLoad: 00007ff9`9cd70000 00007ff9`9cda0000   C:\WINDOWS\System32\IMM32.DLL
Breakpoint 0 hit
notepad!wWinMain:
00007ff6`8402c0f8 488bc4          mov     rax,rsp
```

### プロセスに読み込まれているコードモジュールの一覧を表示する

ブレークポイントでプロセスが停止した状態で`lm`コマンドを実行し、現在プロセスに読み込まれているコードモジュールを確認します。
参考：[lm (読み込まれたモジュールの一覧表示) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/lm--list-loaded-modules-)

``` powershell
0:000> lm
start             end                 module name
00007ff6`84020000 00007ff6`8405a000   notepad    (pdb symbols)          C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym\notepad.pdb\6539CE998C7CAFD73A8E13A54542E1121\notepad.pdb
00007ff9`8ef30000 00007ff9`8f1ca000   COMCTL32   (deferred)             
00007ff9`982c0000 00007ff9`98350000   apphelp    (deferred)             
00007ff9`9aa40000 00007ff9`9aadd000   msvcp_win   (deferred)             
00007ff9`9ab90000 00007ff9`9ae59000   KERNELBASE   (deferred)             
00007ff9`9aec0000 00007ff9`9afc0000   ucrtbase   (deferred)             
00007ff9`9b010000 00007ff9`9b11b000   gdi32full   (deferred)             
00007ff9`9b340000 00007ff9`9b362000   win32u     (deferred)             
00007ff9`9bbc0000 00007ff9`9bcea000   RPCRT4     (deferred)             
00007ff9`9bf20000 00007ff9`9c275000   combase    (deferred)             
00007ff9`9c3c0000 00007ff9`9c46e000   shcore     (deferred)             
00007ff9`9cc50000 00007ff9`9cd0e000   KERNEL32   (deferred)             
00007ff9`9cd70000 00007ff9`9cda0000   IMM32      (deferred)             
00007ff9`9cfd0000 00007ff9`9cffb000   GDI32      (deferred)             
00007ff9`9d000000 00007ff9`9d1a1000   USER32     (deferred)             
00007ff9`9d1b0000 00007ff9`9d24e000   msvcrt     (deferred)             
00007ff9`9d290000 00007ff9`9d485000   ntdll      (pdb symbols)          C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym\ntdll.pdb\E2BF5EA3ECAA1D5310F1E166306A0BCC1\ntdll.pdb
```

### スタックトレースを表示する

プロセスが停止した状態で`k`コマンドを実行して、スタックトレースを表示します。

今回は`notepad!wWinMain`で停止したタイミングでのスタックトレースを取得できました。

``` powershell
0:000> k
 # Child-SP          RetAddr               Call Site
00 00000055`5f11f7b8 00007ff6`840459b6     notepad!wWinMain
01 00000055`5f11f7c0 00007ff9`9cc67034     notepad!__scrt_common_main_seh+0x106
02 00000055`5f11f800 00007ff9`9d2e2651     KERNEL32!BaseThreadInitThunk+0x14
03 00000055`5f11f830 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```

### Notepad.exeを再開する

もう一度`g`コマンドを実行すると、中断されていたプロセスが再開され、メモ帳アプリが起動しました。

![image-20211003210626408](image-20211003210626408.png)

この状態では、デバッガはBusy状態となり、追加のコマンド入力を受け付けなくなります。

再びメモ帳プロセスを停止してデバッガを使用するために、Breakボタンか、[Ctrl+Break]キーを押します。

![image-20211003211015461](image-20211003211015461.png)

これで再度メモ帳プロセスが停止され、デバッガ操作が可能になりました。

### ファイル書き込み時にプロセスを停止する

続いて、`bu ntdll!ZwWriteFile`を実行して、ファイル書き込み時にプロセスを中断するためのブレークポイントを設定します。

``` powershell
0:002> bu ntdll!ZwWriteFile
0:002> bl
     0 e Disable Clear  00007ff6`8402c0f8     0001 (0001)  0:**** notepad!wWinMain
     1 e Disable Clear  00007ff9`9d32ce60     0001 (0001)  0:**** ntdll!NtWriteFile
```

再び`g`コマンドを入力してプロセスを再開したのち、メモ帳に書き込み保存を実行しようとすると、プロセスが停止されます。

このタイミングでスタックトレースを表示すると、書き込み時のスタックトレースを取得することができます。

``` powershell
0:011> k
 # Child-SP          RetAddr               Call Site
00 00000055`5f8fdb78 00007ff9`9bc1f6f4     ntdll!NtWriteFile
01 00000055`5f8fdb80 00007ff9`9bc0c641     RPCRT4!UTIL_WriteFile+0x5c
02 00000055`5f8fdbe0 00007ff9`9bbf5863     RPCRT4!NMP_SyncSend+0x81
03 00000055`5f8fdc60 00007ff9`9bbf2a56     RPCRT4!OSF_CCONNECTION::TransSendReceive+0xf7
04 00000055`5f8fdcd0 00007ff9`9bbf239b     RPCRT4!OSF_CCONNECTION::SendBindPacket+0x2ee
05 00000055`5f8fdf20 00007ff9`9bbf3ed1     RPCRT4!OSF_CCONNECTION::ActuallyDoBinding+0xeb
06 00000055`5f8fdfd0 00007ff9`9bbf3c0e     RPCRT4!OSF_CCONNECTION::OpenConnectionAndBind+0x225
07 00000055`5f8fe080 00007ff9`9bbf7736     RPCRT4!OSF_CCALL::BindToServer+0xce
08 00000055`5f8fe120 00007ff9`9bbf84d6     RPCRT4!OSF_BINDING_HANDLE::InitCCallWithAssociation+0x8a
09 00000055`5f8fe180 00007ff9`9bbf75e7     RPCRT4!OSF_BINDING_HANDLE::AllocateCCall+0x256
0a 00000055`5f8fe2e0 00007ff9`9bca00f5     RPCRT4!OSF_BINDING_HANDLE::NegotiateTransferSyntax+0x37
0b 00000055`5f8fe330 00007ff9`9bca3840     RPCRT4!NdrpClientCall3+0x715
0c 00000055`5f8fe6a0 00007ff9`99bc139e     RPCRT4!NdrClientCall3+0xf0
0d 00000055`5f8fea30 00007ff9`775c1e00     wkscli!NetWkstaGetInfo+0x5e
0e 00000055`5f8feae0 00007ff9`83c62df6     ntlanman!NPOpenEnum+0x50
0f 00000055`5f8fec40 00007ff9`83c61b7f     MPR!MprOpenEnumConnect+0x176
```

### プロセス内のスレッド一覧を表示する

`~`コマンドを使って、プロセス内のスレッド一覧を取得できます。
参考：[~ (スレッドの状態) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/---thread-status-)

現在のメモ帳プロセスには、以下の14個のスレッドが存在するようです。

``` powershell
0:011> ~
   0  Id: de4.7ac Suspend: 1 Teb: 00000055`5f35c000 Unfrozen
   1  Id: de4.22f0 Suspend: 1 Teb: 00000055`5f36a000 Unfrozen
   2  Id: de4.1500 Suspend: 1 Teb: 00000055`5f36e000 Unfrozen
   3  Id: de4.198c Suspend: 1 Teb: 00000055`5f370000 Unfrozen
   4  Id: de4.2094 Suspend: 1 Teb: 00000055`5f364000 Unfrozen
   5  Id: de4.1d6c Suspend: 1 Teb: 00000055`5f372000 Unfrozen
   6  Id: de4.1048 Suspend: 1 Teb: 00000055`5f368000 Unfrozen
   7  Id: de4.1408 Suspend: 1 Teb: 00000055`5f374000 Unfrozen
   8  Id: de4.30c Suspend: 1 Teb: 00000055`5f376000 Unfrozen
   9  Id: de4.1b18 Suspend: 1 Teb: 00000055`5f378000 Unfrozen
  10  Id: de4.af8 Suspend: 1 Teb: 00000055`5f37a000 Unfrozen
. 11  Id: de4.898 Suspend: 1 Teb: 00000055`5f37e000 Unfrozen
  12  Id: de4.1720 Suspend: 1 Teb: 00000055`5f380000 Unfrozen
  13  Id: de4.37c Suspend: 1 Teb: 00000055`5f382000 Unfrozen
```

### 特定のスレッドのスタックトレースを取得する

ここで、特定のスレッドのスタックトレースを取得するには、以下のコマンドを続けて使用します。

``` powershell
~0s
k
```

`~0s`コマンドは、スレッド番号0の設定を取得します。
参考：[~s (現在のスレッドの設定) - Windows drivers | Microsoft Docs](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/-s--set-current-thread-)

出力は次のようになりました。

``` powershell
0:011> ~0s
win32u!NtGdiGetCharABCWidthsW+0x14:
00007ff9`9b3465e4 c3              ret
0:000> k
 # Child-SP          RetAddr               Call Site
00 00000055`5f117108 00007ff9`9b01a2ae     win32u!NtGdiGetCharABCWidthsW+0x14
01 00000055`5f117110 00007ff9`9b01a211     gdi32full!LoadGlyphMetricsWithGetCharABCWidthsI+0x5e
02 00000055`5f1174b0 00007ff9`9b019d60     gdi32full!LoadGlyphMetrics+0x99
03 00000055`5f1174f0 00007ff9`8aa29016     gdi32full!CUspShapingFont::GetGlyphDefaultAdvanceWidths+0x150
04 00000055`5f117550 00007ff9`9b020b65     TextShaping!ShapingGetGlyphPositions+0x516
05 00000055`5f117750 00007ff9`9b0266e3     gdi32full!ShlPlaceOT+0x255
06 00000055`5f117970 00007ff9`9b025d9b     gdi32full!RenderItemNoFallback+0x573
07 00000055`5f117aa0 00007ff9`9b025c6b     gdi32full!RenderItemWithFallback+0xeb
08 00000055`5f117af0 00007ff9`9b025a3f     gdi32full!RenderItem+0x3b
09 00000055`5f117b40 00007ff9`9b027ac6     gdi32full!ScriptStringAnalyzeGlyphs+0x20f
0a 00000055`5f117bf0 00007ff9`9b024ca2     gdi32full!ScriptStringAnalyse+0x626
0b 00000055`5f117dc0 00007ff9`9b0246be     gdi32full!LpkCharsetDraw+0x5c2
0c 00000055`5f117ff0 00007ff9`9d01f5f2     gdi32full!LpkDrawTextEx+0x5e
0d 00000055`5f118060 00007ff9`9d01e9bf     USER32!DT_DrawStr+0xb6
0e 00000055`5f118110 00007ff9`9d01eede     USER32!DT_GetLineBreak+0xf3
0f 00000055`5f1181b0 00007ff9`9d01eb50     USER32!DrawTextExWorker+0x36e
10 00000055`5f118300 00007ff9`6b8a6123     USER32!DrawTextW+0x40
11 00000055`5f118370 00007ff9`6b89ac60     DUI70!DirectUI::Element::GetContentSize+0x463
12 00000055`5f118450 00007ff9`6b8a7196     DUI70!DirectUI::Element::_UpdateDesiredSize+0x6a0
{{ 以下略 }}
```

### デバッグを終了して、プロセスからデタッチする

最後に`qd`コマンドを使用して、デバッグを終了してプロセスからデタッチします。

デバッグを終了すると、Commandウィンドウが終了し、停止されていたメモ帳の書き込み処理が再開されました。

## まとめ

とりあえず[公式チュートリアル](https://docs.microsoft.com/ja-jp/windows-hardware/drivers/debugger/getting-started-with-windbg)のユーザモードデバッグの手順について一通り実践してみました。

WinDbgを用いたWindowsのデバッグやダンプの解析方法について公開しているその他情報については、以下のページのリストをご覧ください。

参考：[WinDbgを用いたデバッグとトラブルシューティングのテクニック](/windows-windbg-001-index)