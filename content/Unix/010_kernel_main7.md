---
title: 
date: "2022-02-20"
template: "post"
draft: true
slug: ""
category: ""
tags:
  - ""
  - ""
  - ""
description: ""
socialImage: "/media/cards/no-image.png"
---

[はじめてのOSコードリーディング ~UNIX V6で学ぶカーネルのしくみ](https://amzn.to/3q8TU3K)にインスパイアされて[xv6 OS](https://github.com/mit-pdos/xv6-public)を読んでます。

UNIX V6自体はx86CPUでは動作しないため、基本的には、UNIXv6をX86アーキテクチャで動くようにした[xv6 OS](https://github.com/mit-pdos/xv6-public)のリポジトリをForkした[kash1064/xv6-public: xv6 OS](https://github.com/kash1064/xv6-public)のソースコードを読んでいくことにしました。

[前回](https://yukituna.com/3923/)は`main`関数で実行される`picinit`関数と`ioapicinit`関数の動きを確認しました。

https://yukituna.com/3923/

今回は`consoleinit`関数の挙動を追っていきます。

<!-- omit in toc -->
## もくじ
- [consoleinit関数](#consoleinit関数)
  - [devsw構造体について](#devsw構造体について)
  - [inodeとは](#inodeとは)
  - [consolewrite関数を読む](#consolewrite関数を読む)
  - [ビデオメモリの書き込み](#ビデオメモリの書き込み)
  - [consoleread関数を読む](#consoleread関数を読む)
- [まとめ](#まとめ)
- [参考書籍](#参考書籍)

## consoleinit関数

`consoleinit`関数は`console.c`で以下のように定義されています。

``` c
void consoleinit(void)
{
  initlock(&cons.lock, "console");

  devsw[CONSOLE].write = consolewrite;
  devsw[CONSOLE].read = consoleread;
  cons.locking = 1;

  ioapicenable(IRQ_KBD, 0);
}
```

まず1行目の`initlock(&cons.lock, "console");`ですが、これは[メモリ割り当て・排他制御 編](https://yukituna.com/3869/)で確認したメモリロックのために`spinlock`構造体を初期化する関数でした。

今回使用している`&cons.lock`は、以下のように定義されています。

``` c
static struct {
  struct spinlock lock;
  int locking;
} cons;
```

なお、`consoleinit`関数の中ではメモリロックは行われません。

`consoleread`関数や`consolewrite`関数などが実行される際に、`cons`が使われてメモリロックが行われます。

続いて、以下の行を見ていきます。

``` c
devsw[CONSOLE].write = consolewrite;
devsw[CONSOLE].read = consoleread;
```

ここで参照している`devsw`は`devsw`構造体の配列であり、この配列は`file.c`で定義されています。

``` c
struct devsw devsw[NDEV];
```

また、`devsw`構造体の定義は`file.h`で行われています。

``` c
// table mapping major device number to
// device functions
struct devsw {
  int (*read)(struct inode*, char*, int);
  int (*write)(struct inode*, char*, int);
};

extern struct devsw devsw[];
#define CONSOLE 1
```

ちなみに`NDEV`は`param.h`で10と定義されていることがわかります。

``` c
#define NDEV         10  // maximum major device number
```

### devsw構造体について

ここで詳しく知りたいのは、`devsw`構造体が何者かという点です。

UNIXのマニュアルなどを見ると、`devsw`構造体はデバイスドライバが`character device interfaces`を持つ場合に使用されるもののように見えます。

参考：[devsw(9) - NetBSD Manual Pages](https://man.netbsd.org/devsw.9)

また、以下のページのように、「システムが一文字ずつデータを転送する機器に対応」した入出力インターフェースが`character device interfaces`に該当すると考えられます。

参考：[デバイスファイル - Wikipedia](https://ja.wikipedia.org/wiki/%E3%83%87%E3%83%90%E3%82%A4%E3%82%B9%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB)

ここで`devsw`構造体の定義を見ると、`read`と`write`の2種類の関数ポインタが設定されています。

ここには、`consoleinit`関数のように任意の関数割り当てが行われます。

引数にはいずれも`inode`構造体が含まれます。

`inode`構造体は、`devsw`構造体と同様に`file.h`で定義されています。

``` c
// in-memory copy of an inode
struct inode {
  uint dev;           // Device number
  uint inum;          // Inode number
  int ref;            // Reference count
  struct sleeplock lock; // protects everything below here
  int valid;          // inode has been read from disk?

  short type;         // copy of disk inode
  short major;
  short minor;
  short nlink;
  uint size;
  uint addrs[NDIRECT+1];
};
```

### inodeとは

そもそも`inode`とは何かについて触れておきます。

`inode`とはざっくり言うとファイル、ディレクトリなどのファイルシステムのオブジェクトに関する情報が格納されている構造体です。

`inode`の持つ情報としては以下のようなものが挙げられます。

- ファイルサイズ(バイト数)
- ファイルを格納しているデバイスのデバイスID
- ファイルの所有者、グループのID
- ファイルシステム内でファイルを識別するinode番号
- タイムスタンプ

参考：[inode - Wikipedia](https://ja.wikipedia.org/wiki/Inode)

xv6OSの`inode`構造体を見ても上記に近い情報が格納されています。

`inode`は、システム内に一意のIDで管理されます。(xv6OSでは恐らく`inum`が該当する)

割り当て可能な`inode`番号には通常上限があり、もし`inode`番号が枯渇した場合は、ストレージデバイスのディスク容量に空きがあっても新規にファイルの作成ができなくなります。

一般的なLinuxシステムの場合は、`df -i`コマンドで各デバイスごとの使用可能な`inode`の上限を確認できます。

``` bash
$ df -i
Filesystem                         Inodes  IUsed   IFree IUse% Mounted on
udev                              1007124    449 1006675    1% /dev
tmpfs                             1019154    919 1018235    1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv 1310720 380878  929842   30% /
tmpfs                             1019154      1 1019153    1% /dev/shm
tmpfs                             1019154      5 1019149    1% /run/lock
tmpfs                             1019154     18 1019136    1% /sys/fs/cgroup
/dev/loop0                             29     29       0  100% /snap/bare/5
/dev/loop2                          10847  10847       0  100% /snap/core18/2284
/dev/loop1                          10836  10836       0  100% /snap/core18/2253
/dev/loop3                          11776  11776       0  100% /snap/core20/1270
/dev/loop5                          18500  18500       0  100% /snap/gnome-3-34-1804/72
/dev/loop4                          11777  11777       0  100% /snap/core20/1328
/dev/loop6                          18500  18500       0  100% /snap/gnome-3-34-1804/77
/dev/loop7                          65095  65095       0  100% /snap/gtk-common-themes/1519
/dev/loop8                            796    796       0  100% /snap/lxd/21835
/dev/loop9                          64986  64986       0  100% /snap/gtk-common-themes/1515
/dev/loop10                           796    796       0  100% /snap/lxd/21545
/dev/loop11                           479    479       0  100% /snap/snapd/14295
/dev/loop12                           482    482       0  100% /snap/snapd/14549
/dev/sda2                           65536    320   65216    1% /boot
tmpfs                             1019154     45 1019109    1% /run/user/121
tmpfs                             1019154     83 1019071    1% /run/user/1000
```

参考：[iノード（inode）とは](https://kazmax.zpp.jp/linux_beginner/inode.html)

### consolewrite関数を読む

この時点ではまだ`inode`を使ってファイルを作成することはないので、ひとまずxv6OSのコードに戻ります。

``` c
devsw[CONSOLE].write = consolewrite;
devsw[CONSOLE].read = consoleread;
```

`devsw`配列の`CONSOLE = 1`要素の`write`と`read`には、それぞれ`console.c`で定義された関数が割り当てされます。

まずは`consolewrite`関数を読んでみます。

``` c
int consolewrite(struct inode *ip, char *buf, int n)
{
  int i;

  iunlock(ip);
  acquire(&cons.lock);
  for(i = 0; i < n; i++) consputc(buf[i] & 0xff);
  release(&cons.lock);
  ilock(ip);

  return n;
}
```

`consolewrite`関数はターゲットとなる`inode`構造体変数のポインタと`consputc`関数に引き渡す文字およびその長さが引数として与えられます。

まず`iunlock`関数ですが、これは`fs.c`で定義されています。

``` c
// Unlock the given inode.
void iunlock(struct inode *ip)
{
  if(ip == 0 || !holdingsleep(&ip->lock) || ip->ref < 1) panic("iunlock");
  releasesleep(&ip->lock);
}
```

この関数についてはファイルシステムを扱う際に詳しく見ていきますが、受け渡しされた`inode`の持つ‘sleeplock‘構造体を操作してロックを解放しています。

続いては`acquire`でロックを取得した後、`consputc`関数に受け渡しされた文字列を一文字ずつ流し込んでいます。

この時、与えられた文字列は`0xFF`とのANDになるので、印字可能な状態が担保されます。

``` c
void consputc(int c)
{
  if(panicked){
    cli();
    for(;;) ;
  }

  if(c == BACKSPACE){
    uartputc('\b'); uartputc(' '); uartputc('\b');
  } else{
      uartputc(c);
  }
  cgaputc(c);
}
```

ここで、与えられた値を引数として`uartputc`関数が呼び出されます。

`uartputc`関数は`uart.c`で定義された関数で、シリアルポート(UART)への空きこみを行います。

ここでは、`COM1(I/Oポート 0x3f8)`に受け取った値を書き込んでいます。

``` c
void uartputc(int c)
{
  int i;

  if(!uart) return;
  for(i = 0; i < 128 && !(inb(COM1+5) & 0x20); i++) microdelay(10);
  outb(COM1+0, c);
}
```

`COM1+0`はデータレジスタになっており、ここに値が書き込まれると送信バッファに書き込みが行われます。

その前の行の`inb(COM1+5)`はラインステータスレジスタの値の読み取りを行っています。

ラインステータスレジスタの6番目のbitは`THRE`と呼ばれるレジスタで、このbitが立っているときは送信バッファが空で、新たなデータを送信可能であることを意味します。

参考：[Serial Ports - OSDev Wiki](https://wiki.osdev.org/Serial_Ports)

つまり`!(inb(COM1+5) & 0x20)`の行は、ラインステータスレジスタの`THRE`をチェックして、送信バッファが使用可能でない場合は`microdelay`関数により処理を遅延させる処理を行っているわけです。

ちなみに、`BACKSPACE`が入力された場合の書き込みが`uartputc('\b'); uartputc(' '); uartputc('\b');`になっているのは、カーソルを一つ戻してスペースで上書きした上で、もう一度書き込み前の位置にカーソルを戻しているイメージみたいです。

### ビデオメモリの書き込み

シリアルポートへの書き込みが完了したら、最後に`cgaputc`関数が呼び出されます。

`cgaputc`関数では、入力値をビデオメモリに書き込んで出力します。

``` c
static void cgaputc(int c)
{
  int pos;

  // Cursor position: col + 80*row.
  outb(CRTPORT, 14);
  pos = inb(CRTPORT+1) << 8;
  outb(CRTPORT, 15);
  pos |= inb(CRTPORT+1);

  if(c == '\n') pos += 80 - pos%80;
  else if(c == BACKSPACE){
    if(pos > 0) --pos;
  } else{
    crt[pos++] = (c&0xff) | 0x0700;  // black on white
  }
  if(pos < 0 || pos > 25*80) panic("pos under/overflow");

  if((pos/80) >= 24){  // Scroll up.
    memmove(crt, crt+80, sizeof(crt[0])*23*80);
    pos -= 80;
    memset(crt+pos, 0, sizeof(crt[0])*(24*80 - pos));
  }

  outb(CRTPORT, 14);
  outb(CRTPORT+1, pos>>8);
  outb(CRTPORT, 15);
  outb(CRTPORT+1, pos);
  crt[pos] = ' ' | 0x0700;
}
```

ここで使用している書き込み先の`crt`はアドレス`0xb8000`の領域です。

この領域はフレームバッファと呼ばれる領域です。

``` c
//PAGEBREAK: 50
#define BACKSPACE 0x100
#define CRTPORT 0x3d4
static ushort *crt = (ushort*)P2V(0xb8000);  // CGA memory
```

参考：[フレームバッファ（frame buffer）とは - IT用語辞典 e-Words](https://e-words.jp/w/%E3%83%95%E3%83%AC%E3%83%BC%E3%83%A0%E3%83%90%E3%83%83%E3%83%95%E3%82%A1.html)

参考：[3.-The Screen](http://www.jamesmolloy.co.uk/tutorial_html/3.-The%20Screen.html)

まず`CRTPORT`ですが、これは`CRT Controller`のレジスタである`0x3D4`を指しています。

これは制御用のレジスタで、`0x3D4`に対応するデータレジスタ領域は`0x3D5`となります。

この2つの領域を利用してコンソール上のカーソル位置をコントロールできます。

`0x3D4`に14をセットすることで、16bitで表現されるカーソルの上位8bitを制御することを指定します。

そして、15をセットした場合は、カーソルの下位8bitを制御することを指定します。

つまり、以下の行では変数`pos`に現在のカーソルの16bitを格納しているわけです。

``` c
outb(CRTPORT, 14);
pos = inb(CRTPORT+1) << 8;
outb(CRTPORT, 15);
pos |= inb(CRTPORT+1);
```

ここで取得したカーソルの上位bitと下位bitの関係は以下のようになります。

上位8bitがカーソルの行の位置を指し、下位8bitが何文字目かを指しています。

![https://yukituna.com/wp-content/uploads/2022/02/image-37.png](https://yukituna.com/wp-content/uploads/2022/02/image-37.png)

以下の行は、改行文字が渡された場合の挙動です。

``` c
if(c == '\n') pos += 80 - pos%80;
```

カーソル位置が次の行の一番左端の位置になるように`pos`を加算しています。

また、`BACKSPACE`が与えられた場合はカーソル位置を一つ戻します。

文字入力が与えられた場合は、16bitの文字データを格納します。

``` c
else if(c == BACKSPACE){
  if(pos > 0) --pos;
} else{
  crt[pos++] = (c&0xff) | 0x0700;  // black on white
}
```

この文字データの上位8bitには、背景と文字の色の情報が保持されます。

また、下位8bitには表示する文字が指定されます。

![https://yukituna.com/wp-content/uploads/2022/02/image-35.png](https://yukituna.com/wp-content/uploads/2022/02/image-35.png)

参考画像：[3.-The Screen](http://www.jamesmolloy.co.uk/tutorial_html/3.-The%20Screen.html)

実際にデバッガで確認してみると、この処理によってコンソールに文字が表示されていることを確認できます。

![https://yukituna.com/wp-content/uploads/2022/02/image-34.png](https://yukituna.com/wp-content/uploads/2022/02/image-34.png)

次の処理は非常にシンプルで、最大の行数である24行をオーバーした場合に、先頭行を削除してスクロールした上で、末尾の行を空行にしています。

``` c
if((pos/80) >= 24){  // Scroll up.
  memmove(crt, crt+80, sizeof(crt[0])*23*80);
  pos -= 80;
  memset(crt+pos, 0, sizeof(crt[0])*(24*80 - pos));
}
```

最後の処理は、現在のカーソル位置を`CRTPORT`と`CRTPORT+1`に保存しています。

``` c
outb(CRTPORT, 14);
outb(CRTPORT+1, pos>>8);
outb(CRTPORT, 15);
outb(CRTPORT+1, pos);
crt[pos] = ' ' | 0x0700;
```

これで`consputc`関数によるコンソールへの書き込みが完了します。

`consolewrite`関数に戻ったらメモリロックの解除と`inode`のロックを行って終了です。

``` c
release(&cons.lock);
ilock(ip);
```

### consoleread関数を読む

次は`consoleread`関数を読んでいきます。

`consoleread`関数は、`inode`と読み取り先のポインタ、読み取るバッファサイズを引数として受け取ります。

``` c
int consoleread(struct inode *ip, char *dst, int n)
{
  uint target;
  int c;

  iunlock(ip);
  target = n;
  acquire(&cons.lock);
  while(n > 0){
    while(input.r == input.w){
      if(myproc()->killed){
        release(&cons.lock);
        ilock(ip);
        return -1;
      }
      sleep(&input.r, &cons.lock);
    }
    c = input.buf[input.r++ % INPUT_BUF];
    if(c == C('D')){  // EOF
      if(n < target){
        // Save ^D for next time, to make sure
        // caller gets a 0-byte result.
        input.r--;
      }
      break;
    }
    *dst++ = c;
    --n;
    if(c == '\n')
      break;
  }
  release(&cons.lock);
  ilock(ip);

  return target - n;
}
```

`consolwrite`関数同様メモリロックと`inode`のロック解除を行った後、指定されたバッファサイズのループ内で以下の処理を行います。

``` c
c = input.buf[input.r++ % INPUT_BUF];
if(c == C('D')){  // EOF
  if(n < target){
    // Save ^D for next time, to make sure
    // caller gets a 0-byte result.
    input.r--;
  }
  break;
}

*dst++ = c;
--n;
if(c == '\n') break;
```

`input`構造体は以下の構造体です。

``` c
#define INPUT_BUF 128
struct {
  char buf[INPUT_BUF];
  uint r;  // Read index
  uint w;  // Write index
  uint e;  // Edit index
} input;
```

この`input`構造体に入ってきた値を1文字ずつ読みだして取得しているようです。

実際にこの処理が呼び出されるのは、OSの起動が完了してからです。

具体的には、シェルに入力した文字を取得する際などに使用されます。

以下の画像は、コンソールに「l」という文字を打ち込んだ際の挙動をデバッガで確認したときのものです。

![https://yukituna.com/wp-content/uploads/2022/02/image-38.png](https://yukituna.com/wp-content/uploads/2022/02/image-38.png)

ユーザの入力値がどのように`input.buf`に格納されるかは、実際にシェルが使えるようになってから詳しく追っていこうと思います。

最後に`ioapicenable(IRQ_KBD, 0);`で割込みを有効化して、`consoleinit`関数は終了します。

## まとめ

今回はコンソールの初期化を行いました。

入出力インターフェースの仕組みについて知ることができたので非常に興味深かったです。

次回はシリアルポートを初期化する`uartinit`関数から見ていきたいと思います。

## 参考書籍

- [30日でできる! OS自作入門](https://amzn.to/3qZSCY7)
- [ゼロからのOS自作入門](https://amzn.to/3qXYsZX)
- [はじめてのOSコードリーディング ~UNIX V6で学ぶカーネルのしくみ](https://amzn.to/3q8TU3K)
- [詳解 Linuxカーネル](https://amzn.to/3I6fkVt)
- [作って理解するOS x86系コンピュータを動かす理論と実装](https://amzn.to/3JRUdI2)