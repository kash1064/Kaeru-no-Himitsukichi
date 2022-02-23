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

[前回](https://yukituna.com/3970/)は`main`関数で実行される`consoleinit`関数の動きを確認しました。

https://yukituna.com/3970/

今回は`uartinit`関数の挙動を追っていきます。

<!-- omit in toc -->
## もくじ
- [uartinit関数](#uartinit関数)
  - [UARTとは](#uartとは)
  - [通信にシリアルポートを使用する](#通信にシリアルポートを使用する)
- [まとめ](#まとめ)
- [参考書籍](#参考書籍)

## uartinit関数

`uartinit`関数は`uart.c`関数で定義された関数で、シリアルポート関連の初期化を行っています。

``` c
#define COM1    0x3f8
static int uart;    // is there a uart?

void uartinit(void)
{
  char *p;

  // Turn off the FIFO
  outb(COM1+2, 0);

  // 9600 baud, 8 data bits, 1 stop bit, parity off.
  outb(COM1+3, 0x80);    // Unlock divisor
  outb(COM1+0, 115200/9600);
  outb(COM1+1, 0);
  outb(COM1+3, 0x03);    // Lock divisor, 8 data bits.
  outb(COM1+4, 0);
  outb(COM1+1, 0x01);    // Enable receive interrupts.

  // If status is 0xFF, no serial port.
  if(inb(COM1+5) == 0xFF) return;
  uart = 1;

  // Acknowledge pre-existing interrupt conditions;
  // enable interrupts.
  inb(COM1+2);
  inb(COM1+0);
  ioapicenable(IRQ_COM1, 0);

  // Announce that we're here.
  for(p="xv6...\n"; *p; p++) uartputc(*p);
}
```

### UARTとは

そもそもUARTとは何かですが、`**Universal Asynchronous Receiver/Transmitter**（汎用非同期送受信機）`を指すようです。

UARTは、2つのデバイス間でシリアルデータを交換するためのプロトコルを指します。

参考：[UARTの概要 | Rohde & Schwarz](https://www.rohde-schwarz.com/jp/products/test-and-measurement/oscilloscopes/educational-content/understanding-uart_254524.html)

参考：[Universal asynchronous receiver-transmitter - Wikipedia](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver-transmitter)

近年では主として使われていないようですが、UARTはシリアルポートによる通信で使用されていたプロトコルみたいです。

`uartinit`関数では、いわゆるCOMポートをセットアップしているようですね。

### 通信にシリアルポートを使用する

OSが通信にシリアルポートを使用する場合は、初めにシリアルポートを初期化する必要があります。

参考：[Serial Ports - OSDev Wiki](https://wiki.osdev.org/Serial_Ports)

ソースコードを順に見ていきます。

``` c
#define COM1    0x3f8

// Turn off the FIFO
outb(COM1+2, 0);
```

`COM1`は`0x3f8`として定義されています。

これは、固定されたCOM1ポートのIOポートのアドレスです。

各COMポートのレジスタについては、IOポートアドレスからのオフセットでアクセスできます。

`COM1+2`は` Interrupt Identification`と`FIFO control registers`を指します。

ここでは、0をセットすることでUART内のFIFOの動作を無効化しています。

FIFOが無効化されている場合、受信したデータは`Receiver buffer register`に受け渡されます。

続いて、以下のコードを見てみます。

``` c
// 9600 baud, 8 data bits, 1 stop bit, parity off.
outb(COM1+3, 0x80);    // Unlock divisor
outb(COM1+0, 115200/9600);
outb(COM1+1, 0);
outb(COM1+3, 0x03);    // Lock divisor, 8 data bits.
outb(COM1+4, 0);
outb(COM1+1, 0x01);    // Enable receive interrupts.
```

`COM1+3`は`Line control register`に該当します。

これは、セットされたbitに応じて通信パラメータを変更します。

![https://yukituna.com/wp-content/uploads/2022/02/image-54.png](https://yukituna.com/wp-content/uploads/2022/02/image-54.png)

参考画像：[Serial UART, an in depth tutorial - Lammert Bies](https://www.lammertbies.nl/comm/info/serial-uart)

`outb(COM1+3, 0x80);`は8bit目をセットして`DLAB`を有効化しています。

これによって、次の`COM1+0`と`COM1+1`への書き込みアクセスが`Divisor latch registers (R/W)`に変化します。

ここに`115200/9600`と0をそれぞれ書き込むことでUARTのタイムベースを9,600bpsに設定していることになります。

続く`outb(COM1+3, 0x03);`では、LRCの`DLAB`を解除するとともに`8 data bits`をセットしています。

その後、`Modem control register`に0をセットした後、割込みを有効化してます。

一通りの初期化処理を行った後、`Line status register`のチェックを行ってシリアルポートが利用可能であることを確認しています。

``` c
// If status is 0xFF, no serial port.
if(inb(COM1+5) == 0xFF) return;
uart = 1;
```

最後に、RBRとIIRの情報を参照して現在の割込み状態を確認した後、割込みを有効化して終了です。

``` c
// Acknowledge pre-existing interrupt conditions;
// enable interrupts.
inb(COM1+2);
inb(COM1+0);
ioapicenable(IRQ_COM1, 0);
```

## まとめ

今回はシリアルポートの初期化処理を追いかけてました。

次回は`pinit`関数です。

## 参考書籍

- [30日でできる! OS自作入門](https://amzn.to/3qZSCY7)
- [ゼロからのOS自作入門](https://amzn.to/3qXYsZX)
- [はじめてのOSコードリーディング ~UNIX V6で学ぶカーネルのしくみ](https://amzn.to/3q8TU3K)
- [詳解 Linuxカーネル](https://amzn.to/3I6fkVt)
- [作って理解するOS x86系コンピュータを動かす理論と実装](https://amzn.to/3JRUdI2)