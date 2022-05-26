---
title: WSL上にRust環境を作るメモ
date: "2021-08-07"
template: "post"
draft: false
slug: "rust-setup-on-wsl"
category: "Note"
tags:
  - "Rust"
  - "WSL"
  - "備忘録"
description: "Rustで競プロを楽しむための環境を作っていきます"
socialImage: "/media/cards/no-image.png"
---

<!-- omit in toc -->
## もくじ
- [環境](#環境)
- [Rust環境の構築](#rust環境の構築)
  - [Rustのインストール](#rustのインストール)
  - [Hello, World](#hello-world)
- [まとめ](#まとめ)

## 環境
今回は、以下の構成でRustで競プロを楽しむための環境を作っていきます。

- WIndows10
- WSL Ubuntu20.04

## Rust環境の構築

### Rustのインストール

[公式ドキュメント](https://www.rust-lang.org/ja/tools/install)を参照すると、WSLのユーザは以下のコマンドでRustが簡単にインストールできるようです。

``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

インストール中に次のように聞かれますが、「Proceed with installatio」を選択しました。

``` bash
1) Proceed with installation (default)
2) Customize installation
3) Cancel installation
```

インストールが完了したら、すべてのツールが`~/.cargo/bin`に配置されているので、このディレクトリをPATHに追加します。

``` bash
export PATH=$PATH:$HOME/.cargo/bin
echo 'export PATH=$PATH:$HOME/.cargo/bin' >> ~/.bashrc
```

PATHが追加できたら、次のコマンドでツールチェーンがインストールされたことを確認します。

``` bash
rustup --version
rustc --version
cargo --version
```

### Hello, World

とりあえずHello, Worldプロジェクトを作成してみます。

``` bash
cargo new hello_world
```

ここで、以下のようなプロジェクトディレクトリが作成されます。

``` bash
$ tree hello_world/
hello_world/
├── Cargo.toml
└── src
    └── main.rs

1 directory, 2 files
```

次に、main.rsをコンパイルします。

``` bash
cd hello_world
cargo run #または cargo build
```

すると、targetディレクトリが作成され、次のような構成になりました。

``` bash
$ tree hello_world/
hello_world/
├── Cargo.lock
├── Cargo.toml
├── src
│   └── main.rs
└── target
    ├── CACHEDIR.TAG
    └── debug
        ├── build
        ├── deps
        │   ├── hello_world-dcff91f54b10472a
        │   └── hello_world-dcff91f54b10472a.d
        ├── examples
        ├── hello_world
        ├── hello_world.d
        └── incremental
            └── hello_world-2x2zxxntihjma
                ├── s-g16k84pkgw-1kx1yoj-1r8cowopde7m7
                │   ├── 18w4g3z43hvkcb89.o
                │   ├── 2195c5i0j9yy401g.o
                │   ├── 2d4qpr6fn1o2oy47.o
                │   ├── 3n8l6lb07r0z64tp.o
                │   ├── 4ltafe1k1v50rxij.o
                │   ├── dep-graph.bin
                │   ├── g7uy5q5v1tqa9ua.o
                │   ├── osa6u353jylok1z.o
                │   ├── query-cache.bin
                │   ├── work-products.bin
                │   └── wzcdn60lipjlwrg.o
                └── s-g16k84pkgw-1kx1yoj.lock

9 directories, 20 files
```

この`debug`ディレクトリ直下の`hello_world`というのが、コンパイルされたELFファイル本体です。

## まとめ

ほんとはここからVSCodeでRustのデバッグができるように設定をしていきたかったのですが、
残念ながらまだRustのデバッグを行える拡張機能はVSCodeには見当たりませんでした。

またアップデートがあれば追記しようと思います。