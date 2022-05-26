---
title: ゼロからのOS自作入門をやってみた時のメモ：環境構築 ~ 2章まで
date: "2021-09-25"
template: "post"
draft: false
slug: "diyos-mikanos-01"
category: "自作OS"
tags:
  - "自作OS"
  - "みかん本"
  - "OS"
description: "発売と同時に即購入して以降、時間が取れなかったり難しくて挫折しちゃったりで放置してたゼロからのOS自作入門に再トライしていきたいと思います。今回は環境構築から2章まで進めていきます。"
socialImage: "/media/cards/no-image.png"
---

発売と同時に即購入して以降、時間が取れなかったり難しくて挫折しちゃったりで放置してた[ゼロからのOS自作入門](https://amzn.to/36JN8a5)に再トライしていきたいと思います。

基本的には写経メインで進めつつ、つまづいたところや理解が浅い点について調べたことを記事にまとめていく予定です。

今回は環境構築から2章まで進めていきます。
ちなみに1章はやるだけなので割愛してます。

<!-- omit in toc -->
## もくじ
- [環境構築](#環境構築)
- [EDKⅡでUEFIアプリケーションを作る](#edkⅱでuefiアプリケーションを作る)
- [イメージのビルドについて](#イメージのビルドについて)
- [まとめ](#まとめ)


## 環境構築

開発環境は以下の構成で作成しました。

- Ubuntu20.04(Hype-V上にGUIで構築)
- Windows 10(ホストマシン)
- VSCode(ホストマシン)

Hyper-V上で構築したUbuntuにVSCodeからRemoteSSHで接続して開発を行い、Qemuでの動作確認のみ、UbuntuにGUIでログインして行う想定です。

※ 書籍の中で解説されている一部のQUEMのコマンドを実行するには、3Dアクセラレーションが有効になっている必要があります。
仮想デスクトップ環境で`(qemu) gtk initialization failed`が発生する場合は、3Dアクセラレーションが有効になっているか確認してください。

環境構築については、著者の方が公開しているこちらのGitHubリポジトリをベースにしてます。

参考：[Build and run scripts for MikanOS](https://github.com/uchan-nos/mikanos-build)

Ubuntuのバージョンが違うと記載の手順どおりに動作しないなど手間が増えるので、できれば仮想マシンかWSLでUbuntu20.04を用意するのがいいと思います。

VSCodeから仮想マシンのUbuntuにRemoteSSHで接続する方法については、以下にまとめています。

参考：[VSCodeでHyper-V上の仮想マシンのファイルを直接編集できるようにする方法 - かえるのほんだな](https://yukituna.com/3286/)

## EDKⅡでUEFIアプリケーションを作る

初っ端から全然知らない技術領域の話から始まりました。

参考：[GitHub - tianocore/edk2: EDK II](https://github.com/tianocore/edk2)

ここで作成している`.EFI`のファイルは、UEFIアプリケーションと呼ばれる、UEFI  BIOSから呼び出されるアプリケーションのようです。
EDKⅡは、UEFIアプリケーションを作るためのSDKのようなものである認識です。

``` c
struct MemoryMap {
  UINTN buffer_size;
  VOID* buffer;
  UINTN map_size;
  UINTN map_key;
  UINTN descriptor_size;
  UINT32 descriptor_version;
};

EFI_STATUS GetMemoryMap(struct MemoryMap* map) {
  if (map->buffer == NULL) {
    return EFI_BUFFER_TOO_SMALL;
  }

  map->map_size = map->buffer_size;
  return gBS->GetMemoryMap(
      &map->map_size,
      (EFI_MEMORY_DESCRIPTOR*)map->buffer,
      &map->map_key,
      &map->descriptor_size,
      &map->descriptor_version);
}
```

何をしているのかよくわからなかったので、とりあえずコードを追ってみました。
ここでは、MemoryMap構造体のmemmapに、GetMemoryMap()を使ってメモリマップを格納しています。

GetMemoryMap()は、gBS->GetMemoryMap()を用いて、関数呼び出し時点のメモリマップを取得します。

ここで、引数`(EFI_MEMORY_DESCRIPTOR*)map->buffer`で与えられている2つ目の引数には、関数が取得したメモリマップが格納されます。
格納されるデータは、EFI_MEMORY_DESCRIPTOR構造体として、`edk2/MdePkg/Include/Uefi/UefiSpec.h`に定義されています。

``` c
///
/// Memory descriptor version number.
///
#define EFI_MEMORY_DESCRIPTOR_VERSION 1

///
/// Definition of an EFI memory descriptor.
///
typedef struct {
  ///
  /// Type of the memory region.
  /// Type EFI_MEMORY_TYPE is defined in the
  /// AllocatePages() function description.
  ///
  UINT32                Type;
  ///
  /// Physical address of the first byte in the memory region. PhysicalStart must be
  /// aligned on a 4 KiB boundary, and must not be above 0xfffffffffffff000. Type
  /// EFI_PHYSICAL_ADDRESS is defined in the AllocatePages() function description
  ///
  EFI_PHYSICAL_ADDRESS  PhysicalStart;
  ///
  /// Virtual address of the first byte in the memory region.
  /// VirtualStart must be aligned on a 4 KiB boundary,
  /// and must not be above 0xfffffffffffff000.
  ///
  EFI_VIRTUAL_ADDRESS   VirtualStart;
  ///
  /// NumberOfPagesNumber of 4 KiB pages in the memory region.
  /// NumberOfPages must not be 0, and must not be any value
  /// that would represent a memory page with a start address,
  /// either physical or virtual, above 0xfffffffffffff000.
  ///
  UINT64                NumberOfPages;
  ///
  /// Attributes of the memory region that describe the bit mask of capabilities
  /// for that memory region, and not necessarily the current settings for that
  /// memory region.
  ///
  UINT64                Attribute;
} EFI_MEMORY_DESCRIPTOR;
```

最終的に、ここで取得したメモリマップは、SaveMemoryMap()によって、`memmmap`という名前のCSV形式のファイルとして保存されました。

ビルドしたイメージファイルが作成される`edk2/Build/OSLoaderX64/DEBUG_CLANG38/X64/OSLoaderPkg/Loader/DEBUG`直下で次のコマンドを実行し、イメージファイルの中身を確認します。

``` bash
mkdir -o mnt
sudo mount -o loop disk.img mnt
cat mnt/memmap

//終わったら
unmount mnt
```

とりあえずこのメモリマップの情報が確認できれば、2章までの内容は完了です。

``` bash
Index, Type, Type(name), PhysicalStart, NumberOfPages, Attribute
0, 3, EfiBootServicesCode, 00000000, 1, F
1, 7, EfiConventionalMemory, 00001000, 9F, F
2, 7, EfiConventionalMemory, 00100000, 700, F
3, A, EfiACPIMemoryNVS, 00800000, 8, F
4, 7, EfiConventionalMemory, 00808000, 8, F
5, A, EfiACPIMemoryNVS, 00810000, F0, F
6, 4, EfiBootServicesData, 00900000, B00, F
7, 7, EfiConventionalMemory, 01400000, 3AB36, F
8, 4, EfiBootServicesData, 3BF36000, 20, F
9, 7, EfiConventionalMemory, 3BF56000, 270C, F
10, 1, EfiLoaderCode, 3E662000, 2, F
11, 4, EfiBootServicesData, 3E664000, 219, F
12, 3, EfiBootServicesCode, 3E87D000, B7, F
13, A, EfiACPIMemoryNVS, 3E934000, 12, F
14, 0, EfiReservedMemoryType, 3E946000, 1C, F
15, 3, EfiBootServicesCode, 3E962000, 10A, F
16, 6, EfiRuntimeServicesData, 3EA6C000, 5, F
17, 5, EfiRuntimeServicesCode, 3EA71000, 5, F
18, 6, EfiRuntimeServicesData, 3EA76000, 5, F
19, 5, EfiRuntimeServicesCode, 3EA7B000, 5, F
20, 6, EfiRuntimeServicesData, 3EA80000, 5, F
21, 5, EfiRuntimeServicesCode, 3EA85000, 7, F
22, 6, EfiRuntimeServicesData, 3EA8C000, 8F, F
23, 4, EfiBootServicesData, 3EB1B000, 4DA, F
24, 7, EfiConventionalMemory, 3EFF5000, 4, F
25, 4, EfiBootServicesData, 3EFF9000, 6, F
26, 7, EfiConventionalMemory, 3EFFF000, 1, F
27, 4, EfiBootServicesData, 3F000000, A1B, F
28, 7, EfiConventionalMemory, 3FA1B000, 1, F
29, 3, EfiBootServicesCode, 3FA1C000, 17F, F
30, 5, EfiRuntimeServicesCode, 3FB9B000, 30, F
31, 6, EfiRuntimeServicesData, 3FBCB000, 24, F
32, 0, EfiReservedMemoryType, 3FBEF000, 4, F
33, 9, EfiACPIReclaimMemory, 3FBF3000, 8, F
34, A, EfiACPIMemoryNVS, 3FBFB000, 4, F
35, 4, EfiBootServicesData, 3FBFF000, 201, F
36, 7, EfiConventionalMemory, 3FE00000, 8D, F
37, 4, EfiBootServicesData, 3FE8D000, 20, F
38, 3, EfiBootServicesCode, 3FEAD000, 20, F
39, 4, EfiBootServicesData, 3FECD000, 9, F
40, 3, EfiBootServicesCode, 3FED6000, 1E, F
41, 6, EfiRuntimeServicesData, 3FEF4000, 84, F
42, A, EfiACPIMemoryNVS, 3FF78000, 88, F
43, 6, EfiRuntimeServicesData, FFC00000, 400, 1
```

## イメージのビルドについて

作成したEFIファイルをビルドしてQemuでエミュレートするまでの部分について、特に解説らしきものがなくよくわからなかったのでまとめてみます。

本書の中では、EFIファイルのビルドは`edk2`ディレクトリの直下で`build`コマンドを利用して行います。

ビルド対象の情報は、`edk2/Conf/target.txt`に書き込んでいます。

今回は、独自に作成するUEFIアプリケーションとして、OSLoaderPkgというフォルダをワークスペースとしています。

``` bash
#  PROPERTY              Type       Use         Description
#  ----------------      --------   --------    -----------------------------------------------------------
#  ACTIVE_PLATFORM       Filename   Recommended Specify the WORKSPACE relative Path and Filename
#                                               of the platform description file that will be used for the
#                                               build. This line is required if and only if the current
#                                               working directory does not contain one or more description
#                                               files.
ACTIVE_PLATFORM       = OSLoaderPkg/OSLoaderPkg.dsc
```

ここで、OSLoaderPkg.dscは次のように定義しています。

``` bash
#@range_begin(defines)
[Defines]
  PLATFORM_NAME                  = OSLoaderPkg
  PLATFORM_GUID                  = d3f11f4e-71e9-11e8-a7e1-33fd4f7d5a3e
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/OSLoader$(ARCH)
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
#@range_end(defines)

#@range_begin(library_classes)
[LibraryClasses]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
#@range_end(library_classes)

  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

#@range_begin(components)
[Components]
  OSLoaderPkg/Loader.inf
#@range_end(components)
```

この設定によって、EDKⅡによってビルドしたEFIファイルは、`OUTPUT_DIRECTORY = Build/OSLoader$(ARCH)`に配置されるため、`edk2/Build/OSLoaderX64/DEBUG_CLANG38/X64/OSLoaderPkg/Loader/DEBUG/`に保存されるというわけです。

次に、`osbook/devtools/run_qemu.sh`をLoader.efiのある`edk2/Build/OSLoaderX64/DEBUG_CLANG38/X64/OSLoaderPkg/Loader/DEBUG/`と同じディレクトリで実行することで、ビルドしたEFIファイルをQemuでエミュレートします。

`osbook/devtools/run_qemu.sh`の中身はこんな感じでした。実行時ディレクトリの情報を引数として、`make_image.sh`を呼び出しています。

``` bash
#!/bin/sh -ex

if [ $# -lt 1 ]
then
    echo "Usage: $0 <.efi file> [another file]"
    exit 1
fi

DEVENV_DIR=$(dirname "$0")
EFI_FILE=$1
ANOTHER_FILE=$2
DISK_IMG=./disk.img
MOUNT_POINT=./mnt

$DEVENV_DIR/make_image.sh $DISK_IMG $MOUNT_POINT $EFI_FILE $ANOTHER_FILE
$DEVENV_DIR/run_image.sh $DISK_IMG
```

`make_image.sh`の中身を見てみます。

``` bash
#!/bin/sh -ex

if [ $# -lt 3 ]
then
    echo "Usage: $0 <image name> <mount point> <.efi file> [another file]"
    exit 1
fi

DEVENV_DIR=$(dirname "$0")
DISK_IMG=$1
MOUNT_POINT=$2
EFI_FILE=$3
ANOTHER_FILE=$4

if [ ! -f $EFI_FILE ]
then
    echo "No such file: $EFI_FILE"
    exit 1
fi

rm -f $DISK_IMG
qemu-img create -f raw $DISK_IMG 200M
mkfs.fat -n 'JISAKU OS' -s 2 -f 2 -R 32 -F 32 $DISK_IMG

$DEVENV_DIR/mount_image.sh $DISK_IMG $MOUNT_POINT
sudo mkdir -p $MOUNT_POINT/EFI/BOOT
sudo cp $EFI_FILE $MOUNT_POINT/EFI/BOOT/BOOTX64.EFI
if [ "$ANOTHER_FILE" != "" ]
then
    sudo cp $ANOTHER_FILE $MOUNT_POINT/
fi
sleep 0.5
sudo umount $MOUNT_POINT
```

このスクリプトを見ると、すでにdisk.imgが存在する場合は削除した上で、`qemu-img create -f raw $DISK_IMG 200M`を用いて、rawデータ形式の200Mのイメージファイルを作成しています。

参考：[QEMU-img ](https://access.redhat.com/documentation/ja-jp/red_hat_enterprise_linux/6/html/virtualization_administration_guide/chap-virtualization_administration_guide-tips_and_tricks)

次に、`mkfs.fat`でMS-DOS filesystemにフォーマットし、mntディレクトリにマウントした上で、作成したEFIファイルを`EFI/BOOT/BOOTX64.EFI`としてコピーしています。

参考：[Ubuntu Manpage: mkfs.fat - create an MS-DOS filesystem under Linux](http://manpages.ubuntu.com/manpages/trusty/man8/mkfs.fat.8.html)

こうして作成したイメージファイルを利用し、`run_image.sh`からqemu-system-x86_64コマンドでエミュレートしているという流れでした。

``` bash
qemu-system-x86_64 \
    -m 1G \
    -drive if=pflash,format=raw,readonly,file=$DEVENV_DIR/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=$DEVENV_DIR/OVMF_VARS.fd \
    -drive if=ide,index=0,media=disk,format=raw,file=$DISK_IMG \
    -device nec-usb-xhci,id=xhci \
    -device usb-mouse -device usb-kbd \
    -monitor stdio \
    $QEMU_OPTS
```



## まとめ

自分の勉強用なので詳細な解説は割愛してます。

このまま最後まで進めていきたいと思います。

