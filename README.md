HotS unpack [![Build Status](https://travis-ci.org/athre0z/hots-unpack.svg)](https://travis-ci.org/athre0z/hots-unpack)
===========
HotS unpack is a static unpacker for HotS game binaries. It takes an encrypted binary as input and creates a decrypted one as output. The output binaries are *not* runnable, but intended only for analysis purposes. Adjusting the entry point would probably make binaries runnable, however this is currently not a goal of this tool. Currently, only the x86 version of HotS is supported.

## Usage
```
hots_unpack path\to\input\binary.exe [path\to\output\binary.exe]
```
The decrypted file is written into the current working directory.

## Binary distribution
[The latest precompiled version can be downloaded here (Windows binaries only).](https://github.com/athre0z/hots-unpack/releases/latest)

## HotS version support
The tool was successfully tested with revisions 34190 - 37274.

## Compilation
Just like most programs written in the Rust language, this tool can be compiled with a simple cargo invocation:
```
cargo build --release
```
