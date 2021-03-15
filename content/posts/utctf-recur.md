---
title: "UTCTF recur challenge"
date: 2021-03-15T22:00:35+05:30
draft: false
toc: false
images:
tags:
  - ctf
  - rev
---

Over the weekend, I participated in the [UTCTF 2021](https://utctf.live/) but was unable to spend a lot of time on the challenges. One of the challenge I worked on was the **recur** challenge in the Reverse Engineering category. The challenge was not that hard but I had fun working on it so I decided to write a writeup for the challenge.

The challenge had a binary file attached with it and the description of the challenge was -

> I found this binary that is supposed to print flags. It doesn't seem to work properly though...

I usually run the `file` command on the challenge binaries just to know if they are stripped or not. A stripped binary has no debugging symbols which makes it harder to debug and reverse. [Here](https://medium.com/@tr0id/working-with-stripped-binaries-in-gdb-cacacd7d5a33) is an article that compare the two and explains how to deal with a stripped binary.

Back to the challenge, here is the output of the `file` command on our binary -

```bash
$ file ./recur
recur: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ffe1273695471373b182d4f5f266181d893ba3d8, for GNU/Linux 4.4.0, not stripped
```

Not stripped which means it would be easy to debug. I also execute the binary just to get an idea of the output. Like the description said, the binary prints the flag but is stuck after `{`

```bash
$ ./recur
utflag{
```

To be continued
