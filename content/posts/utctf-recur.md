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

The challenge had a binary file attached with it and the description of the challenge was

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

For the reversing challenges, I use [Ghidra](https://ghidra-sre.org/) which is a well known reverse engineering tool and is used for generating C source code from an executable. The decompiled binary had the `main` function and a function called `recurrence`. Here are the source codes of the two functions

```cpp
int main(void) {
  byte bVar1;
  byte bVar2;
  int local_1c;
  
  local_1c = 0;
  while (local_1c < 0x1c) {
    bVar1 = flag[local_1c];
    bVar2 = recurrence();
    putchar((int)(char)(bVar2 ^ bVar1));
    fflush(stdout);
    local_1c = local_1c + 1;
  }
  return 0;
}
```

```cpp
ulong recurrence(int param_1) {
  int iVar1;
  int iVar2;
  ulong uVar3;
  
  if (param_1 == 0) {
    uVar3 = 3;
  }
  else {
    if (param_1 == 1) {
      uVar3 = 5;
    }
    else {
      iVar1 = recurrence((ulong)(param_1 - 1));
      iVar2 = recurrence((ulong)(param_1 - 2));
      uVar3 = (ulong)(uint)(iVar2 * 3 + iVar1 * 2);
    }
  }
  return uVar3;
}
```

The code is pretty readable and instead of going through it line by line, here are some things which we learn from the code.

* The `recurrence` function defines a recurrence relation that can be described as

  ```math
  f(x) = \begin{cases}
    3 &\text{if } x = 0 \\
    5 &\text{if } x = 1 \\
    2 * f(x-1) + 3 * f(x-2) &\text{else}
  \end{cases}
  ```

  This is similar to the Fibonacci sequence.

* The `main` function reads `28` bytes as `flag` and a new character is evaluated using the `flag` byte and the output of the `recurrence` method.

* The new character is calculated using the `XOR` operation.

Since, the output of the `recurrence` function is used in calculating the output character, we need the input to the `recurrence` function. The decompiled code does not show what is provided as input to the function. Also, the `28` bytes needed for flag need to be located. For both these problems, I used `gdb` to go through the assembly of the binary.
