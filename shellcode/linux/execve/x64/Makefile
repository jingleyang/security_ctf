all:
	rm -rf *.bin *.o *.elf
	nasm -f elf64 shellcode.asm -o shellcode.x64.o
	ld -m elf_x86_64 shellcode.x64.o -o shellcode.x64.elf
	objcopy -j .text -O binary shellcode.x64.elf shellcode.x64.bin
	@echo "python:"
	@od -t x1 -An shellcode.x64.bin | tr -d '\n' | sed 's/ /\\x/g'
	@echo "\nc&c++:"
	xxd -i shellcode.x64.bin