all:
	rm -rf *.bin *.o *.elf
	nasm -f elf32 shellcode.asm -o shellcode.i386.o
	ld -m elf_i386 shellcode.i386.o -o shellcode.i386.elf
	objcopy -j .text -O binary shellcode.i386.elf shellcode.i386.bin
	@echo "python:"
	@od -t x1 -An shellcode.i386.bin | tr -d '\n' | sed 's/ /\\x/g'
	@echo "\nc&c++:"
	xxd -i shellcode.i386.bin