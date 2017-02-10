OPT=-v -static -Os 
all: clean x64 i386

x64:
	#It is unable to use gcc -S, since execve will not be linked yet.
	#gcc -S -masm=intel execve.c -o execve.x64.asm
	gcc $(OPT) -m64 execve.c -o execve.x64.bin
	objdump -M intel -d execve.x64.bin > execve.x64.asm
i386:
	gcc $(OPT) -m32 execve.c -o execve.i386.bin
	objdump -M intel -d execve.i386.bin > execve.i386.asm
clean:
	rm -rf *.bin *.asm

.PHONY: clean x64 i386