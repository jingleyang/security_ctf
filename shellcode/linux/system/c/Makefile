OPT=-v -static -Os 
SRC=system.c
OUT=system
all: clean x64 i386

x64:
	#It is unable to use gcc -S, since execve will not be linked yet.
	#gcc -S -masm=intel execve.c -o execve.x64.asm
	gcc $(OPT) -m64 $(SRC) -o $(OUT).x64.bin
	objdump -M intel -d $(OUT).x64.bin > $(OUT).x64.asm
i386:
	gcc $(OPT) -m32 $(SRC) -o $(OUT).i386.bin
	objdump -M intel -d $(OUT).i386.bin > $(OUT).i386.asm
clean:
	rm -rf *.bin *.asm

.PHONY: clean x64 i386