;; 
BITS 64

;; Define variables in the data section
SECTION .DATA

	;; Payload data
	hello:     db 'Hello world!',10
	helloLen:  equ $-hello
	
;; Code goes in the text section
SECTION .TEXT

GLOBAL _start 

_start:
	;; Payload code
	mov rax,4            ; 'write' system call = 4
	mov rbx,1            ; file descriptor 1 = STDOUT
	mov rcx,hello        ; string to write
	mov rdx,helloLen     ; length of string to write
	int 80h              ; call the kernel
	
	;; 
	mov rax, 60
	mov rbx, 1
	int 80h
