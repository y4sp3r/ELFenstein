; nasm -f bin -o tiny64 tiny64.asm
BITS 64

org 0x400000
	
ehdr:   	        ; Elf64_Ehdr

	;; Magic number 0x7F454C46020101000000000000000000

	;; 0x7F454C4602010100
	db 0x7f,	 "ELF", 2, 1, 1, 0 ; e_ident
	
	;; 0x0000000000000000
	times 8 db 0	

	dw  2         	; e_type     - 2 		--> executable file
	dw  0x3e      	; e_machine  - 0x3e = 62 	--> x86_64
	dd  1         	; e_version 
	dq  _start    	; e_entry    - entry point	--> _start
	dq  phdr - $$ 	; e_phoff    - phdr offset 
	dq  0         	; e_shoff    - no section header
	dd  0         	; e_flags    - no special CPU flags
	dw  ehdr_size  	; e_ehsize
	dw  phdr_size  	; e_phentsize
	dw  1         	; e_phnum     - only one program header entry
	dw  0         	; e_shentsize - empty
	dw  0         	; e_shnum     - empty
	dw  0         	; e_shstrndx  - empty
	
	ehdr_size  equ  $ - ehdr ; calculate the size of ehdr ==> size = current address - ehdr address
	 
phdr:           ; Elf64_Phdr
	
	dd  1         	; p_type	- 1 	--> loadable program segment
	dd  1         	; p_flags	- 1	--> executable segment 
	dq  0         	; p_offset	- no offset
	dq  $$        	; p_vaddr	- address
	dq  $$        	; p_paddr	- address
	dq  file_size  	; p_filesz 	
	dq  file_size  	; p_memsz
	dq  0x1000    	; p_align	- 4K alignment
	
	phdr_size  equ  $ - phdr ; calculate the size of phdr
	 
_start:

	;; syscall(SYS_write, 1, "Hello, World!\n", 14);
	mov rdx, hello_size
	mov rsi, hello
	mov rdi, 1
	mov rax, 1
	syscall
	
	;; syscal(SYS_exit, 0);
	mov rax, 60 ; exit syscall
	mov rdi,  0 ; exit status 0
	syscall

hello:	db "Hello, World!", 10	; 10 --> \n
	
	hello_size equ $ - hello ; size of the hello string (14 bytes)
	
	file_size  equ  $ - $$ 	; calculate the whole program size in bytes
