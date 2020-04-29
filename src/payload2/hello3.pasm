# Data section #
[var 100]
u32 syscall;

[strings]
# Byte stream or string #
str 0	"Hello world!\n";
str 1	"Hi, how are you\n";
str 2   "/bin/bash"

# Request encryption from the assembler #
[key: polymorph]
key 0 "Key1"

# Code section #
[code]
	# ADD ALGORITHM DETECTION #
	# ADD DECRYPTION #
	
	mov rax,4;                     # 'write' system call = 4 #
	mov rbx,1;            	       # file descriptor 1 = STDOUT #
	mov rcx,{1};          	       # string address to write #
	mov rdx,{$1};     	       # length of string to write #
	int 80h;              	       # call the kernel #

	
	# ADD KEY REFRESH - polymorphism #
	# ADD ALGORITHM SELECTION - meta-morphism#	
	# ADD ENCRYPTION #
