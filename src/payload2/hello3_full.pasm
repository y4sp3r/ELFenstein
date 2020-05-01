# Data section #
[  var 100  ]
u32 syscallnum 1;

# Byte stream or string #
[strings]
	
   0    "Hello world!\n"  ;
   1  	"Hi, how are you\n";
   2 	"/bin/bash";

# Request encryption from the assembler #
[key metamorph]
"Key1"

# Code section #
[code]
	
	# READ KEY #
	# ADD ALGORITHM DETECTION #
	# ADD DECRYPTION #

label1:

	# ASSEMBLER MACRO #
	print "Hello";

	mov rax,4;                     # 'write' system call = 4 #
	mov rbx,{syscallnum};          # file descriptor 1 = STDOUT #
	mov rcx,{1};          	       # string address to write #
	mov rdx,{$1};     	       # length of string to write #
	int 80h;              	       # call the kernel #
		     
	# Branch example #
	jmp label1;
	
	# ADD KEY REFRESH - polymorphism #
	# ADD ALGORITHM SELECTION - meta-morphism #
	# ADD ENCRYPTION #
