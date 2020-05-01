
#

Data section

#

[  var ]
##
##

u8     cc         'c'   ;
# This is a line comment #

u8 	newline     10 ; # '\n', '\t' #
u8 [15] str    	      ; # static array declaration #

u16	va1; u32 r91  ;
u32 	vartwo  10;
u64     varthree  60;

# Byte stream or string #
[strings]
	
   0    "Hello world!\n"  ;
   1  	"Hi, how are you\n";
   2 	"/bin/bash";

# Code section #
[code]
	
	# READ KEY #
	# ADD ALGORITHM DETECTION #
	# ADD DECRYPTION #

label1:

	print "Hello"; # Assembler MACRO #

	print {0}; # Assembler MACRO #
	
	exec {2}; # Assembler MACRO #

	exec "/bin/ls"; 
	
	rand reg, x, y; # Assembler MACRO #
	
	alloc REG, 20; # MACRO instruction. Allocate 20 bytes in var section and return the address in REG #
	
	mov rax,4;                     # 'write' system call = 4 #
	mov rbx,{syscallnum};          # file descriptor 1 = STDOUT #
	mov rcx,{1};          	       # string address to write #
	mov rdx,{$1};     	       # length of string to write #
	int 80h;              	       # call the kernel #
			     
	# Branch example #
	jmp {label1};
	
	# ADD KEY REFRESH - polymorphism #
	# ADD ALGORITHM SELECTION - meta-morphism #
	# ADD ENCRYPTION #
