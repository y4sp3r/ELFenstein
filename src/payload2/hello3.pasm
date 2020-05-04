   
#

Data section

#

[  var ]
##
##

u8 _       ;
u16 __;
u8 _a;
u8 _b 9;
u8 __a;
u8     cc         'c'   ;

# This is a line comment #

u8 	newline     10 ; # '\n', '\t' #
u8 [15] str    	       ; # static array declaration #

u16	va 1; # Hello #
u32 r 91  ;
u32 	vartwo  10;
u64     varthree  60;
u64 out_num 1;

# Byte stream or string #
[ string ] 
	
   0    "Hello world!\n"  ;
   # Hello :)# 1  	"Hi, how are you\n";
   2 	"/bin/bash";

#

1 - If the crypt section is not specified, the automatic handling of encryption is
deactivated.

2 - If the crypt section is specified, here are the possible use cases:

Case 0: [crypt static]
-------

This statement signals to the assembler to use the same encryption routine
and key (of length 16) for every execution (static).
The key is randomly generated before injection.

General execution pattern:

Load key --> Decrypt --> Execute --> Encrypt

Case 1: [crypt polymorph]
-------

This statement allows for a polymorphic binary by refreshing/regenerating
an random encryption key after each execution.

General execution pattern:

Load current key (currK) -> Decrypt (currK) --> Execute --> Refresh key (newK) --> Encrypt (newK) --> Store new key (newK)

Case 2: [crypt meta (xor, rot, rol) ]
-------

This statement adds metamorphism to the binary by injecting an encryption/decryption routine
selector that picks, at each execution and randomly, an encryption routine amongst a predfeined set.

For the case example above, the selector will read the ID of the decryption routine (xor, rot, and encrypt0) from the key
section header before decrypting the target data/code.

After the payload is executed, the selector will randomly choose a routine from the same set, and generate a new encryption/decryptio
key to encrypt the target data/code. When the encryption is finished, the key is automatically stored in the key section. 

Load decryption routine address --> Load current key (currK) -> Decrypt (currK) --> Execute --> Refresh key (newK) --> Pick a new algorithm --> Encrypt (newK) --> Store new key (newK) & 

#

[ crypt polymorphic ]


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
	
	# alloc REG, 20; MACRO instruction. Allocate 20 bytes in var section and return the address in REG #
	
	# Write after read ==> Const prop #
	add {out_num}, 1;
	mov rbx, {out_num};	   
		
	add rbx, 1;
	
	# Read after write #
	mov rbx, {out_num};
	add {out_num}, 1;
	mov rbx, {out_num};
	
	mov rax,4;                     # 'write' system call = 4 #
	mov rbx, {out_num};	       # file descriptor 1 = STDOUT #
	mov rcx, {1};          	       # string address to write #
	mov rdx, {$1};     	       # length of string to write #
	int 80h;              	       # call the kernel #
		     
	# Branch example #
	jmp {label1};
	
	# ADD KEY REFRESH - polymorphism #
	# ADD ALGORITHM SELECTION - meta-morphism #
	# ADD ENCRYPTION #
