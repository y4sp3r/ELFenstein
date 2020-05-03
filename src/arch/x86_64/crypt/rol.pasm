# This is the ROTL encryption/decryption routine #

        # Length of data to process #
        mov rdx, {$data};

	# Initialize loop bytes counter #
  	xor rax, rax;
1:
	mov r10, rax;

	# Make sure to wrap around for the key #
	and r10, 15;
	
	# Load key & data #
	mov cl, [{key}, r10];
	mov bl, [{data}, rax];
	
	# Apply left rotation #
	rol bl, cl;

	# Store xored data # 
	mov [{data}, rax], bl;

	# Loop control #
	inc rax;
	cmp rax, rdx;
	jl 1;

