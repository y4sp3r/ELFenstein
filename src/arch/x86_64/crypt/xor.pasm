# This is the XOR encryption/decryption routine #

        # Length of data to process #
        mov rdx, {$data};

	# Initialize loop bytes counter #
  	xor rcx, rcx;
1:
	mov r10, rcx;

	# Make sure to wrap around for the key #
	and r10, 15;
	
	# Load key & data #
	mov al, [{key}, r10];
	mov bl, [{data}, rcx];

	# Apply xor #
	xor al, bl;

	# Store xored data # 
	mov [{data}, rcx], al;

	# Loop control #
	inc rcx;
	cmp rcx, rdx;
	jl 1;

