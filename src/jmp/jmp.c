//
void jmp()
{
  __asm__ volatile (

		    "mov 0xAABB00CCDD11EEFF, %%rax;\n"
		    "jmp *%%rax;\n"
		    :
		    :
		    :
		    "rax"
		    );
}
