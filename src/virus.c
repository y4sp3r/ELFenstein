//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ptrace.h>

//Default loader address
#define DEFAULT_EP ((unsigned char *)0x0000000000400000)

//Encryption key
char key[] = "ThisIsNotASecKey";
  
//Descryption function
void _x_(char *p, unsigned len)
{  
  for (unsigned i = 0; i < len; i++)
    p[i] ^= key[i & 15]; //i % 16
}

//
char _r_0xFF_()
{
  return (rand() & 255);
}

//
int _t_()
{
  return (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0);
}

//Decryption routine
int _u_()
{
  //Read the memory address of the section
  int   p   = *((int   *)(DEFAULT_EP + 0x09));
  
  //Read the length of the section (size in bytes)
  int   len = *((short *)(DEFAULT_EP + 0x0d));

  //Check if the section is encrypted
  if (p && len)
    {
      //Get section's page address
      unsigned char *ptr       = DEFAULT_EP + p;
      unsigned char *ptr1      = DEFAULT_EP + p + len;
      size_t         pagesize  = sysconf(_SC_PAGESIZE);
      uintptr_t      pagestart = (uintptr_t)ptr & -pagesize;
      int            psize     = (ptr1 - (unsigned char*)pagestart);
      
      //Make the section's page writable
      if (mprotect((void*)pagestart, psize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
	perror("mprotect:");
      
      //Decrypt the section
      _x_(DEFAULT_EP + p, len);

      //Restore the section's page state
      if (mprotect((void*)pagestart, psize, PROT_READ | PROT_EXEC) < 0)
	perror("mprotect:");

      //
      return 1;
    }
  else
    {
      //
      return 0;
    }
}

//Key refresh & encryption routine
int _e_()
{
  //Read the memory address of the section
  int   p   = *((int   *)(DEFAULT_EP + 0x09));
  
  //Read the length of the section (size in bytes)
  int   len = *((short *)(DEFAULT_EP + 0x0d));

  //Check if the section is encrypted
  if (p && len)
    {
      //Get section's page address
      unsigned char *ptr       = DEFAULT_EP + p;
      unsigned char *ptr1      = DEFAULT_EP + p + len;
      size_t         pagesize  = sysconf(_SC_PAGESIZE);
      uintptr_t      pagestart = (uintptr_t)ptr & -pagesize;
      int            psize     = (ptr1 - (unsigned char*)pagestart);
      
      //Make the section's page writable
      if (mprotect((void*)pagestart, psize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
	perror("mprotect:");

      //Key refresh
      for (int i = 0; i < 16; i++)
	key[i] = _r_0xFF_();

      //Key storage
      
      //Decrypt the section
      _x_(DEFAULT_EP + p, len);

      //Restore the section's page state
      if (mprotect((void*)pagestart, psize, PROT_READ | PROT_EXEC) < 0)
	perror("mprotect:");
      
      //
      return 1;
    }
  else
    {
      //
      return 0;
    }
}

//
void _g_()
{
  //
  char *p = malloc(sizeof(char) * 33);

  long long int i = 100000000000;

  //
  while (i--)
    {
      //FUQ U!
      for (int i = 0; i < 32; i++)
	p[i] = "FUQ U!"[i % 6];
    }
  
  //
  free(p);
}

//Section main fucntion - This is the Virus!
__attribute__((section(".v_s"))) int _e_m_(int argc, char *argv[])
{  
  //
  printf("Enter the secret key: ");
  getchar();
  
  return 0;
}

//
int main (int argc, char *argv[])
{
  //
  srand(getpid());
  
  //If being traced ==> throw garbage code
  if (_t_())
    _g_();
  else
    {
      //If encrypted ==> decrypt and call secret function
      if (_u_())
	{
	  //The secret function
	  _e_m_(argc, argv);

	  //Refresh key & encrypt before exit (polymorphism)
	  //_e_();
	}
    }
  
  return 0;
}
