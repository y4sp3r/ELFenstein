//
#include <stdio.h>
#include <unistd.h> 
#include <sys/stat.h>
#include <sys/types.h>
#include <keystone/keystone.h>

//
#define MAX_BUFFER 4096

//
typedef struct code_file_s {

  //
  unsigned long long code_file_size;

  //
  char *code_file_code;
  
} code_file_t;

//
code_file_t *load_code_file(char *fname)
{
  //
  if (fname)
    {
      //
      FILE *fp = fopen(fname, "rb");

      //
      if (fp)
	{
	  //
	  unsigned size;
	  struct stat sb;

	  stat(fname, &sb);

	  size = sb.st_size;
	  
	  //
	  code_file_t *c = malloc(sizeof(code_file_t));

	  //
	  if (c)
	    {
	      c->code_file_size = size;
	      c->code_file_code = malloc(sizeof(char) * size + 1);

	      //
	      if (c->code_file_code)
		{
		  fread(c->code_file_code, sizeof(char), size, fp);
		  
		  fclose(fp);

		  return c;
		}
	      else
		return NULL;
	    }
	  else
	    return NULL;
	}
      else
	return NULL;
    }
  else
    return NULL;
}

//
void release_code_file(code_file_t **c)
{
  if (*c)
    {
      if ((*c)->code_file_code)
	free((*c)->code_file_code);

      free(*c);
    }
}

//
void print_code_file(code_file_t *c)
{
  printf("Size: %u\n", c->code_file_size);
  
  //
  for (unsigned i = 0; i < c->code_file_size; i++)
    putchar(c->code_file_code[i]);
}

//
int main(int argc, char **argv)
{
  //
  if (argc < 2)
    return printf("Usage: %s [input assembly file]\n", argv[0]), 2;

  //
  ks_err err;
  size_t count;
  ks_engine *ks = NULL;
  
  //
  code_file_t *c = load_code_file(argv[1]);
  
  //
  size_t size;
  unsigned char *encode = NULL;

  //
  err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
  
  //
  if (err != KS_ERR_OK)
    {
      printf("ERROR: failed on ks_open(), quit\n");
      
      return -1;
    }

  //
  if (ks_asm(ks, c->code_file_code, 0, &encode, &size, &count) != KS_ERR_OK)
    {
      printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
	     count, ks_errno(ks));
    }
  else
    {
      print_code_file(c);
      
      for (size_t i = 0; i < size; i++)
	printf("%02x ", encode[i]);
      
      printf("\n");
      
      printf("Compiled: %lu bytes, statements: %lu\n", size, count);
    }
  
  // NOTE: free encode after usage to avoid leaking memory
  ks_free(encode);
  
  // close Keystone instance when done
  ks_close(ks);

  //
  release_code_file(&c);
  
  return 0;
}
