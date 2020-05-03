//
#include <stdio.h>
#include <unistd.h> 
#include <sys/stat.h>
#include <sys/types.h>
#include <keystone/keystone.h>

//
#include "parse.h"

//
typedef struct code_file_s {
  
  //
  u64 code_file_size;
  
  //
  u8 *code_file_code;
  
} code_file_t;

//
code_file_t *load_code_file(u8 *fname)
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
	  u32 size;
	  struct stat sb;

	  stat(fname, &sb);

	  size = sb.st_size;
	  
	  //
	  code_file_t *c = malloc(sizeof(code_file_t));

	  //
	  if (c)
	    {
	      c->code_file_size = size;
	      c->code_file_code = malloc(sizeof(u8) * size + 1);

	      //
	      if (c->code_file_code)
		{
		  fread(c->code_file_code, sizeof(u8), size, fp);
		  
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
  for (u32 i = 0; i < c->code_file_size; i++)
    putchar(c->code_file_code[i]);
}

//
int main(int argc, u8 **argv)
{
  //
  if (argc < 2)
    return printf("Usage: %s [input assembly file]\n", argv[0]), 2;
  
  //
  ks_err err;
  size_t count;
  ks_engine *ks = NULL;
  
  //Load payload assembly (PASM)
  code_file_t *c = load_code_file(argv[1]);

  //
  u64 cursor_pos = 0;
  var_section_t *v = NULL;
  string_section_t *s = NULL;
  
  //
  cursor_pos = get_var_section(c->code_file_code, &v);
  
  //
  if (v)
    {
      printf("Pos: %llu\n", cursor_pos);

      for (u64 i = 0; i < v->var_section_nb_vars; i++)
	{
	  printf("%20s @(%20llu) t(%5u) n(%20llu);\n\tbytes:\t",
		 v->var_section_vars[i].var_name,
		 v->var_section_vars[i].var_address,
		 v->var_section_vars[i].var_type,
		 v->var_section_vars[i].var_nb_val_bytes);

	  //
	  for (u64 j = 0; j < v->var_section_vars[i].var_nb_val_bytes; j++)
	    printf("(0x%02x, %c) ",
		   (u8)v->var_section_vars[i].var_val[j],
		   (is_sep((u8)v->var_section_vars[i].var_val[j])) ? ' ' : (u8)v->var_section_vars[i].var_val[j]);

	  printf("\n\n");
	}
    }

  //
  cursor_pos += get_string_section(c->code_file_code + cursor_pos, &s);

  //
  if (s)
    {
      printf("Pos: %llu\n", cursor_pos);

      for (u64 i = 0; i < s->string_section_nb_strings; i++)
	{
	  printf("%llu @(%20llu) l(%20llu); %s\n",
		 i,
		 s->string_section_strings[i].string_address,
		 s->string_section_strings[i].string_val_len,
		 s->string_section_strings[i].string_val);
	}
      
      printf("\n");
    }

  printf("%c%c%c\n",
	 c->code_file_code[cursor_pos],
	 c->code_file_code[cursor_pos + 1],
	 c->code_file_code[cursor_pos + 2]);
  
  //
  free(v);
  
  
  /* // */
  /* size_t size; */
  /* u8 *encode = NULL; */

  /* // */
  /* err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks); */
  
  /* // */
  /* if (err != KS_ERR_OK) */
  /*   { */
  /*     printf("ERROR: failed on ks_open(), quit\n"); */
      
  /*     return -1; */
  /*   } */

  /* // */
  /* if (ks_asm(ks, c->code_file_code, 0, &encode, &size, &count) != KS_ERR_OK) */
  /*   { */
  /*     printf("ERROR: ks_asm() failed & count = %lu, error = %u\n", */
  /* 	     count, ks_errno(ks)); */
  /*   } */
  /* else */
  /*   { */
  /*     print_code_file(c); */
      
  /*     for (size_t i = 0; i < size; i++) */
  /* 	printf("%02x ", encode[i]); */
      
  /*     printf("\n"); */
      
  /*     printf("Compiled: %lu bytes, statements: %lu\n", size, count); */
  /*   } */
  
  /* // NOTE: free encode after usage to avoid leaking memory */
  /* ks_free(encode); */
  
  /* // close Keystone instance when done */
  /* ks_close(ks); */
  
  //
  release_code_file(&c);
  
  return 0;
}
