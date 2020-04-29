//
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>

//
#include <capstone/capstone.h>

//
Elf64_Ehdr *read_elf_header(const char *fname)
{
  FILE *fp = fopen(fname, "rb");

  //
  if (fp)
    {
      Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));

      //
      if (header)
	{
	  //Read header
	  fread(header, 1, sizeof(Elf64_Ehdr), fp);

	  //Check magic number (is it an ELF?)
	  if (memcmp(header->e_ident, ELFMAG, SELFMAG))
	    header = NULL;

	  //
	  fclose(fp);
	  
	  //
	  return header;
	}
      else
	return NULL;
    }
  else
    return NULL;
}

//
typedef struct bin_code_s { unsigned long long size; char *code; } bin_code_t;

//
bin_code_t *read_entry_point(char *fname, unsigned long long ep_addr)
{
  FILE *fp = fopen(fname, "rb");

  //
  if (fp)
    {
      //
      struct stat sb;

      stat(fname, &sb);

      //
      unsigned long long size = (sb.st_size - ep_addr);

      //
      bin_code_t *bc = malloc(sizeof(bin_code_t));

      bc->size = size;
      bc->code = malloc(sizeof(char) * size);
      
      fseek(fp, ep_addr, SEEK_SET);

      fread(bc->code, sizeof(char), size, fp);
      
      return bc;
    }
  else
    return NULL;
}

//
int main(int argc, char **argv)
{
  //
  if (argc < 2)
    return printf("Usage: %s [binary file]\n", argv[0]), 2;

  //
  csh handle;
  cs_insn *insn;
  size_t count;

  //
  Elf64_Ehdr *header = read_elf_header(argv[1]);

  //
  if (!header)
    return printf("Error\n"), 3;

  bin_code_t *bc = read_entry_point(argv[1], header->e_entry);
  
  //Target is x86_64 
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;

  //
  count = cs_disasm(handle, bc->code, bc->size - 1, 0x1000, 0, &insn);

  if (count > 0)
    {
      size_t j;

      for (j = 0; j < count; j++)
	{
	  printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
		 insn[j].op_str);
	}
      
      cs_free(insn, count);
    }
  else
    printf("ERROR: Failed to disassemble given code!\n");
  
  cs_close(&handle);
  
  return 0;
}
