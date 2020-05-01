//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//
#include "parse.h"

//
u64 nb_lines = 0;

//Check if upper case alpha
u8 is_u_alpha(u8 c)
{ return (c >= 'A' && c <= 'Z'); }

//Check if lower case alpha
u8 is_l_alpha(u8 c)
{ return (c >= 'a' && c <= 'z'); }

//Check if alpha
u8 is_alpha(u8 c)
{ return is_u_alpha(c) || is_l_alpha(c); }

//
u8 is_digit(u8 c)
{ return (c >= '0' && c <= '9'); }

//'1' ==> 1
u8 to_digit(u8 c)
{ return c - '0'; }

//
u8 is_sep(u8 c)
{ return (c == ' ' || c == '\n' || c == '\t'); }

//
u32 skip(u8 *p)
{
  u32 i = 0;

  //
  while (p[i] && is_sep(p[i]))
    {
      nb_lines += !(p[i] ^ '\n'); //p[i] == '\n' ==> nb_lines++
      i++;
    }
  
  return i;
}

//
u32 get_string(u8 *p, u8 *str, u32 *len)
{
  u32 i = 0;
  
  //
  while (p[i] && is_alpha(p[i]))
    {
      str[i] = p[i];
      i++;
    }
  
  //
  str[i] = '\0';

  //
  if (len)
    *len = i;
  
  //
  return i;
}

//Skip comment
u32 skip_comment(u8 *p)
{
  u32 i = 0;

  while (p[i] && p[i] != '#')
    {
      nb_lines += !(p[i] ^ '\n'); 
      i++;
    }
  
  //
  return i;
}

//"1234" ==> 1234 - convert string to number
u32 get_number(u8 *p, u64 *v)
{
  //
  u64 vv =0;
  u32 i = 0;
  
  //
  while (p[i] && is_digit(p[i]))
    {
      vv *= 10;
      vv += to_digit(p[i]);
      
      i++;
    }

  //
  *v = vv;
  
  //
  return i;
}

//
u32 get_var_section_header(u8 *p, var_section_t *v)
{
  //Section info
  u32 sec_size = 0;
  u8 sec_name[MAX_STR];
  u32 sec_name_len = 0;
    
  //Skip separators
  u32 i = skip(p); 

  //Go over comments
  while (p[i] && p[i] != '[')
    {
      //
      if (p[i] == '#')
	{	
	  //
	  i++;
	  
	  //
	  i += skip_comment(p + i);
	
	  //
	  i++;

	  //
	  i += skip(p + i); 
	}
      else
	{
	  printf("Payload assembler: [ Error (%llu:%u): unexpected character '%c' ! ]\n", nb_lines, i, p[i]);
	  exit(1);
	}
    }
  
  //
  if (p[i] != '[')
    {
      printf("Payload assembler: [ Error (%llu:%u): '[' expected, '%c' found instead! ]\n", nb_lines, i, p[i]);
      exit(1);
    }

  //
  i++;
  
  //
  i += skip(p + i);
  
  //Get section name
  i += get_string(p + i, sec_name, &sec_name_len);
  
  //
  if (strncmp(sec_name, "var", 3))
    {
      printf("Payload assembler: [ Error (%llu:%u): 'var' section expected, '%s' found instead! ]\n", nb_lines, i, sec_name);
      exit(1);
    }
  
  //
  i += skip(p + i);
  
  //
  if (p[i] != ']')
    {
      printf("Payload assembler: [ Error (%llu:%u): ']' expected, '%c' found instead! ]\n", nb_lines, i, p[i]);
      exit(1);
    }
  
  //Set var table entry
  v->var_section_nb_vars = 0;
  
  v->var_section_bytecode = malloc(sizeof(u8) * MAX_VAR_SEC_BYTECODE_SIZE);

  v->var_section_bytecode_size = 0;

  //
  i++;
  
  //
  i += skip(p + i);

  //
  return i;
}

//
u32 get_var_section_var_type(u8 *p, u8 *var_type, u64 *var_nb_val_bytes)
{
  //
  u32 i = 0;

  //Check if type is known
  if (p[0] == 'u')
    {
      //Check u8
      if (p[1] == '8')
	{
	  //Skip 'u8'
	  i += 2;
	  
	  //
	  i += skip(p + i);
	  
	  //Handle the array case
	  if (p[i] == '[')
	    {
	      //
	      i++;

	      //
	      i += skip(p + i);

	      //
	      i += get_number(p + i, var_nb_val_bytes);

	      //
	      if (*(var_nb_val_bytes) >= MAX_NB_VAL_BYTES)
		{
		  printf("Payload assembler: [ Error (%llu:%u): array size '%llu' exceeds the maximum '%u' ! ]\n", nb_lines, i, *var_nb_val_bytes, MAX_NB_VAL_BYTES);
		  exit(1);
		}

	      //
	      i += skip(p + i);

	      //
	      if (p[i] != ']')
		{
		  printf("Payload assembler: [ Error (%llu:%u): ']' expected, '%c' found instead! ]\n", nb_lines, i, p[i]);
		  exit(1);
		}

	      //
	      i++;
	      
	      //
	      i += skip(p + i);

	      //
	      *var_type = TYPE_U8_A;
	    }
	  else
	    {
	      *var_type = TYPE_U8;
	      *var_nb_val_bytes = 1;
	    }
	}
      else
	{
	  //u16, u32, or u64
	  if (!strncmp(p, "u16", 3))
	    *var_nb_val_bytes = *var_type = TYPE_U16;
	  else
	    if (!strncmp(p, "u32", 3))
	      *var_nb_val_bytes = *var_type = TYPE_U32;
	    else
	      if (!strncmp(p, "u64", 3))
		*var_nb_val_bytes = *var_type = TYPE_U64;
	      else
		{
		  printf("Payload assembler: [ Error (%llu:%u): unknown type: '%c%c%c'! ]\n", nb_lines, i, p[0], p[1], p[2]);
		  exit(1);
		}
	  
	  //
	  i += 3;
	  
	  //
	  i += skip(p + i);
	}
    }
  else
    {
      printf("Payload assembler: [ Error (%llu:%u): unknown type: '%c%c%c'! ]\n", nb_lines, i, p[0], p[1], p[2]);
      exit(1);
    }
  
  //
  return i;
}

//
u32 get_var_section_vars(u8 *p, var_section_t *v)
{
  //
  u32 i = 0;

  //This should be code cave entry address
  u64 var_section_curr_addr = 0; 

  //
  u8 var_type;
  u64 var_nb_val_bytes;
  
  //Go untill new section is found
  while (p[i] != '[')
    {
      if (p[i] == '#')
	{
	  //
	  i++;
	  
	  //
	  i += skip_comment(p + i);

	  //
	  i++;
	  
	  //
	  i += skip(p + i);
	}
      else
	{
	  //Get variable type (handles byte arrays)
	  i += get_var_section_var_type(p + i, &var_type, &var_nb_val_bytes);

	  //
	  v->var_section_vars[v->var_section_nb_vars].var_type = var_type;
	  v->var_section_vars[v->var_section_nb_vars].var_nb_val_bytes = var_nb_val_bytes;

	  //Set values array to 0
	  memset(v->var_section_vars[v->var_section_nb_vars].var_val, 0, MAX_NB_VAL_BYTES);
	  
	  //Get variable name
	  i += get_string(p + i,
			  v->var_section_vars[v->var_section_nb_vars].var_name,
			  NULL);
	  
	  //
	  i += skip(p + i);
      
	  //If u8 allow character
	  if (var_type == TYPE_U8)
	    {
	      //
	      if (p[i] == '\'')
		{
		  //
		  i++;
		  
		  //Get the initializing character value
		  v->var_section_vars[v->var_section_nb_vars].var_val[0] = p[i];
		  
		  //
		  i++;

		  //
		  if (p[i] != '\'')
		    {
		      printf("Payload assembler: [ Error (%llu:%u): '\'' expected, '%c' found instead ! ]\n", nb_lines, i, p[i]);
		      exit(1);
		    }
		  
		  //
		  i++;
		}
	      else
		if (is_digit(p[i]))
		  {
		    u64 var_val;
		
		    i += get_number(p + i, &var_val);
		    
		    v->var_section_vars[v->var_section_nb_vars].var_val[0] = (u8)var_val;
		  }
	      
	      //
	      i += skip(p + i);
	    }
	  else
	    {
	      //
	      u64 var_val;
	      
	      //
	      i += get_number(p + i, &var_val);
	      
	      //
	      if (var_type == TYPE_U16)
		{
		  *((u16 *)&v->var_section_vars[v->var_section_nb_vars].var_val) = (u16)var_val;
		}
	      else
		if (var_type == TYPE_U32)
		  {
		    *((u32 *)&v->var_section_vars[v->var_section_nb_vars].var_val) = (u32)var_val;
		  }
		else
		  if (var_type == TYPE_U64)
		    {
		      *((u64 *)&v->var_section_vars[v->var_section_nb_vars].var_val) = (u64)var_val;
		    }
	      
	      //
	      i += skip(p + i);
	    }
	  
	  //If end of statement
	  if (p[i] != ';')
	    {
	      printf("Payload assembler: [ Error (%llu:%u): ';' expected, '%c' found instead ! ]\n", nb_lines, i, p[i]);
	      exit(1);
	    }
	  
	  //
	  i++;
	  
	  //
	  i += skip(p + i);

	  //
	  v->var_section_vars[v->var_section_nb_vars].var_address = var_section_curr_addr;

	  //
	  var_section_curr_addr += v->var_section_vars[v->var_section_nb_vars].var_nb_val_bytes;
	  
	  //
	  v->var_section_nb_vars++;
	}
    }
  
  //
  v->var_section_bytecode_size = var_section_curr_addr;
  
  //
  return i;
}

//
u32 get_var_section(u8 *p, var_section_t **v)
{
  //
  (*v) = malloc(sizeof(var_section_t));

  //
  u32 i = get_var_section_header(p, (*v));
  
  //
  i += get_var_section_vars(p + i, (*v));
  
  //
  return i;
}
