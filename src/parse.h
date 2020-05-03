#ifndef PARSE_H
#define PARSE_H

//
#include "types.h"

//
#include "const.h"

//Symbols table entry
typedef struct var_s {

  //
  u64 var_line_number;
  
  //
  u8 var_type;
  
  //
  u64 var_address;
  
  //
  u8 var_val[MAX_NB_VAL_BYTES];
  
  // 
  u64 var_nb_val_bytes;
  
  //
  u8 var_name[MAX_STR_LEN];
  
} var_t;

//Variables section
typedef struct var_section_s {

  //
  u64 var_section_nb_vars;
  
  //Symbols table
  var_t var_section_vars[MAX_VARS];

  //Data in bytes
  u8 *var_section_bytecode;

  //Bytecode size in bytes
  u64 var_section_bytecode_size;
  
} var_section_t;

//Symbols table entry
typedef struct string_s {
  
  //
  u64 string_line_number;
  
  //
  u64 string_address;
  
  //
  u8 string_val[MAX_NB_VAL_BYTES];
  
  //String length
  u64 string_val_len;
  
} string_t;

//
typedef struct string_section_s {

  //
  u64 string_section_nb_strings;
  
  //
  string_t string_section_strings[MAX_STRINGS];
  
  //
  u8 *string_section_bytecode;
  
  //
  u64 string_section_bytecode_size;
  
} string_section_t;

//
u8 is_sep(u8 c);

//
u32 get_var_section(u8 *p, var_section_t **v);
u32 get_string_section(u8 *p, string_section_t **s);

//
#endif
