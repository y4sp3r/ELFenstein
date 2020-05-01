#ifndef PARSE_H
#define PARSE_H

//
#include "types.h"

//
#include "const.h"

//Variable symbols table entry
typedef struct var_s {

  //
  u8 var_type;
  
  //
  u64 var_address;
  
  //
  u8 var_val[MAX_NB_VAL_BYTES];
  
  // 
  u64 var_nb_val_bytes;
  
  //
  u8 var_name[MAX_STR];
  
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

//
u8 is_sep(u8 c);

//
u32 get_var_section(u8 *p, var_section_t **v);

//
#endif
