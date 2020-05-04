#ifndef CONST_H
#define CONST_H

//1MiB buffer size
#define MAX_BUFFER 1024 * 1024

//Maximum length of a string
#define MAX_STR_LEN 129

//Maximum nuber of variables
#define MAX_VARS 16

//Maximum number of strings
#define MAX_STRINGS 16

//Maximum size of an array
#define MAX_NB_VAL_BYTES 16

//Maximum size of var data section
#define MAX_VAR_SEC_BYTECODE_SIZE 256

//Maximum size of sring data section
#define MAX_STRING_SEC_BYTECODE_SIZE 256

//Byte array type 
#define TYPE_U8_A 0

//Unsigned integers types (atomic)
#define TYPE_U8   1
#define TYPE_U16  2
#define TYPE_U32  4
#define TYPE_U64  8

//16 bytes
#define MAX_KEY_LEN 16

//Encryption/Decryption scheme
#define CRYPT_TYPE_STATIC      0
#define CRYPT_TYPE_POLYMORPHIC 1
#define CRYPT_TYPE_METAMORPHIC 2

//
static u8 *crypt_type_str[] = { "static", "polymorphic", "metamorphic" };

#endif

