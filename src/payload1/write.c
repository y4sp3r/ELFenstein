#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

//
int main(int argc, char **argv)
{
  //
  if (argc < 2)
    return printf("Usage %s [string]\n", argv[0]), 2;

  //
  write(1, argv[1], strlen(argv[1]));

  putchar('\n');
  
  return 0;
}
