#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

//
int main(int argc, char **argv)
{
  //
  if (argc < 2)
    return printf("Usage %s [bin]\n", argv[0]), 2;
  
  //
  execve(argv[1], NULL, NULL);

  //
  //syscall(SYS_execve, argv[1], NULL, NULL);
  
  return 0;
}
