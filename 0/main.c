#include <stdio.h>

//
void first() __attribute__((constructor));
void last() __attribute__((destructor));

//
void first()
{ printf("First\n"); }

//
void last()
{ printf("Last\n"); }

int main()
{
  printf("Hello!\n");

  return 0;
}
