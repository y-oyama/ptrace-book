#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  pid_t child;
  printf("I am %d\n", getpid());
  child = fork();
  if (child == -1) {
    perror("fork");
    exit(1);
  } else if (child == 0) {
    printf("I am child %d\n", getpid());
    getuid();
    return 1;
  } else {
    printf("I created child %d\n", child);
    printf("I am parent %d\n", getpid());
    getgid();
    return 2;
  }
  return 0;
}
