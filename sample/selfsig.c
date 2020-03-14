#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void handler(int sig)
{
  printf("I am in the handler of signal %d.\n", sig);
}

int main(int argc, char **argv)
{
  int sig;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s num\n", argv[0]);
    exit(1);
  }
  sig = atoi(argv[1]);

  signal(sig, handler);

  printf("I send signal %d.\n", sig);
  kill(getpid(), sig);
  printf("I returned from the handler of signal %d.\n", sig);

  return 0;
}
