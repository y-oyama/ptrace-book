#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int n;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s num\n", argv[0]);
    exit(1);
  }
  n = atoi(argv[1]);

  printf("%d\n", n);

  if (n > 0) {
    char n_str[80];
    snprintf(n_str, 80, "%d", n - 1);
    execl(argv[0], argv[0], n_str, NULL);
    perror("execl");
    exit(1);
  }

  return 0;
}
