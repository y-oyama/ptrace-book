#include <stdio.h>
#include <unistd.h>

int main(void)
{
  int c = 0;
  while (1) {
    int r;
    printf("c = %d\n", c);
    c++;
    r = sleep(5);
    printf("r = %d\n", r);
  }
  return 0;
}
