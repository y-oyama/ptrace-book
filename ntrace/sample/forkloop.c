#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
  int i, n;
  pid_t *child_list;
  unsigned int duration = 0;

  if ((argc != 2) && (argc != 3)) {
    fprintf(stderr, "Usage: %s num-of-children [sleep-duration-in-s]\n", argv[0]), exit(1);
  }
  n = atoi(argv[1]);
  if (argc == 3) {
    duration = atoi(argv[2]);
  }

  if ((child_list = malloc(sizeof(pid_t) * n)) == NULL) {
    perror("malloc"), exit(1);
  }
  printf("I am parent %d.\n", getpid());
  for (i = 0; i < n; i++) {
    pid_t child = child_list[i] = fork();
    if (child == -1) {
      perror("fork"), exit(1);
    } else if (child == 0) {
      printf("I am child %d.\n", getpid());
      if (duration) {
        sleep(duration);
      }
      return 0;
    }
  }

  for (i = 0; i < n; i++) {
    if (waitpid(child_list[i], NULL, 0) != child_list[i]) {
      perror("waitpid"), exit(1);
    }
    printf("Parent finished waiting for child %d.\n", child_list[i]);
  }

  free(child_list);

  return 0;
}
