#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void proc_main(int depth, pid_t self_pid)
{
  pid_t left_child, right_child;

  if (depth < 0) {
    return;
  }

  left_child = fork();
  printf("My pid is %d and left_child pid is %d\n", self_pid, left_child);
  if (left_child == -1) {
    perror("fork");
    exit(1);
  } else if (left_child == 0) {
    /* child */
    proc_main(depth - 1, getpid());
    return;
  }

  right_child = fork();
  printf("My pid is %d and right_child pid is %d\n", self_pid, right_child);
  if (right_child == -1) {
    perror("fork");
    exit(1);
  } else if (right_child == 0) {
    /* child */
    proc_main(depth - 1, getpid());
    return;
  }

  /* parent */
  printf("My pid is %d and I am going to wait for left child %d.\n", self_pid, left_child);
  if (waitpid(left_child, NULL, 0) != left_child) {
    perror("waitpid"), exit(1);
  }    
  printf("My pid is %d and I am goind to wait for right child %d.\n", self_pid, right_child);
  if (waitpid(right_child, NULL, 0) != right_child) {
    perror("waitpid"), exit(1);
  }    

  printf("My pid is %d and I confirmed that two children %d and %d had joined. Parent pid is %d.\n",
         self_pid, left_child, right_child, getppid());
}

int main(int argc, char **argv)
{
  int depth;
  if (argc != 2) {
    fprintf(stderr, "Usage: %s depth-of-tree\n", argv[0]), exit(1);
  }
  depth = atoi(argv[1]);
  proc_main(depth, getpid());
  return 0;
}
