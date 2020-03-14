#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "util.h"

typedef struct {
  bool waiting_sysentry;
} procinfo_t;

static procinfo_t procinfo[32768];
static bool was_forked = false;

static void child_main(char **arg_vec)
{
  if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
    perror("ptrace");
    exit(EXIT_FAILURE);
  }
  kill(getpid(), SIGSTOP);
  execvp(arg_vec[0], arg_vec);
  perror("execv");
  exit(EXIT_FAILURE);
}

static void handler_syscall_entry(pid_t child_pid, struct USER_REGS *regs)
{
#if (__x86_64 || __amd64)
  uintptr_t scnum = regs->orig_rax;
#elif defined(__arm__)
  uintptr_t scnum = regs->ARM_r7;
#else
#error
#endif

  uintptr_t flag;

  if ((scnum == __NR_read)
      || (scnum == __NR_stat)
      || (scnum == __NR_fstat)
      || (scnum == __NR_lstat)) {
    return;
  } else if ((scnum == __NR_open) || (scnum == __NR_openat)) {
    uintptr_t path;
    uint8_t pathbuf[PATH_MAX];
    if (scnum == __NR_open) {
#if (__x86_64 || __amd64)
      path = regs->rdi;
      flag = regs->rsi;
#elif defined(__arm__)
      path = regs->ARM_r0;
      flag = regs->ARM_r1;
#else
#error
#endif
    } else if (scnum == __NR_openat) {
#if (__x86_64 || __amd64)
      path = regs->rsi;
      flag = regs->rdx;
#elif defined(__arm__)
      path = regs->ARM_r1;
      flag = regs->ARM_r2;
#else
#error
#endif
    } else {
      fprintf(stderr, "%s:%d: PANIC: scnum=%ld.\n", __FILE__, __LINE__, scnum);
      exit(EXIT_FAILURE);
    }
    if ((flag & O_WRONLY) || (flag & O_RDWR)) {
      get_remote_string(child_pid, (void *)path, pathbuf, PATH_MAX);
      fprintf(stderr, "Child process %d attempted to open file \"%s\" with a write-access flag. I will kill the process.\n", child_pid, pathbuf);
      if (kill(child_pid, SIGKILL) != 0) {
        perror("kill");
        exit(EXIT_FAILURE);
      }
      fprintf(stderr, "Killed.\n");
    }
  }
}

static pid_t handler_syscall_exit(pid_t child_pid, struct USER_REGS *regs)
{
#if (__x86_64 || __amd64)
  uintptr_t scnum = regs->orig_rax;
#elif defined(__arm__)
  uintptr_t scnum = regs->ARM_r7;
#else
#error
#endif

  (void)scnum;

  return 0;
}

static void parent_main(void)
{
  pid_t child_pid;
  siginfo_t si;
  pid_t w;

  /* waiting for child to stop voluntarily */
  w = waitid(P_ALL, 0, &si, WEXITED | WSTOPPED | WCONTINUED);
  if (w != 0) {
    perror("waitid");
    exit(EXIT_FAILURE);
  }
  if ((si.si_code != CLD_TRAPPED) || (si.si_status != SIGSTOP)) {
    fprintf(stderr, "PANIC: si.si_code=%d, si.si_status=%d\n", si.si_code, si.si_status);
    exit(EXIT_FAILURE);
  }

  child_pid = si.si_pid;

  if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
             PTRACE_O_EXITKILL
             | PTRACE_O_TRACECLONE
             | PTRACE_O_TRACEEXEC
             | PTRACE_O_TRACEEXIT
             | PTRACE_O_TRACEFORK
             | PTRACE_O_TRACESYSGOOD
             | PTRACE_O_TRACEVFORK
             | PTRACE_O_TRACEVFORKDONE) == -1) {
    perror("perror");
    exit(EXIT_FAILURE);
  }
  if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) < 0) {
    perror("ptrace");
    exit(EXIT_FAILURE);
  }

  if (child_pid >= 32768) {
    fprintf(stderr, "Error: too large PID: %d\n", child_pid);
    exit(EXIT_FAILURE);
  }
  procinfo[child_pid].waiting_sysentry = true;

  while (1) {
    w = waitid(P_ALL, 0, &si, WEXITED | WSTOPPED | WCONTINUED);
    if (w != 0) {
      if (errno == ECHILD) {
        //fprintf(stderr, "All children terminated.\n");
        return;
      }
      perror("waitid");
      exit(EXIT_FAILURE);
    }

    child_pid = si.si_pid;

    switch (si.si_code) {
    case CLD_EXITED:
      //printf("Application process %d exited normally (exit status = %d).\n", child_pid, si.si_status);
      break;
    case CLD_KILLED:
      //printf("Application process %d killed (exit status = %d).\n", child_pid, si.si_status);
      break;
    case CLD_STOPPED:
      //printf("Application process %d stopped because of signal %d.\n", child_pid, si.si_status);
      kill(child_pid, SIGCONT);
      break;
    case CLD_CONTINUED:
      //printf("Application process %d continued because of SIGCONT.\n", child_pid);
      break;
    case CLD_DUMPED:
      //printf("Application process %d exited abnormally with signal %d.\n", child_pid, si.si_status);
      break;
    case CLD_TRAPPED: {
      int signum = si.si_status;
      //printf("Application process %d trapped (signum = %d).\n", child_pid, signum);
      if ((signum & 0x7f) == SIGTRAP) {
        if (signum == (0x80 | SIGTRAP)) {
          struct USER_REGS regs;
          if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
          }
          if (procinfo[child_pid].waiting_sysentry) {
            handler_syscall_entry(child_pid, &regs);
            procinfo[child_pid].waiting_sysentry = false;
          } else {
            pid_t r = handler_syscall_exit(child_pid, &regs);
            (void)r;
            procinfo[child_pid].waiting_sysentry = true;
          }
        } else if (signum == ((PTRACE_EVENT_EXIT << 8) | SIGTRAP)) {
          /* Trap before exit */
          /* No-op currently */
        } else if (signum == ((PTRACE_EVENT_EXEC << 8) | SIGTRAP)) {
          /* Trap before return from execve() */
          /* No-op currently */
        } else if (signum == ((PTRACE_EVENT_CLONE << 8) | SIGTRAP)) {
          /* Trap before return from clone() */
          /* No-op currently */
        } else if (signum == ((PTRACE_EVENT_VFORK_DONE << 8) | SIGTRAP)) {
          /* Trap before return from vfork or clone(), after the unblocking op by the child */
          /* No-op currently */
        } else if ((signum == ((PTRACE_EVENT_FORK << 8) | SIGTRAP))
                   || (signum == ((PTRACE_EVENT_VFORK << 8) | SIGTRAP))) {
          /* Trap before return from fork() or vfork() */
          unsigned long grand_child_pid0;
          pid_t grand_child_pid;
          was_forked = true;
          if (ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &grand_child_pid0) == -1) {
            perror("ptrace");
            exit(EXIT_FAILURE);
          }
          grand_child_pid = grand_child_pid0;

          wait_until_new_process_appears(grand_child_pid);

          {
            pid_t grand_child_pid2;
            int st2;
            if ((grand_child_pid2 = waitpid(grand_child_pid, &st2, 0)) != grand_child_pid) {
              perror("waitpid");
              fprintf(stderr, "grand_child_pid2=%d\n", grand_child_pid2);
              exit(EXIT_FAILURE);
            }
          }

          if (ptrace(PTRACE_SYSCALL, grand_child_pid, 0, 0) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
          }

          procinfo[child_pid].waiting_sysentry = false;
          procinfo[grand_child_pid].waiting_sysentry = true;
        } else if (signum == SIGTRAP) {
          /* Normal SIGTRAP: due to int3, for example. */
          /* SIGTRAP is delivered as it is. */
          if (ptrace(PTRACE_SYSCALL, child_pid, 0, SIGTRAP) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
          }
          break;
        } else {
          fprintf(stderr, "Error: unsupported signal number: 0x%08x.\n", signum);
          exit(EXIT_FAILURE);
        }
      } else {
        //fprintf(stderr, "Application process %d caused a non-syscall signal! (signum = %d)\n", child_pid, signum);
        if ((0 < signum) && (signum < NSIG)) {
          //fprintf(stderr, "PID %d: Received a signal (number %d: %s).\n", child_pid, signum, strsignal(signum));
        } else {
          //fprintf(stderr, "waitid returned.\n");
        }
      }

      /* Continue the child. */
      if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) < 0) {
        if (errno == ESRCH) {
          /* Child process is dead. */
          break;
        } else {
          perror("ptrace");
          exit(EXIT_FAILURE);
        }
      }
      break;
    }
    default:
      fprintf(stderr, "Error: unsupported si_code: %d.\n", si.si_code);
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char **argv)
{
  pid_t pid;
  char **cmd_argv;
  int i;
  if (argc == 1) {
    fprintf(stderr, "Usage: %s command...\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  if ((cmd_argv = malloc(sizeof(char *) * argc)) == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  for (i = 0; i < argc - 1; i++) {
    cmd_argv[i] = strdup(argv[i + 1]);
  }
  cmd_argv[argc - 1] = NULL;
  pid = fork();
  if (pid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  } else if (pid == 0) {
    child_main(cmd_argv);
  } else {
    parent_main();
  }

  return 0;
}
