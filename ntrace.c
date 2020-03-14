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

#define MY_PID_MAX 32768

static procinfo_t procinfo[MY_PID_MAX + 1];
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

static void print_st_mode(mode_t mode)
{
  if (S_ISSOCK(mode)) printf("S_IFSOCK|");
  if (S_ISLNK(mode)) printf("S_IFLNK|");
  if (S_ISREG(mode)) printf("S_IFREG|");
  if (S_ISBLK(mode)) printf("S_IFBLK|");
  if (S_ISDIR(mode)) printf("S_IFDIR|");
  if (S_ISCHR(mode)) printf("S_IFCHR|");
  if (S_ISFIFO(mode)) printf("S_IFIFO|");
  if (mode & S_ISUID) printf("S_ISUID|");
  if (mode & S_ISGID) printf("S_ISGID|");
  if (mode & S_ISVTX) printf("S_ISVTX|");
  printf("0%d%d%d", ((mode >> 6) & 0x7), ((mode >> 3) & 0x7), ((mode >> 0) & 0x7));
}

static void print_syscall_args(pid_t child_pid)
{
  struct USER_REGS regs;
  uintptr_t scnum, scretval, scarg1, scarg2, scarg3, scarg4, scarg5, scarg6;
  uint8_t path[PATH_MAX];

  if (was_forked) {
    printf("[pid %5d] ", child_pid);
  }
  if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
    perror("ptrace");
    exit(EXIT_FAILURE);
  }

#if (__x86_64 || __amd64)
  scnum = regs.orig_rax;
  scretval = regs.rax;
  scarg1 = regs.rdi;
  scarg2 = regs.rsi;
  scarg3 = regs.rdx;
  scarg4 = regs.r10;
  scarg5 = regs.r8;
  scarg6 = regs.r9;
#elif defined(__arm__)
  scretval = regs.ARM_r0;
  scnum  = regs.ARM_r7;
  scarg1 = regs.ARM_r0;
  scarg2 = regs.ARM_r1;
  scarg3 = regs.ARM_r2;
  scarg4 = regs.ARM_r3;
  scarg5 = regs.ARM_r4;
  scarg6 = regs.ARM_r5;
#else
#error
#endif

  /* Print syscall name */
  switch (scnum) {
#include "syscall_table.h"
  default:
    printf("syscall_%ld", scnum);
  }

  /* Print syscall arguments */
  printf("(");
  if (scnum == __NR_open) {
    get_remote_string(child_pid, (void *)scarg1, path, sizeof(path));
    printf("\"%s\", %ld, 0x%08lx", path, scarg2, scarg3);
  } else if (scnum == __NR_openat) {
    get_remote_string(child_pid, (void *)scarg2, path, sizeof(path));
    printf("%ld, \"%s\", %ld, 0x%08lx", scarg1, path, scarg3, scarg4);
  } else if (scnum == __NR_access) {
    get_remote_string(child_pid, (void *)scarg1, path, sizeof(path));
    printf("\"%s\", %ld", path, scarg2);
  } else if (scnum == __NR_execve) {
    get_remote_string(child_pid, (void *)scarg1, path, sizeof(path));
    printf("\"%s\", %ld, %ld", path, scarg2, scarg3);
  } else if (scnum == __NR_read) {
    size_t n = scretval;
    printf("%ld, \"", scarg1);
    if (n > 0) {
      void *buf;
      if ((buf = malloc(n)) == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
      }
      get_remote_buffer(child_pid, (void *)scarg2, buf, n);
      print_buffer(buf, n);
      free(buf);
    }
    printf("\", %ld", scarg3);
  } else if (scnum == __NR_write) {
    size_t n = scarg3;
    printf("%ld, \"", scarg1);
    if (n > 0) {
      void *buf;
      if ((buf = malloc(n)) == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
      }
      get_remote_buffer(child_pid, (void *)scarg2, buf, n);
      print_buffer(buf, n);
      free(buf);
    }
    printf("\", %ld", scarg3);
  } else if ((scnum == __NR_stat)
             || (scnum == __NR_fstat)
             || (scnum == __NR_lstat)) {
    struct stat st;
    if  ((scnum == __NR_stat) || (scnum == __NR_lstat)) {
      uint8_t path[PATH_MAX];
      get_remote_string(child_pid, (void *)scarg1, path, sizeof(path));
      printf("\"%s\", ", path);
    } else {
      printf("%ld, ", scarg1);
    }
    get_remote_buffer(child_pid, (void *)scarg2, (void *)&st,  sizeof(st));
    printf("{");
    printf("st_mode=");
    print_st_mode(st.st_mode);
    printf(", ");
    if (S_ISCHR(st.st_mode)) {
      printf("st_rdev=makedev(%d, %d)", (uint8_t)((st.st_rdev >> 8) & 0xff), (uint8_t)(st.st_rdev & 0xff));
    } else {
      printf("st_size=%ld", st.st_size);
    }
    printf(", ...");
    printf("}, ");
  } else {
    /* We currently omit printing 4, 5, 6-th arguments because most syscalls do not receive them. */
#if 0
    printf("%ld, %ld, %ld, %ld, %ld, %ld", scarg1, scarg2, scarg3, scarg4, scarg5, scarg6);
#else      
    (void)(scarg4);
    (void)(scarg5);
    (void)(scarg6);
    printf("%ld, %ld, %ld", scarg1, scarg2, scarg3);
#endif
  }
  printf(")");
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

  if ((scnum == __NR_read)
      || (scnum == __NR_stat)
      || (scnum == __NR_fstat)
      || (scnum == __NR_lstat)) {
    return;
  } else {
    print_syscall_args(child_pid);
  }
}

static void print_return_value(struct USER_REGS *regs)
{
#if (__x86_64 || __amd64)
  printf(" = %lld (0x%08llx)\n", regs->rax, regs->rax);
#elif defined(__arm__)
  printf(" = %ld (0x%08lx)\n", regs->ARM_r0, regs->ARM_r0);
#else
#error
#endif
}

static void handler_syscall_exit(pid_t child_pid, struct USER_REGS *regs)
{
#if (__x86_64 || __amd64)
  uintptr_t scnum = regs->orig_rax;
#elif defined(__arm__)
  uintptr_t scnum = regs->ARM_r7;
#else
#error
#endif

  if ((scnum == __NR_read)
      || (scnum == __NR_stat)
      || (scnum == __NR_fstat)
      || (scnum == __NR_lstat)) {
    print_syscall_args(child_pid);
  }
  print_return_value(regs);
}

static char *my_strsignal(int signum)
{
  if (signum < 0x80) {
    return strsignal(signum);
  } else {
    int hi24 = signum >> 8;
    int lo07 = signum & 0x7f;
    char str[64];
    strcpy(str, "");
    if (hi24 == 0) {
      /* nop */
    } else if (hi24 == PTRACE_EVENT_FORK) {
      strcat(str, "PTRACE_EVENT_FORK<<8 | ");
    } else if (hi24 == PTRACE_EVENT_VFORK) {
      strcat(str, "PTRACE_EVENT_VFORK<<8 | ");
    } else if (hi24 == PTRACE_EVENT_CLONE) {
      strcat(str, "PTRACE_EVENT_CLONE<<8 | ");
    } else if (hi24 == PTRACE_EVENT_EXEC) {
      strcat(str, "PTRACE_EVENT_EXEC<<8 | ");
    } else if (hi24 == PTRACE_EVENT_VFORK_DONE) {
      strcat(str, "PTRACE_EVENT_VFORK_DONE<<8 | ");
    } else if (hi24 == PTRACE_EVENT_EXIT) {
      strcat(str, "PTRACE_EVENT_EXIT<<8 | ");
    } else if (hi24 == PTRACE_EVENT_SECCOMP) {
      strcat(str, "PTRACE_EVENT_SECCOMP<<8 | ");
    } else {
      sprintf(str, "PTRACE_EVENT_OTHERS_0x%08x | ", hi24);
    }
    if (signum & 0x80) {
      strcat(str, "0x80 | ");
    }
    strcat(str, strsignal(lo07));
    return strdup(str);
  }
}

static void print_siginfo(pid_t child_pid, siginfo_t *si)
{
  if (si == NULL) {
    siginfo_t si0;
    si = &si0;
    memset(si, 0, sizeof(siginfo_t));
    if (ptrace(PTRACE_GETSIGINFO, child_pid, 0, si) < 0) {
      perror("ptrace");
      exit(EXIT_FAILURE);
    }
    //psignal(si->si_signo, "psignal output");
    psiginfo(si, "Signal");
  } else {
    //psignal(si->si_signo, "psignal output");
    psiginfo(si, "Signal");
  }
  fprintf(stderr, "  si_signo=%d (%s), si_errno=%d, si_code=%d, si_status=%d (%s),\n",
          si->si_signo, my_strsignal(si->si_signo), si->si_errno, si->si_code, si->si_status, my_strsignal(si->si_status));
  fprintf(stderr, "  si_int=%d, si_ptr=%p, si_addr=%p, si_fd=%d, si_call_addr=%p, si_syscall=%d\n",
          si->si_int, si->si_ptr, si->si_addr, si->si_fd, si->si_call_addr, si->si_syscall);
}

static void parent_main(void)
{
  pid_t child_pid;
  siginfo_t si;
  pid_t w;

  /* waiting for child to stop voluntarily */
  memset(&si, 0, sizeof(siginfo_t));
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

  if (child_pid > MY_PID_MAX) {
    fprintf(stderr, "Error: too large PID: %d\n", child_pid);
    exit(EXIT_FAILURE);
  }
  procinfo[child_pid].waiting_sysentry = true;

  while (1) {
    memset(&si, 0, sizeof(siginfo_t));
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
      //printf("Application process %d stopped because of signal %d (%s).\n", child_pid, si.si_status, my_strsignal(si.si_status));
      kill(child_pid, SIGCONT);
      break;
    case CLD_CONTINUED:
      //printf("Application process %d continued because of SIGCONT.\n", child_pid);
      break;
    case CLD_DUMPED:
      //printf("Application process %d exited abnormally with signal %d (%s).\n", child_pid, si.si_status, my_strsignal(si.si_status));
      break;
    case CLD_TRAPPED: {
      int signum = si.si_status;
      siginfo_t si2;
      //printf("Application process %d trapped (signum = %d, %s).\n", child_pid, signum, my_strsignal(signum));
      memset(&si2, 0, sizeof(siginfo_t));
      if (ptrace(PTRACE_GETSIGINFO, child_pid, 0, &si2) < 0) {
        perror("ptrace");
        exit(EXIT_FAILURE);
      }
      if ((signum == SIGSTOP) && (si.si_signo == SIGCHLD) && (si2.si_addr == NULL)) {
        /* SIGSTOP due to a grandchild is born */
        //printf("[pid %d] SIGSTOP due to the birth of a grandchild.\n", child_pid);

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

        /* Continue the child. */
        procinfo[child_pid].waiting_sysentry = true;
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) < 0) {
          perror("ptrace");
          exit(EXIT_FAILURE);
        }
      } else if ((signum & 0x7f) == SIGTRAP) {
        int injected_signum = 0;
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
            handler_syscall_exit(child_pid, &regs);
            procinfo[child_pid].waiting_sysentry = true;
          }
        } else if (signum == ((PTRACE_EVENT_EXIT << 8) | SIGTRAP)) {
          /* Trap before exit */
          if (!(procinfo[child_pid].waiting_sysentry)) {
            printf(" = ?\n");
          }
        } else if (signum == ((PTRACE_EVENT_EXEC << 8) | SIGTRAP)) {
          /* Trap before return from execve() */
          /* No-op currently */
        } else if (signum == ((PTRACE_EVENT_CLONE << 8) | SIGTRAP)) {
          /* Trap before return from clone() */
          /* No-op currently */
        } else if (signum == ((PTRACE_EVENT_VFORK_DONE << 8) | SIGTRAP)) {
          /* Trap before return from vfork or clone(), which usually occurs
             after the termination of the forked process */
          /* No-op currently */
        } else if ((signum == ((PTRACE_EVENT_FORK << 8) | SIGTRAP))
                   || (signum == ((PTRACE_EVENT_VFORK << 8) | SIGTRAP))) {
          /* Trap before return from fork() or vfork() */
          was_forked = true;
          procinfo[child_pid].waiting_sysentry = false;
        } else if (signum == SIGTRAP) {
          /* Normal SIGTRAP: due to int3, for example. */
          /* SIGTRAP is delivered as it is. */
          injected_signum = SIGTRAP;
        } else {
          fprintf(stderr, "Error: unsupported signal number: 0x%08x.\n", signum);
          exit(EXIT_FAILURE);
        }

        /* Continue the child. */
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, injected_signum) < 0) {
          perror("ptrace");
          exit(EXIT_FAILURE);
        }
      } else {
        //fprintf(stderr, "Application process %d caused a signal due to app's operation (signum = %d, %s)\n", child_pid, signum, my_strsignal(signum));
        print_siginfo(child_pid, NULL);

        if ((0 < signum) && (signum < NSIG)) {
          fprintf(stderr, "PID %d: Received a signal (number %d: %s).\n", child_pid, signum, my_strsignal(signum));
        } else {
          fprintf(stderr, "waitid returned.\n");
        }
        /* Continue the child. */
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, signum) < 0) {
          perror("ptrace");
          exit(EXIT_FAILURE);
        }
      }
      break;
    }
    default:
      fprintf(stderr, "Error: unsupported si_code: %d.\n", si.si_code);
      exit(EXIT_FAILURE);
    } /* switch */
  } /* while (1) */
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
