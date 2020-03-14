#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <errno.h>

#include "util.h"

void print_regs(struct USER_REGS *regs)
{
#if (__x86_64 || __amd64)
  printf("    rax=%lld (0x%08llx), rbx=%lld (0x%08llx), rcx=%lld (0x%08llx), rdx=%lld (0x%08llx), rsi=%lld (0x%08llx), rdi=%lld (0x%08llx)\n",
         regs->rax, regs->rax, regs->rbx, regs->rbx, regs->rcx, regs->rcx, regs->rdx, regs->rdx, regs->rsi, regs->rsi, regs->rdi, regs->rdi);
  printf("    r8 =%lld (0x%08llx), r9 =%lld (0x%08llx), r10=%lld (0x%08llx), r11=%lld (0x%08llx), r12=%lld (0x%08llx)\n",
         regs->r8,  regs->r8,  regs->r9,  regs->r9,  regs->r10, regs->r10, regs->r11, regs->r11, regs->r12, regs->r12);
  printf("    r13 =%lld (0x%08llx), r14 =%lld (0x%08llx), r15=%lld (0x%08llx)\n",
         regs->r13, regs->r13, regs->r14, regs->r14, regs->r15, regs->r15);
  printf("    orig_rax =%lld (0x%08llx)\n",
         regs->orig_rax, regs->orig_rax);
  printf("    rsp=%lld (0x%08llx), rbp=%lld (0x%08llx), rip=%lld (0x%08llx), eflags=%lld (0x%08llx)\n",
         regs->rsp, regs->rsp, regs->rbp, regs->rbp, regs->rip, regs->rip, regs->eflags, regs->eflags);
#elif defined(__arm__)
  printf("    orig_r0=%ld (0x%08lx), r0=%ld (0x%08lx), r1=%ld (0x%08lx), r2=%ld (0x%08lx), r3=%ld (0x%08lx), r4=%ld (0x%08lx)\n",
         regs->ARM_ORIG_r0, regs->ARM_ORIG_r0, regs->ARM_r0, regs->ARM_r0, regs->ARM_r1, regs->ARM_r1, regs->ARM_r2, regs->ARM_r2,
         regs->ARM_r3, regs->ARM_r3, regs->ARM_r4, regs->ARM_r4);
  printf("         r5=%ld (0x%08lx), r6=%ld (0x%08lx), r7=%ld (0x%08lx), r8=%ld (0x%08lx), r9=%ld (0x%08lx), r10=%ld (0x%08lx)\n",
         regs->ARM_r5, regs->ARM_r5, regs->ARM_r6, regs->ARM_r6, regs->ARM_r7, regs->ARM_r7, regs->ARM_r8, regs->ARM_r8,
         regs->ARM_r9, regs->ARM_r9, regs->ARM_r10, regs->ARM_r10);
  printf("    cpsr=%ld (0x%08lx), pc=%ld (0x%08lx), lr=%ld (0x%08lx), sp=%ld (0x%08lx), ip=%ld (0x%08lx), fp=%ld (0x%08lx)\n",
         regs->ARM_cpsr, regs->ARM_cpsr, regs->ARM_pc, regs->ARM_pc, regs->ARM_lr, regs->ARM_lr, regs->ARM_sp, regs->ARM_sp,
         regs->ARM_ip, regs->ARM_ip, regs->ARM_fp, regs->ARM_fp);
#else
  #Error "Unsupported architecture."
#endif
}

void get_remote_string(pid_t child_pid, void *str, void *dstbuf, size_t dstbufsize)
{
  uint8_t *remote_p, *local_p;
  if (dstbufsize < 1) {
    return;
  }
  for (remote_p = (uint8_t *)str, local_p = (uint8_t *)dstbuf; ; remote_p++, local_p++) {
    long d;
    if (local_p == dstbuf + dstbufsize - 1) { /* End of buffer? */
      *local_p = '\0';
      break;
    }
    d = ptrace(PTRACE_PEEKTEXT, child_pid, remote_p, 0);
    if (d == -1) {
      if (errno != 0) {
        perror("ptrace");
        exit(EXIT_FAILURE);
      }
    }
    *local_p = (uint8_t)(d & 0xff); /* Copy one character of the string at a time */
    if (*local_p == '\0') { /* End of string? */
      break;
    }
  }
}
  
void get_remote_buffer(pid_t child_pid, void *srcbuf, void *dstbuf, size_t dstbufsize)
{
  uint8_t *remote_p, *local_p;
  for (remote_p = (uint8_t *)srcbuf, local_p = dstbuf; ; remote_p++, local_p++) {
    long d;
    if (local_p == dstbuf + dstbufsize) {
      break;
    }
    d = ptrace(PTRACE_PEEKTEXT, child_pid, remote_p, 0);
    if (d == -1) {
      if (errno != 0) {
        perror("ptrace");
        exit(EXIT_FAILURE);
      }
    }
    *local_p = *((uint8_t *)&d);
  }
}

void print_buffer(void *buf, size_t bufsize)
{
  uint8_t c;
  int i;
  for (i = 0; i < bufsize; i++) {
    c = *((uint8_t *)buf);
    if (isprint(c)) {
      printf("%c", c);
    } else if (c == '\t') {
      printf("\\t");
    } else if (c == '\n') {
      printf("\\n");
    } else if (c == '\r') {
      printf("\\r");
    } else if (c == '\0') {
      printf("\\0");
    } else {
      printf("\\x%02x", c);
    }
    buf++;
  }
}

void print_waitpid_status(int st, FILE *fp)
{
  if (WIFEXITED(st)) {
    fprintf(fp, "EXIT: %d\n", WEXITSTATUS(st));
  } else if (WIFSIGNALED(st)) {
    fprintf(fp, "SIGNAL: %d\n", WTERMSIG(st));
  } else if (WIFSTOPPED(st)) {
    fprintf(fp, "STOP: %d\n", WSTOPSIG(st));
  } else if (WIFCONTINUED(st)) {
    fprintf(fp, "CONTINUED\n");
  } else {
    fprintf(fp, "OTHERS\n");
  }
}

void wait_until_new_process_appears(pid_t pid)
{
#if 0
  while (kill(pid, 0) == -1) {
    /* How should we wait here? */
  }
#else
  struct USER_REGS regs;
  while (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
    /* How should we wait here? */
  }
#endif
}
