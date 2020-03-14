#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdint.h>

#ifdef __arm__
#include <sys/user.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#define USER_REGS user_regs
#else
#define USER_REGS user_regs_struct
#endif

void print_regs(struct USER_REGS *regs);
void get_remote_string(pid_t child_pid, void *str, void *dstbuf, size_t dstbufsize);
void get_remote_buffer(pid_t child_pid, void *srcbuf, void *dstbuf, size_t dstbufsize);
void print_buffer(void *buf, size_t bufsize);
void print_waitpid_status(int st, FILE *fp);
void wait_until_new_process_appears(pid_t pid);

#endif /* _UTIL_H_ */
