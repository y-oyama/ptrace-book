#!/usr/bin/python

import sys
import re

armbase = "xxx"
for line in iter(sys.stdin.readline, ""):
    m = re.match('^#define __NR_(\S+)\s+.+__NR_SYSCALL_BASE\+\s*(\d+)\)', line)
    if m:
        print("case %s: printf(\"%s\"); break;" % (m.group(2), m.group(1)))
    m = re.match('^#define __ARM_NR_BASE\s+.+__NR_SYSCALL_BASE\+\s*(\w+)\)', line)
    if m:
        armbase = m.group(1)
    m = re.match('^#define __ARM_NR_(\S+)\s+.+__ARM_NR_BASE\+\s*(\d+)\)', line)
    if m:
        print("case %s+%s: printf(\"%s\"); break;" % (armbase, m.group(2), m.group(1)))
