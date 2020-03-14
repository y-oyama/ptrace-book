#!/usr/bin/python

import sys
import re

for line in iter(sys.stdin.readline, ""):
    m = re.match('^#define __NR_(\S+)\s+(\d+)$', line)
    if m:
        print("case __NR_%s /* %s */: printf(\"%s\"); break;" % (m.group(1), m.group(2), m.group(1)))
    else:
        m = re.match('^#define __NR_(\S+)\s+.+__NR_SYSCALL_BASE\+\s*(\d+)\)', line)
        if m:
            print("case __NR_%s /* %s */: printf(\"%s\"); break;" % (m.group(1), m.group(2), m.group(1)))
