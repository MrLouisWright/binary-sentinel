#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
int main(void) { if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) return 1; char *a[] = {"/bin/sh", 0}; execve(a[0], a, 0); return 0; }
