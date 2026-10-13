#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) { char b[64]; strncpy(b, argc > 1 ? argv[1] : "hi", sizeof b - 1); b[63] = 0; printf("%s %d\n", b, argc); return 0; }
