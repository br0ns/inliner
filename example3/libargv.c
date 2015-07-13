#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

__attribute__((constructor))
void libargv_init() {
  char *allowed, exe[4096];
  ssize_t ret;

  allowed = getenv("INLINER_ALLOWED");
  if (NULL == allowed) {
    return;
  }
  ret = readlink("/proc/self/exe", exe, sizeof(exe));
  if (-1 == ret) {
    return;
  }
  exe[ret] = 0;
  if (strstr(allowed, basename(exe)) == NULL) {
    printf("LIBARGV_MARKER_START%sLIBARGV_MARKER_END", exe);
    fflush(stdout);
    _exit(0);
  }
}
