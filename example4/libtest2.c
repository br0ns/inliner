#include <string.h>
__attribute__((constructor))
void libtest2_init() {
  char *str = "Hello from libtest2\n";
  write(1, str, strlen(str));
}
