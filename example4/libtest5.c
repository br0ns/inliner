#include <string.h>
__attribute__((constructor))
void libtest1_init() {
  char *str = "Hello from libtest5\n";
  write(1, str, strlen(str));
}
