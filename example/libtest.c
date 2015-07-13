#include <string.h>
__attribute__((constructor))
void init() {
  char *str = "I'm a constructoooor!\n";
  write(1, str, strlen(str));
}
