#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main (int argc, char *argv[]) {
  int fd, i;

  for (i = 0; i < 20; i++) {
    fd = open("/dev/null", O_RDONLY);
    printf("I opened /dev/null and got fd %d\n", fd);
  }
}
