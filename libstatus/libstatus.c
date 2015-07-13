#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

__attribute__((constructor))
void libstatus_init() {
  struct sockaddr_storage sa;
  socklen_t len;
  int rport, i, ngroups, retval;
  char buf[4096];
  gid_t groups[50];

  printf(" == STATUS ==\n");

  printf("PID    = %d\n", getpid());

  len = sizeof sa;
  strcpy(buf, "ERR");
  rport = -1;
  if (0 == getpeername(0, (struct sockaddr*)&sa, &len) &&
      (AF_INET == sa.ss_family || AF_INET6 == sa.ss_family)
      ) {
    switch (sa.ss_family) {
    case AF_INET:
      rport = ((struct sockaddr_in*)&sa)->sin_port;
      inet_ntop(AF_INET, &((struct sockaddr_in*)&sa)->sin_addr,
                buf, sizeof(buf));
      break;
    case AF_INET6:
      rport = ((struct sockaddr_in6*)&sa)->sin6_port;
      inet_ntop(AF_INET6, &((struct sockaddr_in6*)&sa)->sin6_addr,
                buf, sizeof(buf));
      break;
    }
    printf("HOST   = %s\n", buf);
    printf("PORT   = %d\n", rport);
  } else {
    printf("(stdin/stdout is not a network socket)\n");
  }

  retval = readlink("/proc/self/exe", buf, sizeof(buf));
  if (-1 == retval) {
    printf("!! Could not read /proc/self/exe\n");
  } else {
    buf[retval] = 0;
    printf("EXE    = %s\n", buf);
  }

  if (getcwd(buf, sizeof(buf))) {
    printf("CWD    = %s\n", buf);
  }

  printf("UID    = %d\n", getuid());
  printf("GID    = %d\n", getgid());
  ngroups = getgroups(sizeof(groups) / sizeof(gid_t), groups);
  if (-1 != ngroups) {
    printf("Groups = [\n");
    for (i = 0; i < ngroups; i++) {
      printf("  %d,\n", groups[i]);
    }
    printf("  ]\n");
  }

  printf("\n_exit()'ing\n");
  fflush(stdout);
  _exit(0);
}
