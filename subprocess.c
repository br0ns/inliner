#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

char *subprocess(char *cmd) {
  int fd[2], devnull, ret;
  char *buf;
  size_t len, sz;
  pid_t pid;

  /* keep gcc happy */
  buf = NULL;

  if (pipe(fd)) {
    return NULL;
  }

  pid = fork();
  switch (pid) {
  case -1: /* fork() failed */
    goto ERROR;

  case 0:  /* child */
    /* < /dev/null */
    devnull = open("/dev/null", O_RDONLY);
    if (-1 == devnull) {
      goto ERROR;
    }
    dup2(devnull, STDIN_FILENO);
    /* 2> /dev/null */
    devnull = open("/dev/null", O_WRONLY);
    if (-1 == devnull) {
      goto ERROR;
    }
    dup2(devnull, STDERR_FILENO);
    /* > [pipe] */
    dup2(fd[1], STDOUT_FILENO);

    close(fd[0]);
    close(fd[1]);

    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(1);

  default: /* parent */
    close(fd[1]);
    len = 4096;
    sz = 0;
    buf = malloc(len);
    if (!buf) {
      errno = ENOMEM;
      goto ERROR;
    }
    for (;;) {
      if (sz == len) {
        len *= 2;
        buf = realloc(buf, len);
        if (!buf) {
          errno = ENOMEM;
          goto ERROR;
        }
      }
      ret = read(fd[0], &buf[sz], len - sz);
      if (-1 == ret) {
        if (EINTR == errno) {
          continue;
        } else {
          goto ERROR;
        }
      } else if (0 == ret) {
        buf = realloc(buf, sz + 1);
        if (!buf) {
          errno = ENOMEM;
          goto ERROR;
        }
        /* zero terminate */
        buf[sz] = 0;
        /* wait for child to exit */
        do {
          ret = waitpid(pid, NULL, 0);
        } while (-1 == ret && EINTR == errno);

        return buf;
      } else {
        sz += ret;
      }
    }

  }

  ERROR:
  close(fd[0]);
  close(fd[1]);
  kill(pid, 9);
  /* wait for child to die */
  do {
    ret = waitpid(pid, NULL, 0);
  } while (-1 == ret && EINTR == errno);
  if (buf) {
    free(buf);
  }
  return NULL;
}
