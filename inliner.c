#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <grp.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <time.h>

#include "debug.h"

#include "regex.h"
#include "fifo.h"
#include "filter.h"
#include "subprocess.h"

#include "config.h"

int childfd, logfd = -1, rport = 0, lport = 0;
char rhost[256] = {0};
pid_t childpid;
fifo_t ififo, ofifo;

int dsockpair(int fd[2]) {
  struct sockaddr_storage sa, sa2;
  socklen_t len, len2, type_len;
  int type, sock, tcpnodelay;

  fd[0] = fd[1] = -1;

  len = sizeof sa;
  if (getpeername(0, (struct sockaddr*)&sa, &len) ||
      !(AF_INET == sa.ss_family || AF_INET6 == sa.ss_family)
      ) {
    return -1;
  }

  switch (sa.ss_family) {
  case AF_INET:
    rport = ntohs(((struct sockaddr_in*)&sa)->sin_port);
    inet_ntop(AF_INET, &((struct sockaddr_in*)&sa)->sin_addr,
              rhost, sizeof(rhost));
    break;
  case AF_INET6:
    rport = ntohs(((struct sockaddr_in6*)&sa)->sin6_port);
    inet_ntop(AF_INET6, &((struct sockaddr_in6*)&sa)->sin6_addr,
              rhost, sizeof(rhost));
    break;
  }

  len = sizeof sa;
  if (getsockname(0, (struct sockaddr*)&sa, &len) ||
      !(AF_INET == sa.ss_family || AF_INET6 == sa.ss_family)
      ) {
    return -1;
  }

  switch (sa.ss_family) {
  case AF_INET:
    lport = ntohs(((struct sockaddr_in*)&sa)->sin_port);
    break;
  case AF_INET6:
    lport = ntohs(((struct sockaddr_in6*)&sa)->sin6_port);
    break;
  }

  type_len = sizeof type;
  if (getsockopt(0, SOL_SOCKET, SO_TYPE, &type, &type_len)) {
    return -2;
  }

  if (-1 == (fd[0] = socket(sa.ss_family, type, 0)) ||
      -1 == (fd[1] = socket(sa.ss_family, type, 0))
      ) {
    if (-1 != fd[0]) {
      close(fd[0]);
    }
    return -3;
  }

  fcntl(fd[0], F_SETFL, fcntl(fd[0], F_GETFL) | O_NONBLOCK);

  switch (sa.ss_family) {
  case AF_INET:
    ((struct sockaddr_in*)&sa)->sin_port = 0;
    break;
  case AF_INET6:
    ((struct sockaddr_in6*)&sa)->sin6_port = 0;
    break;
  }

  if(bind( fd[0], (struct sockaddr*)&sa, len) ||
     bind( fd[1], (struct sockaddr*)&sa, len) ||
     listen(fd[0], 3)
     ) {
    close(fd[0]);
    close(fd[1]);
    return -4;
  }

  len = sizeof sa;
  if (getsockname( fd[0], (struct sockaddr*)&sa, &len)) {
    close(fd[0]);
    close(fd[1]);
    return -1;
  }

  switch (sa.ss_family) {
  case AF_INET:
    len = sizeof(struct sockaddr_in);
    break;
  case AF_INET6:
    len = sizeof(struct sockaddr_in6);
    break;
  }

  if (connect(fd[1], (struct sockaddr*)&sa, len)) {
    close(fd[0]);
    close(fd[1]);
  }

  if (getsockname(fd[1], (struct sockaddr*)&sa, &len)) {
    close(fd[0]);
    close(fd[1]);
    return -1;
  }

  for(;;) {
    len2 = sizeof sa2;
    if (-1 == (sock = accept(fd[0], (struct sockaddr*)&sa2, &len2))) {
      close(fd[0]);
      close(fd[1]);
    }
    if (len2 == len && 0 == memcmp(&sa, &sa2, len)) {
      close(fd[0]);
      fd[0] = sock;
      break;
    }
    close(sock);
  }

  if (option_drip) {
    tcpnodelay = 1;
    if (setsockopt(0, IPPROTO_TCP, TCP_NODELAY, &tcpnodelay, sizeof(tcpnodelay))) {
      return -5;
    }
    if (setsockopt(1, IPPROTO_TCP, TCP_NODELAY, &tcpnodelay, sizeof(tcpnodelay))) {
      return -5;
    }
  }

  return 0;
}

char *filepath(char *path) {
  char *res, buf[4096] = {0}, *out;
  size_t len;
  ssize_t retval;

  if (path[0] == '/') {
    return strdup(path);
  } else {
    retval = readlink("/proc/self/exe", buf, sizeof(buf));
    if (-1 == retval) {
      return NULL;
    }
    buf[retval] = 0;
    res = dirname(buf);
    len = strlen(res);
    out = malloc(len + 1 + strlen(path) + 1);
    memcpy(out, res, len);
    out[len] = '/';
    strcpy(&out[len + 1], path);
  }

  return out;
}

void act_kill() {
  close(childfd);
  close(0);
  close(1);
  close(2);
  _exit(0);
}

void act_hang() {
  int retval;
  uint8_t buf[4096];
  fd_set rfds;

  /* kill the child */
  signal(SIGCHLD, SIG_IGN);
  kill(childpid, 9);
  close(childfd);

  /* read until input socket is closed */
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    retval = select(1, &rfds, NULL, NULL, NULL);
    if (-1 == retval) {
      if (EINTR == errno) {
        continue;
      } else {
        break;
      }
    } else if (retval) {
      retval = read(0, buf, sizeof(buf));
      if (-1 == retval) {
        if (EINTR == errno) {
          continue;
        } else {
          break;
        }
      } else if (0 == retval) {
        break;
      }
    }
  }
  act_kill();
}

void writec(int fd, uint8_t c) {
  for (;;) {
    if (write(fd, &c, 1) == -1) {
      if (errno != EINTR) {
        act_kill();
      }
    } else {
      break;
    }
  }
}

int do_read(int fd, uint8_t *buf, size_t numb) {
  int ret;

  for (;;) {
    ret = read(fd, buf, numb);
    if (!(ret == -1 && errno == EINTR)) {
      break;
    }
  }

  return ret;
}

int do_write(int fd, uint8_t *buf, size_t numb) {
  int ret;
  size_t i;

  for (i = 0; i < numb;) {
    ret = write(fd, &buf[i], numb - i);
    if (-1 == ret) {
      if (EINTR == errno) {
        continue;
      } else {
        return -1;
      }
    } else {
      i += ret;
    }
  }

  return numb;
}

void fifo_flush(fifo_t *fifo, int fd) {
  uint8_t c;
  if (!fifo_empty(fifo)) {
    while (-1 != fifo_pop(fifo, &c)) {
      writec(fd, c);
    }
  }
}

void act_flush_both() {
  int i;
  filter_t *filt;

  /* empty fifos */
  fifo_flush(&ififo, childfd);
  fifo_flush(&ofifo, 1);

  /* rewind filters */
  for (i = 0; (filt = allfilters[i]); i++) {
    filter_rewind(filt, 0);
  }
}

void act_flush_input() {
  int i;
  filter_t *filt;

  /* empty fifos */
  fifo_flush(&ififo, childfd);

  /* rewind filters */
  for (i = 0; (filt = ifilters[i]); i++) {
    filter_rewind(filt, 0);
  }
}

void act_flush_output() {
  int i;
  filter_t *filt;

  /* empty fifos */
  fifo_flush(&ofifo, 1);

  /* rewind filters */
  for (i = 0; (filt = ofilters[i]); i++) {
    filter_rewind(filt, 0);
  }
}

void act_patch(act_t *act, filter_t *filt, filter_t **filters) {
  uint8_t *patch;
  fifo_t *fifo;
  size_t szoldfifo, sznewfifo, szold, sznew, offset, gbeg, gend, i;
  int delta;

  fifo = filt->fifo;
  regex_format(filt->regex, act->patch.fmt, &patch, &sznew);

  debug("act_patch grp = %d, patch = { %s }\n", act->patch.group, patch);
  fifo_debug(fifo);

  offset = filt->regex->offset;
  gbeg = filt->regex->groups[act->patch.group].begin + offset;
  gend = filt->regex->groups[act->patch.group].end + offset;

  szold = gend - gbeg;
  delta = sznew - szold;
  szoldfifo = fifo_size(fifo);
  sznewfifo = szoldfifo + delta;
  debug("act_patch old = %d, new = %d, offset = %d, fifo = %d\n",
        (int)szold, (int)sznew, (int)offset, (int)sznewfifo);

  if (delta) {
    fifo_resize(fifo, sznewfifo);
    if (delta < 0) {
      /* slide end of fifo backward */
      for (i = gend; i < szoldfifo; i++) {
        fifo_set(fifo, i + delta, fifo_get(fifo, i));
      }
    } else {
      /* slide end of fifo forward */
      for (i = szoldfifo - 1; i >= gend; i--) {
        fifo_set(fifo, i + delta, fifo_get(fifo, i));
      }
    }
  }

  /* patch in new bytes */
  for (i = 0; i < sznew; i++) {
    fifo_set(fifo, gbeg + i, patch[i]);
  }
  free(patch);

  /* rewind filters */
  for (i = 0; (filt = filters[i]); i++) {
    filter_rewind(filt, gbeg);
  }

  fifo_debug(fifo);
}

void act_patch_file(act_t *act, filter_t *filt, filter_t **filters) {
  uint8_t *patch, buf[4096];
  char *path;
  fifo_t *fifo;
  size_t szoldfifo, sznewfifo, szold, sznew, offset, gbeg, gend, i;
  int delta, fd, numb;

  fifo = filt->fifo;

  path = filepath(act->patch_file.file);
  fd = open(path, O_RDONLY);
  free(path);
  patch = NULL;
  sznew = 0;
  if (-1 != fd) {
    for (;;) {
      numb = read(fd, buf, sizeof(buf));
      if (numb == 0) {
        close(fd);
        break;
      } else if (numb == -1) {
        if (EINTR == errno) {
          continue;
        } else {
          close(fd);
          debug("act_patch_file: error while reading file\n");
          break;
        }
      }
      patch = realloc(patch, sznew + numb);
      memcpy(&patch[sznew], buf, numb);
      sznew += numb;
    }
    debug("act_patch_file read %d bytes\n", (int)sznew);
  } else {
    debug("act_patch_file: could not open file '%s' for reading\n", act->patch_file.file);
  }

  /* code below is copy'n'pasted from above -- i don't dare too many last minute changes */
  debug("act_patch_ grp = %d, patch = { %s }\n", act->patch_file.group, patch);
  fifo_debug(fifo);

  offset = filt->regex->offset;
  gbeg = filt->regex->groups[act->patch_file.group].begin + offset;
  gend = filt->regex->groups[act->patch_file.group].end + offset;

  szold = gend - gbeg;
  delta = sznew - szold;
  szoldfifo = fifo_size(fifo);
  sznewfifo = szoldfifo + delta;
  debug("act_patch old = %d, new = %d, offset = %d, fifo = %d\n",
        (int)szold, (int)sznew, (int)offset, (int)sznewfifo);

  if (delta) {
    fifo_resize(fifo, sznewfifo);
    if (delta < 0) {
      /* slide end of fifo backward */
      for (i = gend; i < szoldfifo; i++) {
        fifo_set(fifo, i + delta, fifo_get(fifo, i));
      }
    } else {
      /* slide end of fifo forward */
      for (i = szoldfifo - 1; i >= gend; i--) {
        fifo_set(fifo, i + delta, fifo_get(fifo, i));
      }
    }
  }

  /* patch in new bytes */
  for (i = 0; i < sznew; i++) {
    fifo_set(fifo, gbeg + i, patch[i]);
  }
  free(patch);

  /* rewind filters */
  for (i = 0; (filt = filters[i]); i++) {
    filter_rewind(filt, gbeg);
  }

  fifo_debug(fifo);
}

void act_exec(char *cmd) {
  char *args[2];

  args[0] = filepath(cmd);
  args[1] = NULL;

  signal(SIGCHLD, SIG_IGN);
  kill(childpid, 9);
  close(childfd);

  execv(args[0], args);
}

void do_log(char *str, size_t numb) {
  char *path;
  char tbuf[256];
  time_t t;
  struct tm *tmp;

  if (logfd == -1 && option_logfile) {
    path = filepath(option_logfile);
    logfd = open(path, O_APPEND | O_WRONLY | O_CREAT, 0644);
    free(path);
  }

  if (logfd == -1) {
    return;
  }

  t = time(NULL);
  tmp = localtime(&t);
  if (!(tmp && strftime(tbuf, sizeof(tbuf), "%y-%m-%d %H:%M:%S", tmp))) {
    strcpy(tbuf, "xxx");
  }

  flock(logfd, LOCK_EX);
  dprintf(logfd, "[time=%s, host=%s, rport=%d, lport=%d, pid=%d] ",
          tbuf, rhost, rport, lport, getpid());
  do_write(logfd, (uint8_t*)str, numb);
  writec(logfd, '\n');
  flock(logfd, LOCK_UN);
}

void do_log_str(char *str) {
  do_log(str, strlen(str));
}

void act_log(act_t *act, filter_t *filt) {
  uint8_t *s;
  size_t numb;

  if (!option_logfile) {
    return;
  }

  regex_format(filt->regex, act->fmt, &s, &numb);
  do_log((char*)s, numb);
  free(s);
}

void act_input(act_t *act, filter_t *filt) {
  uint8_t *s;
  size_t numb;

  regex_format(filt->regex, act->fmt, &s, &numb);
  (void)do_write(childfd, s, numb);
  free(s);
}

void act_output(act_t *act, filter_t *filt) {
  uint8_t *s;
  size_t numb;

  regex_format(filt->regex, act->fmt, &s, &numb);
  debug("act_output %d\n", (int)numb);
  (void)do_write(1, s, numb);
  free(s);
}

bool act_guard(act_t *act, filter_t *filt) {
  /* XXX: optimize, plox: memoize files */
  uint8_t *needle, *haystack, buf[4096];
  char *path;
  size_t szneedle, szhaystack;
  ssize_t numb;
  int fd;
  bool res;

  regex_format(filt->regex, act->guard.fmt, &needle, &szneedle);

  haystack = NULL;
  szhaystack = 0;

  path = filepath(act->guard.path);
  if (-1 == (fd = open(path, O_RDONLY))) {
    debug("act_guard could not open file \"%s\"\n", act->guard.path);
    res = false;
    goto EXIT;
  }

  for (;;) {
    numb = read(fd, buf, sizeof(buf));
    if (numb == 0) {
      close(fd);
      break;
    } else if (numb == -1) {
      if (EINTR == errno) {
        continue;
      } else {
        close(fd);
        res = false;
        goto EXIT;
      }
    }
    haystack = realloc(haystack, szhaystack + numb);
    memcpy(&haystack[szhaystack], buf, numb);
    szhaystack += numb;
  }

  debug("act_guard read %d bytes\n", (int)szhaystack);

  if (memmem(haystack, szhaystack, needle, szneedle)) {
    debug("act_guard match\n");
    res = !act->guard.whitelist;
  } else {
    debug("act_guard no match\n");
    res = act->guard.whitelist;
  }

 EXIT:
  close(fd);
  free(path);
  return res;
}

void run_actions(filter_t *filt, filter_t **filters) {
  int i;
  act_t *act;

  for (i = 0; i < filt->num_acts; i++) {
    act = &filt->acts[i];
    switch (act->kind) {
    case  ACT_HANG:
      debug("run_actions: HANG\n");
      do_log_str("hung");
      act_hang();
      break;
    case  ACT_KILL:
      debug("run_actions: KILL\n");
      do_log_str("killed");
      act_kill();
      break;
    case  ACT_FLUSH_BOTH:
      debug("run_actions: FLUSH_BOTH\n");
      act_flush_both();
      break;
    case  ACT_FLUSH_INPUT:
      debug("run_actions: FLUSH_INPUT\n");
      act_flush_input();
      break;
    case  ACT_FLUSH_OUTPUT:
      debug("run_actions: FLUSH_OUTPUT\n");
      act_flush_output();
      break;
    case  ACT_PATCH:
      debug("run_actions: PATCH\n");
      act_patch(act, filt, filters);
      break;
    case  ACT_PATCH_FILE:
      debug("run_actions: PATCH_FILE\n");
      act_patch_file(act, filt, filters);
      break;
    case  ACT_EXEC:
      debug("run_actions: EXEC\n");
      act_exec(act->exec);
      break;
    case  ACT_LOG:
      debug("run_actions: LOG\n");
      act_log(act, filt);
      break;
    case  ACT_INPUT:
      debug("run_actions: INPUT\n");
      act_input(act, filt);
      break;
    case  ACT_OUTPUT:
      debug("run_actions: OUTPUT\n");
      act_output(act, filt);
      break;
    case  ACT_GUARD:
      debug("run_actions: GUARD\n");
      if (!act_guard(act, filt)) {
        return;
      }
      break;
    }
  }
}

void run_filters(filter_t *filters[]) {
  filter_t *filt;
  int i;
  bool again;

  do {
    again = false;
    for (i = 0; (filt = filters[i]); i++) {
      if (filter_run(filt)) {
        again = true;
        run_actions(filt, filters);
      }
    }
  } while (again);
}

/* void do_release(fifo_t *fifo, int fd, size_t numb) { */
/*   uint8_t buf[4096]; */
/*   size_t i; */

/*   while */
/* } */

void try_release(filter_t *filters[], fifo_t *fifo, int fd) {
  size_t offset, tmp, i, numb;
  filter_t *filt;
  uint8_t c, buf[4096];

  debug("try_release filters = %p, fifo = %p, fd = %d\n", filters, fifo, fd);

  if (filters[0]) {
    offset = filter_get_offset(filters[0]);
    for (i = 1; (filt = filters[i]); i++) {
      tmp = filter_get_offset(filt);
      if (tmp < offset) {
        offset = tmp;
      }
    }

    if (offset) {
      for (i = 0; (filt = filters[i]); i++) {
        filter_dec_offset(filt, offset);
      }
      /* for (i = 0; i < offset; i++) { */
      /*   fifo_pop(fifo, &c); */
      /*   debug("try_release release %c\n", c); */
      /*   writec(fd, c); */
      /* } */
    }
  } else {
    /* fifo_flush(fifo, fd); */
    offset = fifo_size(fifo);
  }

  if (option_drip) {
    for (i = 0; i < offset; i++) {
      fifo_pop(fifo, &c);
      debug("try_release: drip %c\n", c);
      writec(fd, c);
    }
  } else {
    while (offset) {
      if (offset > sizeof(buf)) {
        numb = fifo_pop_buf(fifo, buf, sizeof(buf));
      } else {
        numb = fifo_pop_buf(fifo, buf, offset);
      }
      debug("try_release: write %d bytes\n", numb);
      do_write(fd, buf, numb);
      offset -= numb;
    }
  }
}

void force_release(filter_t *filters[], fifo_t *fifo, int fd) {
  filter_t *filt;
  int i;
  bool again;

  for (i = 0; (filt = filters[i]); i++) {
    if (filter_force_release(filt)) {
      again = true;
      run_actions(filt, filters);
    }
  }

  while (again) {
    again = false;
    for (i = 0; (filt = filters[i]); i++) {
      if (filter_run(filt)) {
        again = true;
        run_actions(filt, filters);
      }
    }
  }

  try_release(filters, fifo, fd);
}

char *expand_env(char *v) {
  size_t len;
  char *vout;

  len = strlen(v);
  if (('$' == v[0] && '(' == v[1] && ')' == v[len - 1]) ||
      ('`' == v[0] && '`' == v[len - 1])
      ) {
    if ('$' == v[0]) {
      v += 2;
      len -= 3;
    } else {
      v += 1;
      len -= 2;
    }
    v = strdup(v);
    v[len] = 0;
    vout = subprocess(v);
    free(v);
  } else {
    vout = strdup(v);
  }
  len = strlen(vout);
  /* strip trailing newlines */
  while (len && '\n' == vout[len - 1]) {
    len--;
    vout[len] = 0;
  }
  return vout;
}

void init_env() {
  int i;
  bool more;
  char *k, *v, *path, *preload, *cur, *end;
  size_t len, sz, szcur, szpath;

  for (i = 0; option_env[i]; i += 2) {
    k = option_env[i];
    v = option_env[i + 1];
    if (strcmp("LD_PRELOAD", k) == 0) {
      /* may be a colon separated list; expand each part */
      /* first copy to writable memory */
      v = strdup(v);
      len = 1024;
      sz = 0;
      preload = calloc(len, 1);
      for (more = true; more;) {
        cur = v;
        end = strchr(cur, ':');
        if (NULL == end) {
          more = false;
          end = cur + strlen(cur);
        }
        szcur = end - cur;
        cur[szcur] = 0;

        cur = expand_env(cur);
        path = filepath(cur);
        free(cur);
        szpath = strlen(path);
        /* invariant: there's always room for at least one more byte */
        if (sz) {
          preload[sz] = ':';
          sz++;
        }
        if (sz + szpath >= len) {
          len *= 2;
          preload = realloc(preload, len);
        }
        memcpy(&preload[sz], path, szpath);
        sz += szpath;
        free(path);

        /* go to next */
        v = end + 1;
      }
      preload[sz] = 0;
      setenv(k, preload, 1);
      free(preload);

    } else if (strcmp("LD_LIBRARY_PATH", k) == 0) {
      v = expand_env(v);
      path = filepath(v);
      setenv(k, path, 1);
      free(v);
      free(path);

    } else {
      v = expand_env(v);
      setenv(k, v, 1);
      free(v);
    }
  }
}

void run(int fd[2]) {
  filter_t *filt;
  int i, retval, devzero, fdcur, fdmax, fdnum;
  uint8_t buf[4096];
  fd_set rfds;
  struct timeval tv;
  char *argv[2];
  struct rlimit rlim;
  bool is_shutdown;

  if (0 == (childpid = fork())) {
    /* spawn child */

    /* target program */
    argv[0] = filepath(option_target);
    argv[1] = NULL;
    for (i = 0; i < 3; i++) {
      dup2(fd[1], i);
    }
    close(fd[0]);

    /* set alarm? */
    if (option_alarm != -1) {
      alarm(option_alarm);
    }

    /* set rlimits? */
    if (option_rlimit_nproc != -1) {
      rlim.rlim_cur = option_rlimit_nproc;
      rlim.rlim_max = option_rlimit_nproc;
      setrlimit(RLIMIT_NPROC, &rlim);
    }
    if (option_rlimit_cpu != -1) {
      rlim.rlim_cur = option_rlimit_cpu;
      rlim.rlim_max = option_rlimit_cpu;
      setrlimit(RLIMIT_CPU, &rlim);
    }

    /* switch group? */
    if (option_gid != -1) {
      /* unused return value -- just make gcc happy */
      retval = setresgid(option_gid, option_gid, option_gid);
      /* drop all supplementary groups */
      setgroups(1, (gid_t *)&option_gid);
    }

    /* switch user? */
    if (option_uid != -1) {
      /* unused return value -- just make gcc happy */
      retval = setresuid(option_uid, option_uid, option_uid);
    }

    /* set env */
    init_env();

    /* randomize fds? */
    if (option_random_fds) {
      /* we dup(2) /dev/zero onto ALL THE FDS, then close a bunch at random */
      devzero = open("/dev/zero", O_RDWR);
      if (devzero) {
        fdnum = option_random_fds_amount;
        fdmax = devzero;
        /* close fds and uptate fdmax as we go */
        while (-1 != (fdcur = dup(devzero))) fdmax = fdcur;
        /* only touch fds >=50 */
        if (fdnum > fdmax - 50) {
          fdnum = fdmax - 50;
        }
        /* if we need to free up many fds put a bunch up high so we have lots of */
        /* entropy left */
        if (fdnum > 10) {
          for (i = 0; i < fdnum - 10; i++, fdmax--) {
            close(fdmax);
          }
        }
        /* now free up a few fds at random -- these will be hard to guess and */
        /* hopefully the ones that the attacker needs */
        srandom(time(NULL) + getpid());
        for (i = 0; i < 10 && i < fdnum;) {
          if (-1 != close(50 + (random() % (fdmax - 50)))) i++;
        }
      }
    }

    /* go, go gadget! */
    execv(argv[0], argv);
    _exit(1);
  }

  close(fd[1]);
  childfd = fd[0];
  if ((pid_t)-1 == childpid) {
    act_kill();
  }

  /* initialize fifos and filters */
  fifo_init(&ififo);
  for (i = 0; (filt = ifilters[i]); i++) {
    filter_init(filt, &ififo);
  }
  fifo_init(&ofifo);
  for (i = 0; (filt = ofilters[i]); i++) {
    filter_init(filt, &ofifo);
  }

  is_shutdown = false;

  for (;;) {
    FD_ZERO(&rfds);
    if (!is_shutdown) {
      FD_SET(0, &rfds);
    }
    FD_SET(childfd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = option_timeout;

    retval = select(childfd + 1, &rfds, NULL, NULL, &tv);

    if (retval == -1) {
      if (EINTR == errno) {
        continue;
      } else {
        break;
      }
    } else if (!retval) {
      debug("timeout: try release\n");
      if (!fifo_empty(&ififo)) {
        force_release(ifilters, &ififo, childfd);
      } else {
        force_release(ofilters, &ofifo, 1);
      }
      continue;
    }

    if (FD_ISSET(0, &rfds)) {
      retval = do_read(0, buf, sizeof(buf));
      if (retval == 0) {
        is_shutdown = true;
        if (option_kill_on_shutdown) {
          break;
        }
        while (!fifo_empty(&ififo)) {
          force_release(ifilters, &ififo, childfd);
        }
        shutdown(childfd, SHUT_WR);
        goto NEXT;
      } else if (retval == -1) {
        break;
      }

      fifo_push_buf(&ififo, buf, retval);
      debug("ififo\n");
      fifo_debug(&ififo);

      run_filters(ifilters);
      try_release(ifilters, &ififo, childfd);
    }

  NEXT:
    if (FD_ISSET(childfd, &rfds)) {
      retval = do_read(childfd, buf, sizeof(buf));
      if (0 >= retval) {
        while (!fifo_empty(&ofifo)) {
          force_release(ofilters, &ofifo, 1);
        }
        break;
      }

      fifo_push_buf(&ofifo, buf, retval);
      debug("ofifo\n");
      fifo_debug(&ofifo);

      run_filters(ofilters);
      try_release(ofilters, &ofifo, 1);
    }
  }

  act_kill();
  _exit(0);
}

int main (int argc, char *argv[]) {
  int fd[2];

  (void)argc;
  (void)argv;

  if (dsockpair(fd)) {
    debug("dsockpair failed, using socketpair\n");
    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd)) {
      perror("socketpair");
    }
  }

  run(fd);

  return 0;
}
