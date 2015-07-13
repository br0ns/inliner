#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <netdb.h>
#include <sysexits.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#ifdef USE_IDSA
#include <idsa_internal.h>

/* The below requires idsa-0.93.8 or newer */
/* linetd uses both the IDSA_SSM and IDSA_ES schemes */
#include <idsa_schemes.h>

/* names defined for the linetd scheme */

#define LINET_EU   "error-usage"
#define LINET_ES   "error-system"
#define LINET_EI   "error-init"

#define LINET_EF   "error-fork"
#define LINET_CC   "client-connect"

#define LINET_DR   "daemon-ready"
#define LINET_DE   "daemon-exit"

#define LINET_JD   "job-done"
#define LINET_JE   "job-error"
#define LINET_JS   "job-signal"

#endif

#define LINETD   "linetd"
#define LINET_SCHEME  LINETD
#define LINET_SERVICE LINETD

#define LINET_TCP   "tcp"
#define LINET_USAGE    1
#define LINET_SYSTEM   2
#define LINET_BUFFER 512
#define LINET_SLEEP    5
#define LINET_MAXRES  16
#define LINET_READBUF 32

#define LOADAVG "/proc/loadavg"

#ifndef VERSION
#define VERSION "unknown"
#endif

volatile int run = 1;
volatile int zombies = 0;
int child_count = 0;
int load_fd = (-1);

int resource_table[LINET_MAXRES][2];
int resource_count = 0;

#ifdef USE_IDSA
IDSA_CONNECTION *ic = NULL;
#endif

static void handle_child(int s)
{
  zombies = 1;
}

static void handle_stop(int s)
{
  run = 0;
}

static double get_load()
{
  char buffer[LINET_READBUF];

  if(lseek(load_fd,0,SEEK_SET)){
    return 0.0;
  }

  if(read(load_fd,buffer,LINET_READBUF) <= 0){
    return 0.0;
  }

  buffer[LINET_READBUF-1] = '\0';

  return atof(buffer);
}

static void fatal_failure(int type, int error, char *message, ...)
{
  va_list args;
  char buffer[LINET_BUFFER];
  int exitcode;

  exitcode = EX_UNAVAILABLE;

#ifdef USE_IDSA
  if (ic == NULL) {
    ic = idsa_open(LINET_SERVICE, NULL, 0);
  }
#endif

  va_start(args, message);
  vsnprintf(buffer, LINET_BUFFER - 1, message, args);
  buffer[LINET_BUFFER - 1] = '\0';
  va_end(args);

  switch (type) {
  case LINET_USAGE:
#ifdef USE_IDSA
    idsa_set(ic, LINET_EU, LINET_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, 
        IDSA_SSM,  IDSA_T_STRING, IDSA_SSM_SFAIL, 
        IDSA_ES,   IDSA_T_STRING, IDSA_ES_USAGE, 
        "comment", IDSA_T_STRING, buffer, 
        NULL);
#endif
    fprintf(stderr, "%s: %s\n", LINETD, buffer);
    exitcode = EX_USAGE;
    break;
  case LINET_SYSTEM:
#ifdef USE_IDSA
    idsa_set(ic, LINET_ES, LINET_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, 
        IDSA_SSM,  IDSA_T_STRING, IDSA_SSM_SFAIL, 
        IDSA_ES,   IDSA_T_STRING, IDSA_ES_SYSTEM, 
        "comment", IDSA_T_STRING, buffer,
        "code",    IDSA_T_ERRNO, &error, 
        NULL);
#endif
    fprintf(stderr, "%s: %s: %s\n", LINETD, buffer, strerror(error));
    exitcode = EX_OSERR;
    break;
  }

#ifdef USE_IDSA
  if (ic) {
    idsa_close(ic);
    ic = NULL;
  }
#endif

  exit(exitcode);
}

static void fork_parent(char *name)
{
  int p[2];
  pid_t pid;
  char buffer[LINET_BUFFER];
  /* int kfd, maxfd; */
  int rr, status, result;

  if (pipe(p)) {
    fatal_failure(LINET_SYSTEM, errno, "unable to create pipe");
  }

  fflush(stderr);

  pid = fork();
  switch (pid) {
  case -1:
    fatal_failure(LINET_SYSTEM, errno, "unable to fork");
    break;
  case 0:			/* in child - make pipe stderr and detach from terminal */
    close(p[0]);
    if (dup2(p[1], STDERR_FILENO) != STDERR_FILENO) {
      fatal_failure(LINET_SYSTEM, errno, "unable to duplicate stdandard error file descriptor");
    }
    close(p[1]);
    close(STDOUT_FILENO);
    close(STDIN_FILENO);

    /* ugly, double edged sword */
    /*
    maxfd = getdtablesize();
    for (kfd = STDERR_FILENO + 1; kfd < maxfd; kfd++) {
      close(kfd);
    } 
    */

    setsid();
    break;
  default:			/* in parent - read from pipe, exit when pipe closes */
    close(p[1]);

    do {
      rr = read(p[0], buffer, LINET_BUFFER);
      switch (rr) {
      case -1:
	switch (errno) {
	case EAGAIN:
	case EINTR:
	  rr = 1;
	  break;
	default:
	  fprintf(stderr, "%s: unable to read child messages: %s\n", name, strerror(errno));
	  fflush(stderr);
	  break;
	}
	break;
      case 0:
	/* eof */
	break;
      default:
	write(STDERR_FILENO, buffer, rr);
	/* don't care if write fails, can't do anything about it */
	break;
      }
    } while (rr > 0);

    sched_yield();
    result = 0;

    if (waitpid(pid, &status, WNOHANG) > 0) {	/* got a child */
      result = EX_SOFTWARE;
      if (WIFEXITED(status)) {
	result = WEXITSTATUS(status);
	snprintf(buffer, LINET_BUFFER, "exited with code %d", result);
      } else if (WIFSIGNALED(status)) {
	snprintf(buffer, LINET_BUFFER, "killed by signal %d\n", WTERMSIG(status));
      } else {
	snprintf(buffer, LINET_BUFFER, "unknown exit condition");
      }

      buffer[LINET_BUFFER - 1] = '\0';
#ifdef USE_IDSA
      idsa_set(ic, LINET_EI, LINET_SCHEME, 0, IDSA_R_PARTIAL, IDSA_R_UNKNOWN, IDSA_R_PARTIAL, 
          IDSA_SSM,  IDSA_T_STRING, IDSA_SSM_SFAIL, 
          IDSA_ES,   IDSA_T_STRING, IDSA_ES_OTHER, 
          "comment", IDSA_T_STRING, buffer, 
          NULL);
#endif
      fprintf(stderr, "%s: %s\n", LINETD, buffer);
      fflush(stderr);
    }
    /* else child probably ok */
    exit(result);

    break;
  }
}

static void drop_root(char *name, char *user, char *group, char *root)
{
  uid_t uid = 0;
  gid_t gid = 0;
  struct passwd *pw;
  struct group *gr;

  if (user) {
    uid = atoi(user);
    if (uid == 0) {
      pw = getpwnam(user);
      if (pw == NULL) {
	fatal_failure(LINET_SYSTEM, errno, "unable to find user %s", user);
      } else {
	uid = pw->pw_uid;
	gid = pw->pw_gid;
      }
    }
  }

  if (group) {
    gid = atoi(group);
    if (gid == 0) {
      gr = getgrnam(group);
      if (gr == NULL) {
	fatal_failure(LINET_SYSTEM, errno, "unable to find group %s", group);
      } else {
	gid = gr->gr_gid;
      }
    }
  }

  if (root != NULL) {
    if (chroot(root)) {
      fatal_failure(LINET_SYSTEM, errno, "unable to change root directory to %s", root);
    }
  }
  chdir("/");

  if(getuid() == 0){
    if(setgroups(0,NULL)){
      fatal_failure(LINET_SYSTEM, errno, "unable to delete supplementary groups");
    }
  }

  if (group || user) {
    if (setgid(gid)) {
      fatal_failure(LINET_SYSTEM, errno, "unable to change gid to %lu", (unsigned long) gid);
    }
  }

  if (user) {			/* now change id */
    if (setuid(uid)) {
      fatal_failure(LINET_SYSTEM, errno, "unable to change uid to %lu", (unsigned long) uid);
    }
  }
}

static void usage(char *name)
{
  printf(
    "Usage: %s "
    "[-a[k|r]] [-b address] [-c] [-d] [-f] [-g group] [-h] [-i instances] [-j count] " 
#ifdef USE_IDSA
    "[-k[a|c|i] risk] "
#endif
    "[-l load] [-m timeout] [-n nice] [-o[c|d|r|t]] -p port [-q backlog] [-r directory] [-s[c|d|f|l|m|n|s|t|u|v] limit] [-t ttl] [-u user] [-v] "
#ifdef USE_IDSA
    "[-x[e|o|u]] "
#endif
    "path [options ...]\n\n", name);

  printf("Options:\n"
    "-a[k|r]       disable k)eepalive or address r)euse socket option\n"
    "-b address    bind a particular address instead of all available ones\n"
    "-c            copyright notice\n"
    "-d            disable sanity checks\n"
    "-f            do not fork into the background\n"
    "-g gid        run with group id\n"
    "-h            this help\n"
    "-i integer    maximum number of child processes to run concurrently\n"
    "-j integer    just run specified number of child processes, then exit\n"
#ifdef USE_IDSA
    "-k? risk      risk values: a)vailability, c)onfidentiality, i)ntegrity\n"
#endif
    "-l double     load average above which service is disabled\n"
    "-m timeout    schedule an alarm signal for each child\n"
    "-n level      run at reduced priority\n"
    "-o?           type of service [tos]: optimal d)elay, r)eliability or t)hroughput\n"
    "-p port       local port to listen on\n"
    "-q backlog    number of connections queued in listen\n"
    "-r directory  chroot into directory\n"
    "-s? value     resource limit set for child\n"
    "-t integer    time to live [ttl] counter\n"
    "-u uid        run with user id\n"
    "-v            print version and exit\n"
#ifdef USE_IDSA
    "-x?           enable flag: honour e)nvironment variable IDSA_SOCKET, fail o)pen, allow u)ploading of rules\n"
#endif
    "\n"
  );

  printf("Note: The -p option is mandatory\n\n");

  printf("Examples:\n");

  printf("\n%s -u nobody -or -i 5 -m 5 -p finger /usr/sbin/in.fingerd in.fingerd -l\n", name);
  printf(
    "  Run fingerd as nobody.\n"
    "  Maximize reliability of the TCP/IP connection.\n"
    "  Start at most 5 fingerd instances.\n"
    "  Send a SIG_ALARM to each process after 5 seconds.\n"
  );

  printf("\n%s -u nobody -p 2300 -t 1 /usr/bin/tail tail /var/log/apache/access_log\n", name);
  printf(
    "  Display the last lines of a log file to those connecting on port 2300.\n"
    "  Set TTL to 1 which makes it inaccessible to users outside the subnet.\n"
  );

#ifdef USE_IDSA
  printf("\nIDSA_SOCKET=/tmp/idsa %s -i1 -unobody -n5 -l2.0 -m10 -su0 -sm4096 -xexo -kc0.7/0.3 -ki0.2/0.3 -pnetstat /bin/netstat netstat -tn\n", name);
  printf(
    "  Run at most one instance of netstat as nobody at nice level 5.\n"
    "  Stop this service if the system load is greater than 2.0.\n"
    "  Schedule a SIG_ALARM if netstat hasn't completed after 10 seconds.\n"
    "  Do not allow netstat to spawn a subprocess or occupy more than 4096k of RAM.\n"
    "  Connect to idsad listening on socket /tmp/idsa but continue if no idsad is available.\n"
    "  Reporting each new connection as having a high (0.7) risk to confidentiality but a low (0.2) risk to integrity.\n"
  );
#endif
}

static int setup_listener(char *name, char *port, char *interface, int queue, int ttl, int tos, int reuse, int keepalive)
{
  int fd;
  struct sockaddr_in addr;
  int addrlen;
  int prt;
  struct hostent *hst;
  struct servent *srv;

  addr.sin_family = AF_INET;

  if (port == NULL) {
    fatal_failure(LINET_USAGE, 0, "require a port to bind (-p port)");
  }
  prt = atoi(port);
  if (prt == 0) {
    srv = getservbyname(port, LINET_TCP);
    if (srv == NULL) {
      fatal_failure(LINET_USAGE, 0, "could not convert %s to a nonzero number", port);
    }
    addr.sin_port = srv->s_port;
  } else {
    addr.sin_port = htons(prt);
  }

  if (interface) {
    if (inet_aton(interface, &(addr.sin_addr)) == 0) {
      hst = gethostbyname(interface);
      if (hst == NULL) {
	fatal_failure(LINET_USAGE, 0, "could not convert %s to an address", interface);
      }
      if (hst->h_addrtype != AF_INET) {
	fatal_failure(LINET_USAGE, 0, "%s does not resolve to an ip4 address", interface);
      }
      addr.sin_addr = *(struct in_addr *) hst->h_addr;
    }
  } else {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    fatal_failure(LINET_SYSTEM, errno, "could not create an internet socket");
  }

  if(reuse){
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(int));
  }

  if(keepalive){
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(int));
  }

  addrlen = sizeof(addr);
  if (bind(fd, (struct sockaddr *) &addr, addrlen) == (-1)) {
    fatal_failure(LINET_SYSTEM, errno, "could not bind an internet socket");
  }

  if (listen(fd, queue) == (-1)) {
    fatal_failure(LINET_SYSTEM, errno, "could not listen on socket");
  }

  if(ttl) {
    if (setsockopt(fd, SOL_IP, IP_TTL, (void *)&ttl, sizeof(int))) {
      fatal_failure(LINET_SYSTEM, errno, "could not set time to live to %d hops", ttl);
    }
  }

  if(tos) {
    if (setsockopt(fd, SOL_IP, IP_TOS, (void *)&tos, sizeof(int))) {
      fatal_failure(LINET_SYSTEM, errno, "could not set type of service to 0x%02x", tos);
    }
  }

  return fd;
}

static int run_command(int lfd, char *cmd, char **vector, int fd, int timeout)
{
  struct sigaction sag;
  sigset_t sst;
  struct rlimit r;
  int i;
#ifdef USE_IDSA
  int error;
#endif

  switch (fork()) {
  case -1:
#ifdef USE_IDSA
    error = errno;
    idsa_set(ic, LINET_EF, LINET_SCHEME, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_PARTIAL, 
        IDSA_SSM,  IDSA_T_STRING, IDSA_SSM_WFAIL, 
        IDSA_ES,   IDSA_T_STRING, IDSA_ES_SYSTEM, 
        "comment", IDSA_T_STRING, "unable to create child process", 
        "code",    IDSA_T_ERRNO, &error, 
        NULL);
#endif
    close(fd);
    return -1;
    break;
  case 0:
    close(lfd);
    if(load_fd >= 0){
      close(load_fd);
    }
#ifdef USE_IDSA
    idsa_close(ic);
#endif

    sag.sa_handler = SIG_DFL;
    sigemptyset(&(sag.sa_mask));
    sag.sa_flags = SA_RESTART;

    /* is this the correct way of resetting signal handlers ? */
    sigaction(SIGCHLD, &sag, NULL);
    sigaction(SIGTERM, &sag, NULL);

    /* I haven't touched these, but it would seem important */
    sigaction(SIGALRM, &sag, NULL);
    sigaction(SIGPIPE, &sag, NULL);

    sigemptyset(&sst);
    sigaddset(&sst, SIGCHLD);
    sigaddset(&sst, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &sst, NULL);	/* enable child signal */

    if ((fd != STDIN_FILENO) && (dup2(fd, STDIN_FILENO) != STDIN_FILENO)) {
      exit(EX_OSERR);
    }
    if ((fd != STDOUT_FILENO)
	&& (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO)) {
      exit(EX_OSERR);
    }
    if ((fd != STDERR_FILENO)
	&& (dup2(fd, STDERR_FILENO) != STDERR_FILENO)) {
      exit(EX_OSERR);
    }
    if (fd > STDERR_FILENO) {
      close(fd);
    }

    for(i = 0; i < resource_count; i++){
      r.rlim_cur = resource_table[i][1];
      r.rlim_max = resource_table[i][1];
      if (setrlimit(resource_table[i][0], &r)) {
        exit(EX_OSERR);
      }
    }

    if (timeout) {
      alarm(timeout);
    }

    execv(cmd, vector);

#ifndef PARANOID
    fprintf(stderr, "unable to run %s: %s\n", vector[0], strerror(errno));
#endif

    exit(EX_UNAVAILABLE);
    break;
  default:
    child_count++;
    close(fd);
    return 0;
    break;
  }
  return 0;
}

#ifdef USE_IDSA
static int accept_connection(int lfd, unsigned ar, unsigned cr, unsigned ir)
#else
static int accept_connection(int lfd)
#endif
{
  struct sockaddr_in addr;
  unsigned int addrlen;
  int nfd;
  sigset_t sst;
#ifdef USE_IDSA
  int len;
  int cp[2], sp[2];
  unsigned long ca, sa;
  int ttl;
  int complete;
  char *reason;
  int one;
#endif

  sigemptyset(&sst);
  sigaddset(&sst, SIGCHLD);
  sigaddset(&sst, SIGTERM);

  addrlen = sizeof(struct sockaddr_in);

  sigprocmask(SIG_UNBLOCK, &sst, NULL);	/* enable child signal */
  nfd = accept(lfd, (struct sockaddr *) &addr, &addrlen);
  sigprocmask(SIG_BLOCK, &sst, NULL);	/* disable child signal */

  if (nfd < 0) {
    return -1;
  }
#ifdef USE_IDSA
  complete = 1;

  cp[0] = IPPROTO_TCP;
  cp[1] = ntohs(addr.sin_port);
  ca = ntohl(addr.sin_addr.s_addr);

  addrlen = sizeof(struct sockaddr_in);
  if (getsockname(nfd, (struct sockaddr *) &addr, &addrlen)) {
    complete = 0;
  }

  sp[0] = IPPROTO_TCP;
  sp[1] = ntohs(addr.sin_port);
  sa = ntohl(addr.sin_addr.s_addr);

  ttl = 0;
  len = sizeof(int);
  if (getsockopt(nfd, SOL_IP, IP_TTL, (void *) &ttl, &len)) {
    complete = 0;
  }

  one = 1;

  if (idsa_set(ic, LINET_CC, LINET_SCHEME, 1, ar, cr, ir, 
        IDSA_SSM,        IDSA_T_STRING, IDSA_SSM_WSTART, 
        "ip4src",        IDSA_T_ADDR, &ca, 
        "portsrc",       IDSA_T_PORT,  cp, 
        "ip4dst",        IDSA_T_ADDR, &sa, 
        "portdst",       IDSA_T_PORT,  sp, 
        "ipttl",         IDSA_T_INT,  &ttl, 
        "complete",      IDSA_T_FLAG, &complete, 
        IDSA_RQ_REQUEST, IDSA_T_INT,  &one,
        IDSA_RQ_USED,    IDSA_T_INT,  &child_count,
        NULL) != IDSA_L_ALLOW) {
    reason = idsa_reason(ic);
    if(reason){
      write(nfd,reason,strlen(reason));
    }
    close(nfd);
    return -1;
  }
#endif

  return nfd;
}

int main(int argc, char **argv)
{
  char *user, *group, *interface, *root, *port, *cmd;
  int niceinc;
  int nofork;
  int timeout;
  int instances;
  int queue;

  int reuse;
  int keepalive;
  int what;
  int value;
  int offset;
  int i, j;
  char c;
  int lfd;
  int nfd;
  struct sigaction sag;
  sigset_t sst;
  int status;
  int hang;
  int busy;
  int tos;
  int ttl;
  int sane;
  int just;
#ifdef USE_IDSA
  int exitcode;
  int killcode;
  int flags;
  unsigned int arisk, crisk, irisk, risk;
#endif

  double limit_load = 0.0;

  port = NULL;
  user = NULL;
  group = NULL;
  root = NULL;
  interface = NULL;
  cmd = NULL;

  just = 0;
  sane = 1;
  reuse = 1;
  keepalive = 1;
  niceinc = 0;
  nofork = 0;
  timeout = 0;
  instances = 0;
  queue = 5;
  tos = 0;
  ttl = 0;
  offset = 0;

#ifdef USE_IDSA
  flags = 0;
  arisk = idsa_risk_make(-0.3,0.8);
  crisk = IDSA_R_UNKNOWN;
  irisk = IDSA_R_PARTIAL;
#endif

  i = j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      c = argv[i][j];
      switch (c) {
      case 'c':
	printf("(c) 2002,2007 Marc Welz: Distributed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':		/* print brief help message */
      case '?':
	usage(argv[0]);
	exit(0);
	break;
      case 'v':
#ifdef USE_IDSA
	printf("linetd %s-i\n", VERSION);
#else
	printf("linetd %s\n", VERSION);
#endif
	exit(0);
	break;

	/* flags */
      case 'f':		/* keep in foreground */
	nofork = 1;
	j++;
	break;
      case 'a' :        /* disable reuse of address */
        j++;
	c = argv[i][j];
	switch (c) {
        case 'r':
          reuse = 0;
          break;
	case 'k':
          keepalive = 0;
          break;
	case '\0':
	  fatal_failure(LINET_USAGE, 0, "option -a requires a modifier");
	  break;
	default:
	  fatal_failure(LINET_USAGE, 0, "unknown modifier -a%c", c);
	  break;
        }

	j++;
	if (argv[i][j] == '\0') {
	  j = 1;
	  i++;
	}

        break;
      case 'd' :        /* disable sanity checks */
        sane = 0;
	j++;
        break;

	/* strings */
      case 'u':
      case 'g':
      case 'p':
      case 'r':
      case 'b':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i >= argc) {
	  fatal_failure(LINET_USAGE, 0, "option -%c requires a parameter", c);
	}
	switch (c) {
	case 'u':
	  user = argv[i] + j;
	  break;
	case 'g':
	  group = argv[i] + j;
	  break;
	case 'p':        
	  port = argv[i] + j;
	  break;
	case 'r':
	  root = argv[i] + j;
	  break;
	case 'b':
	  interface = argv[i] + j;
	  break;
	}
	i++;
	j = 1;
	break;

      case 'l':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i >= argc) {
	  fatal_failure(LINET_USAGE, 0, "option -%c requires a parameter", c);
	}
	if (!isdigit(argv[i][j])) {
	  fatal_failure(LINET_USAGE, 0, "option -%c requires a floating point value", c);
	}
        load_fd = open(LOADAVG, O_RDONLY);
        if(load_fd < 0){
          fatal_failure(LINET_SYSTEM, errno, "unable to open %s to read load average", LOADAVG);
        }
	limit_load = atof(argv[i] + j);
	i++;
	j = 1;
	break;

      case 'n':
      case 'm':
      case 'i':
      case 'j':
      case 'q':
      case 't':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i >= argc) {
	  fatal_failure(LINET_USAGE, 0, "option -%c requires a parameter", c);
	}
	if (!isdigit(argv[i][j])) {
	  fatal_failure(LINET_USAGE, 0, "option -%c requires a numeric value", c);
	}
	value = atoi(argv[i] + j);
	switch (c) {
	case 'n':
	  niceinc = value;
	  break;
	case 'm':
	  timeout = value;
	  break;
	case 'i':
	  instances = value;
	  break;
	case 'j':
	  just = value;
	  break;
	case 'q':
	  queue = value;
	  break;
	case 't':
	  ttl = value;
	  break;
	}
	i++;
	j = 1;
	break;

      case 'o':
        j++;
	c = argv[i][j];
	switch (c) {
        case 'c':
          tos = IPTOS_LOWCOST;
          break;
	case 'd':
          tos = IPTOS_LOWDELAY;
          break;
	case 'r':
          tos = IPTOS_RELIABILITY;
          break;
	case 't':
          tos = IPTOS_THROUGHPUT;
          break;

	case '\0':
	  fatal_failure(LINET_USAGE, 0, "option -o requires a modifier");
	  break;
	default:
	  fatal_failure(LINET_USAGE, 0, "unknown modifier -o%c", c);
	  break;
        }

	j++;
	if (argv[i][j] == '\0') {
	  j = 1;
	  i++;
	}

        break;

#ifdef USE_IDSA
      case 'k' : /* risk ratings */
	j++;
	c = argv[i][j];
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}

	if (i >= argc) {
	  fatal_failure(LINET_USAGE, 0, "option -k%c requires a parameter", c);
	}

        risk = idsa_risk_parse(argv[i]+j);

	switch (c) {
	case 'a':
          arisk = risk;
          break;
	case 'c':
          crisk = risk;
          break;
	case 'i':
          irisk = risk;
          break;
        }
	i++;
	j = 1;
        break;

      case 'x':
        j++;
	c = argv[i][j];
	switch (c) {
        case 'e':
	  flags |= IDSA_F_ENV; /* honour IDSA_SOCKET */
          break;
	case 'o':
	  flags |= IDSA_F_FAILOPEN; /* continue on failure */
          break;
	case 'u':
	  flags |= IDSA_F_UPLOAD; /* allow uploading of rules */
          break;
	case '\0':
	  fatal_failure(LINET_USAGE, 0, "option -x requires a modifier");
	  break;
	default:
	  fatal_failure(LINET_USAGE, 0, "unknown modifier -x%c", c);
	  break;
        }
	j++;
	if (argv[i][j] == '\0') {
	  j = 1;
	  i++;
	}
        break;
#endif

      case 's':
	j++;
	c = argv[i][j];
	what = 0;
	switch (c) {
	case 'c':
	  what = RLIMIT_CORE;
	  break;
	case 'd':
	  what = RLIMIT_DATA;
	  break;
	case 'f':
	  what = RLIMIT_FSIZE;
	  break;
	case 'l':
	  what = RLIMIT_MEMLOCK;
	  break;
	case 'm':
	  what = RLIMIT_RSS;
	  break;
	case 'n':
	  what = RLIMIT_NOFILE;
	  break;
	case 's':
	  what = RLIMIT_STACK;
	  break;
	case 't':
	  what = RLIMIT_CPU;
	  break;
	case 'u':
	  what = RLIMIT_NPROC;
	  break;
	case 'v':
	  what = RLIMIT_AS;
	  break;

	case '\0':
	  fatal_failure(LINET_USAGE, 0, "option -s requires a modifier");
	  break;
	default:
	  fatal_failure(LINET_USAGE, 0, "unknown modifier -s%c", c);
	  break;
	}

	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}

	if (i >= argc) {
	  fatal_failure(LINET_USAGE, 0, "option -s%c requires a parameter", c);
	}
	if (!isdigit(argv[i][j])) {
	  fatal_failure(LINET_USAGE, 0, "option -s%c requires a numeric value", c);
	}
	value = atoi(argv[i] + j);

        if(resource_count >= LINET_MAXRES){
	  fatal_failure(LINET_USAGE, 0, "too many resource restrictions", c);
        }

        resource_table[resource_count][0] = what;
        resource_table[resource_count][1] = value;
        resource_count++;

	i++;
	j = 1;
	break;

      case '-':
	j++;
	break;
      case '\0':
	j = 1;
	i++;
	break;
      default:
	fatal_failure(LINET_USAGE, 0, "unknown option -%c", argv[i][j]);
	break;
      }
    } else {
      cmd = argv[i];
      offset = i + 1;

      if (sane) {
        if (i + 1 >= argc){
          fprintf(stderr, "%s: warning: zeroth argument should be specified\n", argv[0]);
          offset = i;
        }
      }

      i = argc;
    }
  }

  if (cmd == NULL) {
    fatal_failure(LINET_USAGE, 0, "require a command to run");
  }

  if (!nofork) {
    fork_parent(argv[0]);
  }
#ifdef USE_IDSA
  if (ic == NULL) {
    ic = idsa_open(LINETD, NULL, flags);
  }
  if (ic == NULL) {
    fprintf(stderr, "%s: unable to open idsa connection\n", argv[0]);
    exit(EX_UNAVAILABLE);
  }
#endif

  sigfillset(&(sag.sa_mask));
  sag.sa_flags = 0;

  sag.sa_handler = handle_child;
  if (sigaction(SIGCHLD, &sag, NULL)) {
    fatal_failure(LINET_SYSTEM, errno, "unable to set signal handler");
  }

  sag.sa_handler = handle_stop;
  if (sigaction(SIGTERM, &sag, NULL)) {
    fatal_failure(LINET_SYSTEM, errno, "unable to set signal handler");
  }

  lfd = setup_listener(argv[0], port, interface, queue, ttl, tos, reuse, keepalive);

  drop_root(argv[0], user, group, root);

  if(sane){
    if(access(cmd, X_OK)){
      fatal_failure(LINET_SYSTEM, errno, "\"%s\" %s", cmd, (cmd[0] == '/') ? "appears unavailable" : "might need an absolute path");
    }
  }

  if (niceinc) {
    nice(niceinc);
  }

#ifdef USE_IDSA
  if(idsa_set(ic, LINET_DR, LINET_SCHEME, 1, IDSA_R_SUCCESS, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, 
        IDSA_SSM,  IDSA_T_STRING, IDSA_SSM_SSTART, 
        "version", IDSA_T_STRING, VERSION, 
        NULL) != IDSA_L_ALLOW){
    fprintf(stderr, "%s: start disallowed\n", LINETD);
    return EX_NOPERM;
  }
#endif

  if (!nofork) {
    close(STDERR_FILENO);
  }

  sigemptyset(&sst);
  sigaddset(&sst, SIGCHLD);
  sigaddset(&sst, SIGTERM);

  sigprocmask(SIG_BLOCK, &sst, NULL);	/* disable child signal for everything execpt accept and sleep */

  while (run) {
#ifdef USE_IDSA
    nfd = accept_connection(lfd, arisk, crisk, irisk);
#else
    nfd = accept_connection(lfd);
#endif
    if (nfd >= 0) {
      run_command(lfd, cmd, &argv[offset], nfd, timeout);
      if(just){
        just--;
        if(just == 0){
          run = 0;
        }
      }
    }

    do{ /* check children and load */
      busy = 0;
      hang = ((instances > 0) && (child_count >= instances)); /* actually wait for child */

      if (zombies || hang) {
        if (waitpid(WAIT_ANY, &status, hang ? 0 : WNOHANG) > 0) {	/* collect pids without risk of EINTR */
#ifdef USE_IDSA

          /* in theory this could parse signals and exit codes. Eg SIG{SEGV,BUS} == ES_INTERNAL etc */

          if (WIFEXITED(status)) {
            exitcode = WEXITSTATUS(status);
            if (exitcode == 0) {
              idsa_set(ic, LINET_JD, LINET_SCHEME, 0, IDSA_R_NONE, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, 
                  IDSA_SSM, IDSA_T_STRING, IDSA_SSM_WSTOP, 
                  NULL);
            } else {
              idsa_set(ic, LINET_JE, LINET_SCHEME, 0, IDSA_R_PARTIAL, IDSA_R_UNKNOWN, IDSA_R_PARTIAL, 
                  IDSA_SSM, IDSA_T_STRING, IDSA_SSM_WFAIL, 
                  IDSA_ES,  IDSA_T_STRING, IDSA_ES_OTHER, 
                  "exit",   IDSA_T_INT, &exitcode, 
                  NULL);
            }
          } else if (WIFSIGNALED(status)) {
            killcode = WTERMSIG(status);
            idsa_set(ic, LINET_JS, LINET_SCHEME, 0, IDSA_R_PARTIAL, IDSA_R_UNKNOWN, IDSA_R_PARTIAL,
                IDSA_SSM, IDSA_T_STRING, IDSA_SSM_WFAIL, 
                IDSA_ES,  IDSA_T_STRING, IDSA_ES_OTHER, 
                "signal", IDSA_T_INT, &killcode,
                NULL);
          }
#endif
          child_count--;
          busy = ! hang; 
        } else { /* nothing more to collect */
          zombies = 0;
        }
      }

      if((load_fd >= 0) && (zombies == 0)){ /* if zombies then loop will run again, defer load check */
        if(get_load() > limit_load){ /* go to sleep if overloaded */
          sigprocmask(SIG_UNBLOCK, &sst, NULL);	/* enable child|term signal */
          sleep(LINET_SLEEP);
          sigprocmask(SIG_BLOCK, &sst, NULL);	/* disable child|term signal */
          busy = run;
        }
      }
    } while (busy); /* end of child and delay loop */
  } /* end of main loop */

  if(lfd >= 0){
    close(lfd);
  }
  if(load_fd >= 0){
    close(load_fd);
  }

#ifdef USE_IDSA
  idsa_set(ic, LINET_DE, LINET_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, 
      IDSA_SSM,  IDSA_T_STRING, IDSA_SSM_SSTOP, 
      "version", IDSA_T_STRING, VERSION, 
      NULL);
  idsa_close(ic);
#endif

  return 0;
}
