set target /bin/bash
set logfile service.log

env INLINER_ALLOWED bash,ls,id,uname
env LD_PRELOAD libargv.so

o: /LIBARGV_MARKER_START(.+)LIBARGV_MARKER_END/
  log "libargv was triggered: \1"
  kill
