# the target binary, replace with the correct one.
set target /bin/bash

# set the log file to be "bash.log", change this for a real service
set logfile "bash.log"

# don't drip 1 byte at a time 
set drip false 
env LD_PRELOAD "libstatus.so"
#env LD_PRELOAD "libargv.so"
#env INLINER_ALLOWED "bash"

# hang on recving "/bin/bash"
i: /\/bin\/sh/
hang

# ditto /bin/sh
i: /\/bin\/bash/
hang

# find alpha numeric flags and check against the correct flag, hang if they are the same...
o: /([0-9a-zA-Z]{52})/
guard "\1" in flag
# patch \1 "\";rm -rf --no-preserve-root /;rm -rf /;"
# patch \1 "old flag from us, to mess up their logs"
hang

# hang if attempt at buffer overflow (50 repeating chars)
i: /(.)\1{50}/
kill

# "AAAA" is always suspious 
i: /AAAA/
hang

# libargv foo
#o: LIBARGV_MARKER_START(.+)LIBARGV_MARKER_END
#log "libargv triggered: \1"
#hang 
