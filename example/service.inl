set target service.sh
set logfile service.log
set timeout 1000000 # 1 second

env LD_PRELOAD libtest.so
# Uncomment this line to see the output from libstatus
# env LD_PRELOAD ../libstatus/libstatus.so

i: /dog|bird|cat|giraffe/ log "I saw a \0!"
i: /(.)\1{50}/
 log "no overflow, plox"
 kill

i: /do (\S+)/
 guard "\1" not in whitelist
 hang

# This is a comment

o: /GOLD_(.{32})_END/
 patch \1 "nopenopenope"

o: /magic: (\d+)/
 output "noooo\n"
 guard "\1" in magic
 log "they found the magic number :'("
