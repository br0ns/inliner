# A small and fast one process per port inetd replacement for TCP/IPv4
# --------------------------------------------------------------------
# 
# Instead of having a line like this in inetd.conf
# 
#   finger stream tcp nowait nobody /usr/sbin/tcpd /usr/sbin/in.fingerd
# 
# Run the command below. Note that linetd will also change its uid
# 
#   linetd -p finger -u nobody /usr/sbin/in.fingerd in.fingerd
# 
# To bind only the localhost address and limit the number of children 
# to 5 at a time
# 
#   linetd -p finger -i 5 -b localhost -u nobody /usr/sbin/in.fingerd in.fingerd
# 
# To stop linetd use fuser
#
#   fuser -n tcp -s -k -TERM finger
#
# To see all the other switches and more examples type
#
#   linetd -h
# 
# Linetd can idsa for access control and logging, but this is optional.
# Idsa can be downloaded from http://jade.cs.uct.ac.za/idsa/ 
# You will need version 0.93.8 or newer

linetd: linetd.c
	gcc -s -Wall -O2 -fomit-frame-pointer -DVERSION=\"1.4\" $(shell which idsalog > /dev/null && echo "-DUSE_IDSA -lidsa") linetd.c -o linetd

install: linetd
	install -D linetd /usr/local/sbin/linetd 
	install -D linetd.8 /usr/local/man/man8/linetd.8

# auto{make,conf} is overkill. I believe in readable makefiles ;)
