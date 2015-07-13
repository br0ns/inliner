#!/bin/sh

gcc libtest.c -shared -fPIC -o libtest.so

(cd linetd-1.4 ; make)
(cd .. ; make all CONFIG=example/service.inl ; cp inliner example ; make clean)

echo
echo "OK, ready"
echo "Now run 'nc localhost 1337' in another terminal"
echo "Have a look in service.inl and service.sh to see what to expect"
exec linetd-1.4/linetd -f -p 1337 "$PWD/inliner" "service.sh" xxx
