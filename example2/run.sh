#!/bin/sh

gcc service.c -o service
gcc libtest1.c -shared -fPIC -o libtest1.so
gcc libtest2.c -shared -fPIC -o libtest2.so

(cd .. ; make CONFIG=example2/service.inl ; cp inliner example2 ; make clean)

echo "run './inliner'"
