#!/bin/sh

gcc libtest0.c -shared -fPIC -o libtest0.so
gcc libtest1.c -shared -fPIC -o libtest1.so
gcc libtest2.c -shared -fPIC -o libtest2.so
gcc libtest3.c -shared -fPIC -o libtest3.so
gcc libtest4.c -shared -fPIC -o libtest4.so
gcc libtest5.c -shared -fPIC -o libtest5.so
gcc libtest6.c -shared -fPIC -o libtest6.so
gcc libtest7.c -shared -fPIC -o libtest7.so
gcc libtest8.c -shared -fPIC -o libtest8.so
gcc libtest9.c -shared -fPIC -o libtest9.so

(cd .. ; make CONFIG=example4/service.inl ; cp inliner example4 ; make clean)

echo "run './inliner'"
