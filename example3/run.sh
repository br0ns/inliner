#!/bin/sh

gcc libargv.c -shared -fPIC -o libargv.so

# (cd .. ; make DEBUG=1 CONFIG=example3/service.inl ; cp inliner example3 ; make clean)
(cd .. ; make CONFIG=example3/service.inl ; cp inliner example3 ; make clean)

echo "run './inliner'"
