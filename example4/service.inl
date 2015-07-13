set target /bin/bash

# need a qualified path here because of a limitation in inliner
env LD_PRELOAD $(ls *.so | sort -R | head -n 1)
