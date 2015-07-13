#ifndef __DEBUG_H
#define __DEBUG_H

#ifdef DEBUG
#include <stdio.h>
#define debug(...)                              \
  do {                                          \
    printf(__VA_ARGS__);                        \
    fflush(stdout);                             \
  } while (0)
#else
#define debug(...)
#endif

#endif
