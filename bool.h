#ifndef __BOOL_H
#define __BOOL_H

#if __STDC_VERSION__ >= 199901L
/* C99 code */
#include <stdbool.h>
#else
/* Not C99 code */
typedef enum {false, true} bool;
#endif

#endif
