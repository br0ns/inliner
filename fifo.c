#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "fifo.h"

#include "debug.h"

#define INIT_SIZE 256

#define SIZE(fifo) \
  ((fifo)->q < (fifo)->p ?                      \
   (fifo)->q - (fifo)->p + (fifo)-> len :       \
   (fifo)->q - (fifo)->p                        \
   )

int fifo_init(fifo_t *fifo) {
  fifo->p = 0;
  fifo->q = 0;
  fifo->len = INIT_SIZE;
  fifo->buf = malloc(fifo->len);
  if (!fifo->buf) {
    errno = ENOMEM;
    return -1;
  }
  return 0;
}

void fifo_push(fifo_t *fifo, uint8_t c) {
  size_t oldlen;
  if (SIZE(fifo) + 1 >= fifo->len) {
    oldlen = fifo->len;
    fifo->len *= 2;
    fifo->buf = realloc(fifo->buf, fifo->len);
    if (fifo->q < fifo->p) {
      memcpy(&fifo->buf[oldlen], fifo->buf, fifo->q);
      fifo->q += oldlen;
    }
  }
  fifo->buf[fifo->q++] = c;
  if (fifo->q >= fifo->len) {
    fifo->q = 0;
  }
}

void fifo_push_buf(fifo_t *fifo, uint8_t *buf, size_t numb) {
  size_t i;

  for (i = 0; i < numb; i++) {
    fifo_push(fifo, buf[i]);
  }
}

int fifo_pop(fifo_t *fifo, uint8_t *c) {
  if (SIZE(fifo) == 0) {
    return -1;
  }
  if (c) {
    *c = fifo->buf[fifo->p++];
  }
  if (fifo->p >= fifo->len) {
    fifo->p = 0;
  }
  return 0;
}

int fifo_pop_buf(fifo_t *fifo, uint8_t *buf, size_t numb) {
  size_t i;

  for (i = 0; i < numb && fifo_pop(fifo, &buf[i]) == 0; i++);

  return i;
}

uint8_t fifo_get(fifo_t *fifo, int pos) {
  size_t i;
  i = fifo->p + pos;
  if (i >= fifo->len) {
    i -= fifo->len;
  }
  return fifo->buf[i];
}

void fifo_resize(fifo_t *fifo, size_t size) {
  size_t oldlen;
  if (size >= fifo->len) {
    oldlen = fifo->len;
    do {
      fifo->len *= 2;
    } while (size >= fifo->len);
    fifo->buf = realloc(fifo->buf, fifo->len);
    if (fifo->q < fifo->p) {
      memcpy(&fifo->buf[oldlen], fifo->buf, fifo->q);
      fifo->q += oldlen;
    }
  }
  fifo->q = fifo->p + size;
  if (fifo->q > fifo->len) {
    fifo->q -= fifo->len;
  }
}

void fifo_set(fifo_t *fifo, int pos, uint8_t c) {
  size_t i;
  i = fifo->p + pos;
  if (i >= fifo->len) {
    i -= fifo->len;
  }
  fifo->buf[i] = c;
}

size_t fifo_size(fifo_t *fifo) {
  return SIZE(fifo);
}

bool fifo_empty(fifo_t *fifo) {
  return fifo->p == fifo->q;
}

#ifdef DEBUG
void fifo_debug(fifo_t *fifo) {
  size_t i;
  debug("fifo %p: len = %d, sz = %d, p = %d, q = %d, buf = %p\n",
        fifo, (int)fifo->len, (int)SIZE(fifo), (int)fifo->p, (int)fifo->q, fifo->buf);
  debug("{ ");
  for (i = 0; i < SIZE(fifo); i++) {
    debug("%c", fifo_get(fifo, i));
  }
  debug(" }\n");
}
#else
#define fifo_debug(fifo)
#endif
