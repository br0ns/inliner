#ifndef __FIFO_H
#define __FIFO_H

#include <stdint.h>
#include <unistd.h>

#include "bool.h"

typedef struct {
  size_t len, p, q;
  uint8_t *buf;
} fifo_t;

int fifo_init(fifo_t *fifo);
void fifo_push(fifo_t *fifo, uint8_t c);
void fifo_push_buf(fifo_t *fifo, uint8_t *buf, size_t numb);
int fifo_pop(fifo_t *fifo, uint8_t* c);
int fifo_pop_buf(fifo_t *fifo, uint8_t *buf, size_t numb);
uint8_t fifo_get(fifo_t *fifo, int pos);
void fifo_resize(fifo_t *fifo, size_t size);
void fifo_set(fifo_t *fifo, int pos, uint8_t c);
size_t fifo_size(fifo_t *fifo);
bool fifo_empty(fifo_t *fifo);

#ifdef DEBUG
void fifo_debug(fifo_t *fifo);
#else
#define fifo_debug(fifo)
#endif


#endif
