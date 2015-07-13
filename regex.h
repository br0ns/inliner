#ifndef __REGEX2_H
#define __REGEX2_H

#include <stdint.h>
#include <unistd.h>

#include "bool.h"

typedef enum {
  RE_SUCCESS = 0,     /* match                               */
  RE_SUCCESS_AGAIN,   /* accepting, but may handle more data */
  RE_AGAIN,           /* need more data                      */
  RE_FAILURE          /* no match                            */
} re_result;

typedef enum {
  RE_NODE_MATCH,
  RE_NODE_SPLIT,
  RE_NODE_JUMP,

  RE_NODE_CAPTURE_BEGIN,
  RE_NODE_CAPTURE_END,

  RE_NODE_CLASS,
  RE_NODE_ANTICLASS,
  RE_NODE_LITERAL,
  RE_NODE_WILDCARD,
  RE_NODE_BACKREF
} re_node_kind;

typedef struct {
  int gen;
  union {
    int split;
    int jump;
    struct {
      uint8_t *chars;
      size_t numb;
    } class;
    struct {
      uint8_t *chars;
      size_t numb;
    } anticlass;
    uint8_t literal;
    int backref;
    int capture;
  };
  re_node_kind kind;
} re_node;

typedef struct {
  size_t begin, end;
} re_group;

typedef struct {
  size_t node;
  re_group *groups;
} re_state;

typedef struct {
  size_t num_states, len;
  re_state **states;
} re_list;

typedef struct {
  re_list *cur, *new;
  int gen;
  size_t num_groups, pos, offset;
  re_node *nodes;
  re_group *groups;
  uint8_t (*getchar)(void *, int);
  void *stream;
} regex_t;

void regex_reset(regex_t *re);
re_result regex_put(regex_t *re, uint8_t c);
bool regex_format(regex_t *re, uint16_t *fmt,
                  uint8_t **outbuf, size_t *outlen);

#endif
