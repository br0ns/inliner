#ifndef __FILTER_H
#define __FILTER_H

#include "bool.h"
#include "regex.h"
#include "fifo.h"

typedef enum {
  ACT_HANG,
  ACT_KILL,
  ACT_FLUSH_BOTH,
  ACT_FLUSH_INPUT,
  ACT_FLUSH_OUTPUT,
  ACT_PATCH,
  ACT_PATCH_FILE,
  ACT_EXEC,
  ACT_LOG,
  ACT_INPUT,
  ACT_OUTPUT,
  ACT_GUARD
} act_kind;

typedef struct _act_t {
  union {
    struct {
      uint16_t *fmt;
      int group;
    } patch;
    struct {
      char *file;
      int group;
    } patch_file;
    uint16_t *fmt;
    char *exec;
    struct {
      uint16_t *fmt;
      char *path;
      int whitelist;
    } guard;
  };
  act_kind kind;
} act_t;

typedef struct _filt_t {
  regex_t *regex;
  act_t *acts;
  int num_acts;

  bool do_advance, was_accepting;
  size_t offset, cur;
  fifo_t *fifo;
} filter_t;

void filter_init(filter_t *filt, fifo_t *fifo);
bool filter_run(filter_t *filt);
int filter_get_offset(filter_t *filt);
void filter_dec_offset(filter_t *filt, int offset);
bool filter_force_release(filter_t *filt);
void filter_rewind(filter_t *filt, size_t offset);

#endif
