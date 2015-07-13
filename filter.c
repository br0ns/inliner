#include "regex.h"
#include "filter.h"
#include "debug.h"

void filter_advance(filter_t *filt) {
  filt->regex->offset++;
  filt->cur = filt->regex->offset;
  filt->do_advance = false;
  filt->was_accepting = false;
  regex_reset(filt->regex);
}

bool filter_run(filter_t *filt) {
  size_t bufsz;
  uint8_t c;

  /* do we need to go to next position? */
  if (filt->do_advance) {
    filter_advance(filt);
  }

  bufsz = fifo_size(filt->fifo);
  while (filt->cur < bufsz && filt->regex->offset < bufsz) {
    debug("filter_run: offset = %d, cur = %d\n", (int)filt->regex->offset, (int)filt->cur);
    for (; filt->cur < bufsz; filt->cur++) {
      c = fifo_get(filt->fifo, filt->cur);
      switch (regex_put(filt->regex, c)) {
      case RE_SUCCESS:
        filt->do_advance = true;
        return true;
      case RE_SUCCESS_AGAIN:
        filt->was_accepting = true;
        break;
      case RE_FAILURE:
        if (filt->was_accepting) {
          filt->do_advance = true;
          return true;
        }
        goto NEXT;
      default:
        break;
      }
    }
    /* pushed all available data to regex and still got RE_(SUCCESS_)AGAIN */
    if (filt->cur == bufsz) {
      return false;
    }
  NEXT:
    filter_advance(filt);
  }

  /* we got here because the regex failed on every position in the fifo */
  return false;
}

int filter_get_offset(filter_t *filt) {
  return filt->regex->offset;
}

void filter_dec_offset(filter_t *filt, int n) {
  filt->regex->offset -= n;
  filt->cur -= n;
}

void filter_rewind(filter_t *filt, size_t offset) {
  if (filt->regex->offset >= offset) {
    debug("filter_rewind %p, offset = %d\n", filt, (int)offset);
    filt->regex->offset = offset;
    filt->cur = offset;
    filt->do_advance = false;
    filt->was_accepting = false;
    regex_reset(filt->regex);
  } else {
    debug("filter_rewind no need\n");
  }
}

bool filter_force_release(filter_t *filt) {
  if (filt->regex->offset == 0 && fifo_size(filt->fifo) > 0) {
    filt->do_advance = true;
    return filt->was_accepting;
  }

  return false;
}

void filter_init(filter_t *filt, fifo_t *fifo) {
  filt->fifo = fifo;
  filt->cur = 0;
  filt->do_advance = false;
  filt->was_accepting = false;

  filt->regex->getchar = (uint8_t(*)(void*, int))fifo_get;
  filt->regex->stream = (void*)fifo;
  filt->regex->offset = 0;
  regex_reset(filt->regex);
}
