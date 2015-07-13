#include <stdlib.h>
#include <string.h>

#include "debug.h"

#include "regex.h"
#include "bool.h"

#define INIT_STATE_LIST_LEN 32

void _re_list_init(re_list **lptr) {
  re_list *l;
  l = *lptr;
  if (!l) {
    l = malloc(sizeof(re_list));
    l->states = NULL;
  }
  if (!l->states) {
    l->len = INIT_STATE_LIST_LEN;
    l->states = malloc(l->len * sizeof(re_state*));
  }
  l->num_states = 0;
  *lptr = l;
}

void _re_freestate(re_state *s) {
  free(s->groups);
  free(s);
}

bool _re_addstate(regex_t *re, re_state *s) {
  re_state *s2;
  re_list *l;
  re_node *node;
  bool res1, res2;

  node = &re->nodes[s->node];

  if (node->kind != RE_NODE_BACKREF && node->gen == re->gen) {
    _re_freestate(s);
    return 0;
  }

  node->gen = re->gen;
  switch (node->kind) {
  case RE_NODE_SPLIT:
    /* follow epsilon transitions */
    s2 = malloc(sizeof(re_state));
    s2->groups = malloc(re->num_groups * sizeof(re_group));
    memcpy(s2->groups, s->groups, re->num_groups * sizeof(re_group));
    s2->node = node->split;

    s->node++;
    res1 = _re_addstate(re, s);
    res2 = _re_addstate(re, s2);

    return res1 || res2;
  case RE_NODE_JUMP:
    s->node = node->jump;
    return _re_addstate(re, s);
  case RE_NODE_CAPTURE_BEGIN:
    s->groups[node->capture].begin = re->pos;
    s->node++;
    return _re_addstate(re, s);
  case RE_NODE_CAPTURE_END:
    s->groups[node->capture].end = re->pos;
    s->node++;
    return _re_addstate(re, s);
  case RE_NODE_MATCH:
    /* save grouping */
    re->groups = malloc(re->num_groups * sizeof(re_group));
    memcpy(re->groups, s->groups, re->num_groups * sizeof(re_group));
    /* this state will not go into the list, so free it */
    _re_freestate(s);
    re->groups[0].begin = 0;
    re->groups[0].end = re->pos;
    debug("_re_addstate MATCH (%d, %d)\n", (int)re->offset, (int)re->pos);
    return 1;
  default:
    l = re->new;
    if (l->num_states == l->len) {
      l->len *= 2;
      l->states = realloc(l->states, l->len * sizeof(re_state*));
    }
    l->states[l->num_states++] = s;
  }
  return 0;
}

re_result _re_step(regex_t *re, uint8_t c) {
  size_t i, j, begin, end;
  re_state *s;
  re_node *node;
  re_result res;
  bool success;

  success = false;
  re->gen++;
  re->new->num_states = 0;
  for (i = 0; i < re->cur->num_states; i++) {
    res = RE_FAILURE;
    s = re->cur->states[i];
    node = &re->nodes[s->node];
    switch (node->kind) {
    case RE_NODE_CLASS:
      res = RE_FAILURE;
      for (j = 0; j < node->class.numb; j++) {
        if (c == node->class.chars[j]) {
          res = RE_SUCCESS;
        }
      }
      break;
    case RE_NODE_ANTICLASS:
      res = RE_SUCCESS;
      for (j = 0; j < node->anticlass.numb; j++) {
        if (c == node->anticlass.chars[j]) {
          res = RE_FAILURE;
        }
      }
      break;
    case RE_NODE_WILDCARD:
      res = RE_SUCCESS;
      break;
    case RE_NODE_LITERAL:
      if (c == node->literal) {
        res = RE_SUCCESS;
      } else {
        res = RE_FAILURE;
      }
      break;
    case RE_NODE_BACKREF:
      begin = s->groups[node->backref].begin;
      end = s->groups[node->backref].end;
      /* small hack here: groups[0].end is not used until after a match */
      debug("(%u) backref %u %u %u\n",
            (unsigned int)i, (unsigned int)begin,
            (unsigned int)s->groups[0].end, (unsigned int)end);
      if (begin + s->groups[0].end >= end) {
        res = RE_SUCCESS;
      } else {
        if (c == re->getchar(re->stream,
                             re->offset + begin + s->groups[0].end++)
            ) {
          if (begin + s->groups[0].end >= end) {
            res = RE_SUCCESS;
          } else {
            res = RE_AGAIN;
          }
        } else {
          res = RE_FAILURE;
        }
      }
      if (res != RE_AGAIN) {
        s->groups[0].end = 0;
      }
      break;
    default:
      break;
    }

    switch (res) {
    case RE_SUCCESS:
      s->node++;
    case RE_AGAIN:
      debug("_re_put new->num_states = %u\n",
            (unsigned int)re->new->num_states);
      if (_re_addstate(re, s)) {
        success = true;
      }
      debug("_re_put new->num_states = %u\n",
            (unsigned int)re->new->num_states);
      break;
    case RE_FAILURE:
      _re_freestate(s);
      break;
    default:
      break;
    }
  }

  if (0 == re->new->num_states) {
    if (success) {
      debug("_re_put = RE_SUCCESS\n");
      return RE_SUCCESS;
    } else {
      debug("_re_put = RE_FAILURE\n");
      return RE_FAILURE;
    }
  } else {
    if (success) {
      debug("_re_put = RE_SUCCESS_AGAIN\n");
      return RE_SUCCESS_AGAIN;
    } else {
      debug("_re_put = RE_AGAIN\n");
      return RE_AGAIN;
    }
  }
}

void regex_reset(regex_t *re) {
  re_list *tmp;
  re_state *s;
  size_t i;

  debug("re reset\n");

  /* if reset before SUCCESS or FAILURE clear up state list */
  if (re->cur && re->cur->num_states) {
    for (i = 0; i < re->cur->num_states; i++) {
      _re_freestate(re->cur->states[i]);
    }
  }

  _re_list_init(&re->cur);
  _re_list_init(&re->new);

  if (0 == re->num_groups) {
    re->num_groups = 1;
  }

  re->gen++;
  re->pos = 0;

  s = malloc(sizeof(re_state));
  /* might as well reuse group allocation */
  if (re->groups) {
    s->groups = re->groups;
  } else {
    s->groups = malloc(re->num_groups * sizeof(re_group));
  }
  memset(s->groups, 0, re->num_groups * sizeof(re_group));
  s->groups[0].begin = re->pos;
  s->node = 0;

  re->groups = NULL;

  _re_addstate(re, s);
  tmp = re->cur; re->cur = re->new; re->new = tmp;
}

re_result regex_put(regex_t *re, uint8_t c) {
  re_list *tmp;
  re_result res;

  debug("re put (%c)\n", c);

  re->pos++;
  res = _re_step(re, c);
  tmp = re->cur; re->cur = re->new; re->new = tmp;

  return res;
}

bool regex_format(regex_t *re, uint16_t *fmt,
                 uint8_t **outbuf, size_t *outlen) {
  size_t bcki, fmti, bufi, len;
  uint16_t c;
  uint8_t *buf;

  if (!re->groups) {
    return false;
  }

  len = 32;
  bufi = 0;
  buf = malloc(len);

#define _fmt_put(c) \
  do {                                          \
    if (bufi == len) {                          \
      len *= 2;                                 \
      buf = realloc(buf, len);                  \
    }                                           \
    buf[bufi++] = c;                            \
  } while (0)

  for (fmti = 0; fmt[fmti] != 0xffff; fmti++) {
    c = fmt[fmti];
    if (c <= 0xff) {
      _fmt_put(c);
    } else {
      c -= 0x100;
      debug("regex_format grp %u (%u, %u)\n",
            c, (unsigned int)re->groups[c].begin,
            (unsigned int)re->groups[c].end);
      for (bcki = re->groups[c].begin; bcki < re->groups[c].end; bcki++) {
        _fmt_put(re->getchar(re->stream, bcki + re->offset));
      }
    }
  }

  /* easier debugging */
  _fmt_put(0); bufi--;

  buf = realloc(buf, len);
  *outbuf = buf;
  if (outlen) {
      *outlen = bufi;
  }

  return true;
}
