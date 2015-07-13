import sys, string, types

class ParseError(Exception):
    pass
class OptionError(Exception):
    pass
def error(pos, err):
    raise ParseError(pos - 1, err)

def parse(input):
    def cstr(s):
        return ''.join('\\x%02x' % ord(c) for c in s)
        # out = ''
        # for c in s:
        #     if   c == '\a':
        #         out += '\\a'
        #     elif c == '\b':
        #         out += '\\b'
        #     elif c == '\t':
        #         out += '\\t'
        #     elif c == '\n':
        #         out += '\\n'
        #     elif c == '\v':
        #         out += '\\v'
        #     elif c == '\f':
        #         out += '\\f'
        #     elif c == '\r':
        #         out += '\\r'
        #     elif c == '"':
        #         out += '\\"'
        #     elif ord(c) < 0x20 or ord(c) > 0x7e:
        #         out += '\\x%02x' % ord(c)
        #     else:
        #         out += c
        # return out

    def cchr(c):
        return '\\x%02x' % ord(c)
        # if   c == '\a':
        #     return '\\a'
        # elif c == '\b':
        #     return '\\b'
        # elif c == '\t':
        #     return '\\t'
        # elif c == '\n':
        #     return '\\n'
        # elif c == '\v':
        #     return '\\v'
        # elif c == '\f':
        #     return '\\f'
        # elif c == '\r':
        #     return '\\r'
        # elif c == "'":
        #     return "\\'"
        # elif ord(c) < 0x20 or ord(c) > 0x7e:
        #     return '\\x%02x' % ord(c)
        # else:
        #     return c

    def skipws(pos):
        while pos < len(input) and input[pos] in string.whitespace:
            pos += 1
        return pos

    def skipuntil(pos, c):
        while pos < len(input) and input[pos] <> c:
            pos += 1
        return pos

    def skip(pos):
        pos = skipws(pos)
        while tok(pos, '#'):
            pos = skipuntil(pos + 1, '\n')
            pos = skipws(pos)
        return pos

    def tok(pos, s):
        if pos + len(s) <= len(input):
            return input[pos:pos+len(s)] == s
        return False

    def peek(pos, n = 1, err = 'unexpected end of input'):
        if pos + n <= len(input):
            return input[pos:pos+n]
        error(pos, err)

    def num(pos):
        n = ''
        while pos < len(input) and input[pos].isdigit():
            n += input[pos]
            pos += 1
        return pos, n

    def groupchars(pos):
        beginchar = peek(pos)
        pos += 1
        if beginchar not in '"\'()/':
            error(pos, 'expected regex or regex format string')
        if   beginchar == '(':
            endchar = ')'
        elif beginchar == '[':
            endchar = ']'
        elif beginchar == '{':
            endchar = '}'
        else:
            endchar = beginchar
        return pos, beginchar, endchar

    def regex(pos):
        name = 'regex%s' % len(regexes)
        def char(pos, special = '[]{}()|*+.?', backrefs = True):
            ranges = {
                'd': string.digits,
                's': string.whitespace,
                'w': string.letters + string.digits + '_',
                }
            c = peek(pos)
            pos += 1
            if c == endchar:
                return pos, 'END', None
            if c not in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
                error(pos, 'unexpected character (%s)' % `c`[1:-1])
            special = special + endchar
            t = 'SPECIAL' if c in special else 'NORMAL'
            if c == '\\':
                c2 = peek(pos, err = 'incomplete escape sequence')
                pos += 1
                if   c2 == 'n':
                    c = '\n'
                elif c2 == 'r':
                    c = '\r'
                elif c2 == 't':
                    c = '\t'
                elif c2.lower() in ranges:
                    s = ranges[c2.lower()]
                    if c2.isupper():
                        cs = map(chr, range(256))
                        s = ''.join(c for c in cs if c not in s)
                    t = 'RANGE'
                    c = s
                elif c2 == 'x':
                    hexc = '1234567890abcdefABCDEF'
                    c3 = peek(pos, err = 'incomplete hex escape')
                    pos += 1
                    if c3 not in hexc:
                        error(pos, 'not a hex character')
                    c4 = peek(pos, err = 'incomplete hex escape')
                    pos += 1
                    if c4 not in hexc:
                        error(pos, 'not a hex character')
                    c = chr(int(c3 + c4, 16))
                elif c2 in special or c2 == '\\':
                    c = c2
                elif c2.isdigit():
                    if not backrefs:
                        error(pos, 'backrefs not allowed here')
                    n = c2
                    pos, n2 = num(pos)
                    t = 'BACKREF'
                    c = int(n + n2)
                else:
                    error(pos, 'invalid escape sequence')
            return pos, t, c

        grpnum = [0, 0] # number of opened/closed groups
        nesting = []
        def one(pos):
            pos, t, c = char(pos)
            if t == 'NORMAL':
                return pos, 'LITERAL', c

            if t == 'RANGE':
                return pos, 'CLASS', c

            if t == 'BACKREF':
                if c > grpnum[0] or c < grpnum[0] - grpnum[1] + 1:
                    error(pos, 'no such group')

            if t == 'SPECIAL':
                if   c == '[':
                    was_range = False
                    pos, t, c = char(pos, special = '^', backrefs = False)
                    if t == 'SPECIAL':
                        cs = ''
                        anti = True
                    elif t == 'RANGE':
                        cs = c
                        was_range = True
                        anti = False
                    else:
                        cs = c
                        anti = False
                    if cs == '':
                        pos, t, c = char(pos, special = '', backrefs = False)
                        if t == 'RANGE':
                            was_range = True
                        cs = c
                    while True:
                        pos, t, c = char(pos, special = ']', backrefs = False)
                        if t == 'SPECIAL':
                            break
                        elif t == 'RANGE':
                            was_range = True
                        if c == '-' and cs:
                            pos2 = pos
                            if was_range:
                                error(pos2, 'bad character range')
                            pos, t, c = char(pos, special = ']', backrefs = False)
                            if t == 'NORMAL':
                                f = ord(cs[-1])
                                cs = cs[:-1]
                                t = ord(c)
                                if t <= f:
                                    error(pos2, 'bad character range')
                                cs += ''.join(chr(x) for x in range(f, t + 1))
                            elif t == 'RANGE':
                                was_range = True
                            else:
                                cs += '-'
                                break
                            if was_range:
                                error(pos2, 'bad character range')
                        else:
                            was_range = False
                        cs += c
                    if cs == '':
                        error(pos, 'empty character class')
                    t = 'ANTICLASS' if anti else 'CLASS'
                    return pos, t, cs

                elif c == '{':
                    n1 = ''
                    n2 = ''
                    comma = False
                    while True:
                        c2 = peek(pos, err = 'incomplete repetition pattern')
                        pos += 1
                        if c2 == '}':
                            break
                        if c2 == ',':
                            if comma:
                                error(pos, 'bad repetition pattern')
                            comma = True
                        elif c2.isdigit():
                            if comma:
                                n2 += c2
                            else:
                                n1 += c2
                        else:
                            error(pos, 'bad character in repetition pattern')
                    n1 = int(n1 or '0')
                    if comma:
                        n2 = int(n2 or '-1')
                    else:
                        n2 = n1
                    if n2 >= 0 and n2 < n1:
                        error(pos, 'minimum repetitions larger than max')
                    return pos, 'REPEAT', (n1, n2)

                elif c == '.':
                    return pos, 'WILDCARD', None
                elif c == '*':
                    return pos, 'REPEAT', (0, -1)
                elif c == '+':
                    return pos, 'REPEAT', (1, -1)
                elif c == '?':
                    return pos, 'REPEAT', (0, 1)
                elif c == '|':
                    return pos, 'CHOICE', pos

                elif c == '(':
                    if tok(pos, '?:'):
                        pos += 2
                        capturing = False
                    else:
                        grpnum[0] += 1
                        num = grpnum[0]
                        capturing = True
                    nesting.append((pos, capturing))
                    pos, sz, grp = many(pos)
                    if capturing:
                        cb = ('CAPTURE_BEGIN', num)
                        ce = ('CAPTURE_END', num)
                        grp = [cb] + grp + [ce]
                        sz += 2
                    return pos, 'GROUP', (sz, grp)

                elif c == ')':
                    try:
                        _, capturing = nesting.pop()
                    except:
                        error(pos, 'unmatched ")"')
                    if capturing:
                        grpnum[1] += 1
                    return pos, 'END', None
                else:
                    error(pos, 'runaway "%s"' % c)
            return pos, t, c

        def many(pos):
            sz = 0
            stack = []
            grp = []
            while True:
                pos, t, c = one(pos)
                if   t == 'END':
                    break
                elif t == 'GROUP':

                    sz += c[0]
                    grp.append((t, c))

                elif t == 'REPEAT':
                    if not grp:
                        error(pos, 'nothing to repeat')
                    elm = grp.pop()
                    if elm[0] == 'CHOICE':
                        error(pos, 'syntax error')
                    esz = size(elm)
                    sz -= esz
                    rsz = 0
                    min = c[0]
                    max = c[1]
                    rgrp = []

                    if max < 0:
                        if min > 1:
                            rgrp += [elm] * (min - 1)
                            rsz += esz * (min - 1)
                            max -= min - 1
                            min = 1
                        # maybe prime factorize
                        if min == 0:
                            rgrp += [('SPLIT', esz + 2)]
                            rgrp += [elm]
                            rgrp += [('JUMP', -esz - 1)]
                            rsz += esz + 2
                        else:
                            assert min == 1
                            rgrp += [elm]
                            rgrp += [('SPLIT', -esz)]
                            rsz += esz + 1
                    else:
                        rgrp += [elm] * min
                        rsz += esz * min
                        max -= min
                        for j in range(max):
                            rgrp += [('SPLIT', (max - j) * (esz + 1))]
                            rgrp += [elm]
                        rsz += max * (esz + 1)
                    grp.append(('GROUP', (rsz, rgrp)))
                    sz += rsz

                elif t == 'CHOICE':
                    if not grp:
                        error(pos, 'no left option')
                    stack.append(('GROUP', (sz, grp)))
                    grp = []
                    sz = 0
                else:
                    sz += 1
                    grp.append((t, c))

            if not grp:
                if not stack:
                    error(pos, 'empty group')
                else:
                    error(pos, 'no right option')
            stack.append(('GROUP', (sz, grp)))

            while len(stack) > 1:
                elmr = stack.pop()
                eszr = size(elmr)
                elml = stack.pop()
                eszl = size(elml)
                grp = [('SPLIT', eszl + 2),
                       elml,
                       ('JUMP', eszr + 1),
                       elmr,
                       ]
                sz = eszl + eszr + 2
                stack.append(('GROUP', (sz, grp)))
            _, (sz, grp) = stack[0]
            return pos, sz, grp

        def size((t, c)):
            return c[0] if t == 'GROUP' else 1

        def flat(n, xs):
            out = []
            for foo in xs:
                t, x = foo
                if t == 'GROUP':
                    n, out2 = flat(n, x[1])
                    out += out2
                    continue
                elif t in ('SPLIT', 'JUMP'):
                    x += n
                n += 1
                out.append((t, x))
            return n, out

        def build(prog):
            out = 're_node %s_nodes[] = {\n' % name
            for t, x in prog:
                if t in ('CLASS', 'ANTICLASS') and len(x) > 128:
                    t = 'ANTICLASS' if t == 'CLASS' else 'CLASS'
                    cs = map(chr, range(256))
                    x = ''.join(c for c in cs if c not in x)
                out += '  {\n'
                if   t == 'MATCH':
                    out += '''    .kind = RE_NODE_MATCH
  }
'''
                    break
                elif t == 'SPLIT':
                    out += '''    .kind = RE_NODE_SPLIT,
    .split = %d
''' % x
                elif t == 'JUMP':
                    out += '''    .kind = RE_NODE_JUMP,
    .jump = %d
''' % x
                elif t == 'CAPTURE_BEGIN':
                    out += '''    .kind = RE_NODE_CAPTURE_BEGIN,
    .capture = %d
''' % x
                elif t == 'CAPTURE_END':
                    out += '''    .kind = RE_NODE_CAPTURE_END,
    .capture = %d
''' % x
                elif t == 'CLASS':
                    out += '''    .kind = RE_NODE_CLASS,
    .class = {
      .chars = (uint8_t*)"%s",
      .numb = %d
    }
''' % (cstr(x), len(x))
                elif t == 'ANTICLASS':
                    out += '''    .kind = RE_NODE_ANTICLASS,
    .anticlass = {
      .chars = (uint8_t*)"%s",
      .numb = %d
    }
''' % (cstr(x), len(x))
                elif t == 'LITERAL':
                    out += '''    .kind = RE_NODE_LITERAL,
    .literal = '%s'
''' % cchr(x)
                elif t == 'WILDCARD':
                    out += '''    .kind = RE_NODE_WILDCARD
'''
                elif t == 'BACKREF':
                    out += '''    .kind = RE_NODE_BACKREF,
    .backref = %d
''' % x
                else:
                    raise Exception('unknown action: %s' % t)
                out += '  },\n'
            out += '};\n'
            out += '''regex_t %s = {
  .nodes = %s_nodes,
  .num_groups = %d
};
''' % (name, name, grpnum[0] + 1)
            return out

        pos, _, endchar = groupchars(pos)
        pos, _sz, grp = many(pos)
        if nesting:
            error(nesting[-1],  'unmatched "("')
        _, prog = flat(0, grp)
        prog.append(('MATCH', None))
        regexes.append(build(prog))
        return pos, name, grpnum[0]

    def ident(pos):
        s1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
        s2 = s1 + '0123456789'
        pos2 = pos
        c = peek(pos2)
        pos2 += 1
        if c not in s1:
                return pos, ''
        id = c
        while True:
            c = peek(pos2)
            if c not in s2:
                return pos2, id
            pos2 += 1
            id += c

    def str(pos):
        c = peek(pos)
        if c in '\'"(':
            pos += 1
            if c == '(':
                endchar = ')'
            else:
                endchar = c
        else:
            endchar = '\n'
        s = ''
        while True:
            c = peek(pos)
            pos += 1
            if   c == endchar:
                break
            if c not in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
                error(pos, 'unexpected character (%s)' % `c`[1:-1])
            elif c == '\\':
                c2 = peek(pos, err = 'incomplete escape sequence')
                pos += 1
                if   c2 == 'n':
                    c = '\n'
                elif c2 == 'r':
                    c = '\r'
                elif c2 == 't':
                    c = '\t'
                elif c2 == 'x':
                    hexc = '1234567890abcdefABCDEF'
                    c3 = peek(pos, err = 'incomplete hex escape')
                    pos += 1
                    if c3 not in hexc:
                        error(pos, 'not a hex character')
                    c4 = peek(pos, err = 'incomplete hex escape')
                    pos += 1
                    if c4 not in hexc:
                        error(pos, 'not a hex character')
                    c = int(c3 + c4, 16)
                elif c2 in ('\\', endchar):
                    c = c2
                else:
                    error(pos, 'invalid escape sequence')
            s += c
        if endchar == '\n' and '#' in s:
            s = s[:s.index('#')]
        return pos, s

    def filter(pos):
        name = 'filter%s' % len(filters)

        def refmt(pos, numgrps):
            pos, _, endchar = groupchars(pos)
            s = []
            while True:
                c = peek(pos)
                pos += 1
                if c not in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
                    error(pos, 'unexpected character (%s)' % `c`[1:-1])
                if   c == endchar:
                    break
                elif c == '\\':
                    c2 = peek(pos, err = 'incomplete escape sequence')
                    pos += 1
                    if   c2 == 'n':
                        c = ord('\n')
                    elif c2 == 'r':
                        c = ord('\r')
                    elif c2 == 't':
                        c = ord('\t')
                    elif c2 == 'x':
                        hexc = '1234567890abcdefABCDEF'
                        c3 = peek(pos, err = 'incomplete hex escape')
                        pos += 1
                        if c3 not in hexc:
                            error(pos, 'not a hex character')
                        c4 = peek(pos, err = 'incomplete hex escape')
                        pos += 1
                        if c4 not in hexc:
                            error(pos, 'not a hex character')
                        c = int(c3 + c4, 16)
                    elif c2 in ('\\', endchar):
                        c = ord(c2)
                    elif c2.isdigit():
                        n = c2
                        pos2, n2 = num(pos)
                        n = int(n + n2)
                        if n > numgrps:
                            error(pos, 'no such group')
                        pos = pos2
                        c = n + 0x100
                    else:
                        error(pos, 'invalid escape sequence')
                else:
                    c = ord(c)
                s.append(c)
            s.append(0xffff)
            return pos, s

        def action(pos, numgrps):
            if   tok(pos, 'hang'):
                return pos + 4, ('HANG', None)
            elif tok(pos, 'kill'):
                return pos + 4, ('KILL', None)
            elif tok(pos, 'flush'):
                pos = skip(pos + 5)
                if tok(pos, 'input'):
                    return pos + 5, ('FLUSH', 'INPUT')
                elif tok(pos, 'output'):
                    return pos + 6, ('FLUSH', 'OUTPUT')
                elif tok(pos, 'both'):
                    return pos + 4, ('FLUSH', 'BOTH')
                else:
                    return pos, ('FLUSH', 'BOTH')
            elif tok(pos, 'patch'):
                pos = skip(pos + 5)
                grp = 0
                if tok(pos, '\\'):
                    pos2, n = num(pos + 1)
                    if n and pos2 < len(input) and input[pos2].isspace():
                        pos = skip(pos2)
                        grp = int(n)
                    else:
                        error(pos + 2, 'invalid group number')
                else:
                    error(pos + 1, 'expected a group number (\\x -- no qoutes)')
                if tok(pos, 'file'):
                    pos = skip(pos + 4)
                    pos, s = str(pos)
                    return pos, ('PATCH_FILE', (grp, s))
                else:
                    pos, fmt = refmt(pos, numgrps)
                    return pos, ('PATCH', (grp, fmt))
            elif tok(pos, 'exec'):
                pos = skip(pos + 4)
                pos, s = str(pos)
                return pos, ('EXEC', s)
            elif tok(pos, 'log'):
                pos = skip(pos + 3)
                pos, fmt = refmt(pos, numgrps)
                return pos, ('LOG', fmt)
            elif tok(pos, 'input'):
                pos = skip(pos + 5)
                pos, fmt = refmt(pos, numgrps)
                return pos, ('INPUT', fmt)
            elif tok(pos, 'output'):
                pos = skip(pos + 6)
                pos, fmt = refmt(pos, numgrps)
                return pos, ('OUTPUT', fmt)
            elif tok(pos, 'guard'):
                pos = skip(pos + 5)
                if tok(pos, '\\'):
                    pos2, n = num(pos + 1)
                    if n and pos2 < len(input) and input[pos2].isspace():
                        pos = skip(pos2)
                        grp = int(n)
                        fmt = [0x100 + grp, 0xffff]
                    else:
                        error(pos + 2, 'invalid group number')
                else:
                    pos, fmt = refmt(pos, numgrps)
                    pos = skip(pos)
                if tok(pos, 'not'):
                    whitelist = True
                    pos = skip(pos + 3)
                else:
                    whitelist = False
                if not tok(pos, 'in'):
                    error(pos, 'expected "in"')
                pos = skip(pos + 2)
                pos, path = str(pos)
                return pos, ('GUARD', (fmt, path, whitelist))
            else:
                return pos, None

        def build(acts):
            def fmt2str(fmt):
                xs = []
                for x in fmt:
                    xs += [x & 0xff, (x >> 8) & 0xff]
                return cstr(map(chr, xs))
            out = 'act_t %s_acts[] = {\n' % name
            for i, (t, x) in enumerate(acts):
                out += '  {\n'
                if   t == 'HANG':
                    out += '''    .kind = ACT_HANG
'''
                elif t == 'KILL':
                    out += '''    .kind = ACT_KILL
'''
                elif t == 'FLUSH':
                    out += '''    .kind = ACT_FLUSH_%s,
''' % x
                elif t == 'PATCH':
                    out += '''    .kind = ACT_PATCH,
    .patch = {
      .fmt = (uint16_t*)"%s",
      .group = %d
    }
''' % (fmt2str(x[1]), x[0])
                elif t == 'PATCH_FILE':
                    out += '''    .kind = ACT_PATCH_FILE,
    .patch_file = {
      .file = "%s",
      .group = %d
    }
''' % (cstr(x[1]), x[0])
                elif t == 'EXEC':
                    out += '''    .kind = ACT_EXEC,
    .exec = "%s"
''' % cstr(x)
                elif t == 'LOG':
                    out += '''    .kind = ACT_LOG,
    .fmt = (uint16_t*)"%s"
''' % fmt2str(x)
                elif t == 'INPUT':
                    out += '''    .kind = ACT_INPUT,
    .fmt = (uint16_t*)"%s"
''' % fmt2str(x)
                elif t == 'OUTPUT':
                    out += '''    .kind = ACT_OUTPUT,
    .fmt = (uint16_t*)"%s"
''' % fmt2str(x)
                elif t == 'GUARD':
                    out += '''    .kind = ACT_GUARD,
    .guard = {
      .fmt = (uint16_t*)"%s",
      .path = "%s",
      .whitelist = %d,
    }
''' % (fmt2str(x[0]), cstr(x[1]), int(x[2]))
                if i == len(acts) - 1:
                    out += '  }\n};\n'
                else:
                    out += '  },\n'
            return out

        pos, regexname, numgrps = regex(pos)
        pos = skip(pos)
        if tok(pos, '{'):
            braces = True
            pos = skip(pos + 1)
        else:
            braces = False
        acts = []
        while True:
            pos, act = action(pos, numgrps)
            if not act:
                break
            pos = skip(pos)
            acts.append(act)
        if not acts:
            error(i, err = 'expected one or more actions')
        if braces:
            if not tok(pos, '}'):
                error(pos + 1, 'expected "}"')
            pos = skip(pos + 1)

        out = build(acts)
        out += '''filter_t %s = {
  .regex = &%s,
  .acts = %s_acts,
  .num_acts = %d
};
''' % (name, regexname, name, len(acts))
        filters.append(out)

        return pos, name

    regexes = []
    filters = []
    ifilts = []
    ofilts = []
    opts = { # defaults
        'alarm'             : -1,
        'timeout'           : 1000, # 1 ms
        'rlimit_nproc'      : -1,
        'rlimit_cpu'        : -1,
        'uid'               : -1,
        'gid'               : -1,
        'logfile'           : '',
        'kill_on_shutdown'  : False,
        'drip'              : True,
        'random_fds'        : True,
        'random_fds_amount' : 150,
        }
    env = {}
    intopts = ('alarm', 'timeout', 'rlimit_nproc', 'rlimit_cpu', 'uid', 'gid',
               'random_fds_amount')
    boolopts = ('kill_on_shutdown', 'drip', 'random_fds')
    stropts = ('target', 'logfile')
    allopts = intopts + boolopts + stropts
    pos = skip(0)

    last_was_filt = False
    while pos < len(input):
        if tok(pos, 'set'):
            last_was_filt = False
            pos = skip(pos + 3)
            pos2, id = ident(pos)
            if not id:
                error(pos + 1, 'expected an option identifier')
            if id not in allopts:
                error(pos + 1, 'unknown option: "%s"' % id)
            pos = skip(pos2)
            pos2, val = str(pos)
            if id in intopts:
                val = val.strip()
                if len(val) > 2 and val[:2] == '0x':
                    val = val[2:]
                    base = 16
                else:
                    base = 10
                if not val.isdigit():
                    error(pos + 1, 'value for option "%s" must be an integer' % id)
                val = int(val, base)
            elif id in boolopts:
                val = val.strip()
                if val not in ('true', 'false'):
                    error(pos + 1, 'expected an boolean (true/false)')
                val = val == 'true'
            pos = pos2
            opts[id] = val

        elif tok(pos, 'env'):
            last_was_filt = False
            pos = skip(pos + 3)
            pos2, var = ident(pos)
            if not var:
                error(pos + 1, 'expected an environment variable')
            pos3 = skip(pos2)
            pos3, val = str(pos3)
            if var in env:
                if var == 'LD_PRELOAD':
                    env[var] += ':' + val
                else:
                    error(pos + 1, 'duplicate environment variable: %s' % var)
            else:
                env[var] = val
            pos = pos3

        else:
            if   tok(pos, 'i:') or tok(pos, 'I:'):
                inp = True
            elif tok(pos, 'o:') or tok(pos, 'O:'):
                inp = False
            else:
                err = 'expected a filter definition'
                if last_was_filt:
                    err += ', an action'
                err += ' or setting an option or environment variable'
                error(pos + 1, err)
            pos = skip(pos + 2)
            pos, filtname = filter(pos)
            last_was_filt = True
            if inp:
                ifilts.append(filtname)
            else:
                ofilts.append(filtname)
        pos = skip(pos)

    out = ''.join(regexes + filters)
    out += '''filter_t *ifilters[] = {
  %s
};
''' % ', '.join(['&%s' % f for f in ifilts] + ['NULL'])
    out += '''filter_t *ofilters[] = {
  %s
};
''' % ', '.join(['&%s' % f for f in ofilts] + ['NULL'])
    out += '''filter_t *allfilters[] = {
  %s
};
''' % ', '.join(['&%s' % f for f in ifilts + ofilts] + ['NULL'])
    for opt in allopts:
        if opt not in opts:
            raise OptionError(opt)
    for k, v in opts.items():
        if isinstance(v, types.StringType):
            if v:
                v = '"%s"' % cstr(v)
            else:
                v = 'NULL'
            t = 'char *'
        elif isinstance(v, types.BooleanType):
            t = 'int '
            v = int(v)
        elif isinstance(v, types.IntType):
            t = 'int '
        else:
            raise TypeError
        out += '%soption_%s = %s;\n' % (t, k, v)
    out += 'char *option_env[] = {\n'
    for k, v in env.items():
        out += '  "%s", ' % cstr(k)
        out += '"%s",\n' % cstr(v)
    out += '  NULL, NULL\n};\n' # extra null to keep gcc happy
    if not opts['logfile']:
        print '!! no logfile specified'
        print '!! consider adding "set logfile ..."'
    return out

if __name__ == '__main__':
    if len(sys.argv) <> 3:
        print 'usage: %s infile outfile' % sys.argv[0]
        exit()

    infile, outfile = sys.argv[1:]

    s = open(infile, 'r').read()
    try:
        s = parse(s)
        with open(outfile, 'w') as fd:
            fd.write(s)
        sys.exit(0)
    except ParseError as (pos, msg):
        i = 0
        n = 0
        lines = []
        while i < len(s):
            n += 1
            try:
                j = s.index('\n', i)
            except ValueError:
                j = len(s)
            line = s[i:j]
            if j >= pos:
                line = s[i:j]
                linum = '%d' % n
                print 'error <%s:%d,%d>:' % (infile, n, j - i)
                print '  %s' % msg
                if n > 4:
                    print '  ...'
                pre = lines[-3:]
                for k, l in enumerate(pre):
                    print '  %s> %s' % (str(n - len(pre) + k).rjust(len(linum)), l)
                print '  %s> %s' % (linum, line)
                print ' ' * (pos - i + len(linum) + 4) + '^'
                break
            lines.append(line)
            i = j + 1
    except OptionError as opt:
        print 'error <%s>:' % infile
        print '  must set option "%s"' % opt
    sys.exit(-1)
