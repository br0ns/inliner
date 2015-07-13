# `inliner`

This tool acts as a man-in-the-middle for binaries run directly or through
e.g. `inetd`.

Configuration of the tool is "baked in" in the sense that a single binary is
produced for a given configuration.  Build with

```
  make CONFIG=myconfig.inl
```

## Configuration

A configuration file contains a collection of options, filters and environment
variables.  Comments start on `#` and run to the end of the line.

### Options

An option has the form:

```
  set <option> <value>
```

If `<value>` is a relative path, it will be relative to the inliner-binary.

If you need to write binary data, use `\xYZ`, e.g match to match a C-string use:

```
  /[^\x00]+/
```

Currently the supported options are:

#### `target`

The target binary.  Must be set.

#### `logfile`

An optional logfile.  The `log`-action writes to this file (see below).

#### `alarm`

Register an alarm signal.  In seconds.

#### `drip` (default: `true`)

Whether to put data onto the network one byte or a full buffer at a time.  If
this option is set TCP_NODELAY will be set on the output socket and data will be
written one byte at a time.  Otherwise no extra socket options are set, and data
is written in chunks of up to 4096 bytes.  Be aware that filters who hold on to
bytes may change how many bytes are put onto the network at a time.  If no
filters are defined the inliner is equivalent to an input/output pump with at 4K
buffer.

#### `kill_on_shutdown` (default: `false`)

Whether to kill the process if the input file descriptor is closed (i.e. the
client calls `shutdown(fd, SHUT_WR)`).

#### `uid`

Switch to given user id.

#### `gid`

Switch to given group id.  Drop all secondary groups.

#### `rlimit_nproc`

Set `rlimit_nproc` (see `setrlimit(2)`).

#### `rlimit_cpu`

Set `rlimit_cpu` (see `setrlimit(2)`).

#### `timeout` (default: `1000`, i.e. 1ms)

Wait for new input/output this amount of microseconds before forcing filters to
release bytes.

#### `random_fds` (default: `true`)

Whether to randomize file descriptors.  Works by `dup(2)`'ing `/dev/zero` to all
file descriptors, then `close(2)`'ing some at random.

#### `random_fds_amount` (default: `150`)

If `random_fds` is set then this is the amount of file descriptors to
`close(2)`, making them available to the wrapped program.

### Environment

An environment variable has the form:

```
  env <var> <value>
```

Multiple definitions of the environment variable `LD_PRELOAD` are allowed.  The
result will be to set `LD_PRELOAD` to the concatenation all the definitions,
separated by `:`. E.g. this:

```
  env LD_PRELOAD foo.so
  env LD_PRELOAD bar.so
```

is equivalent to this:

```
  env LD_PRELOAD foo.so:bar.so
```

If `<value>` is a relative path, it will be relative to the inliner-binary.

### Filters

A filter has the form:

```
  (i|o): /<regex>/
    <action>
    ...
    <action>
```

The `/`'s around `<regex>` can be replaced by any character, with the exception
that if `(`, `{` or `[` is used on the left then `)`, `}` or `]` should be used
on the right respectively.

An action is one of:

#### `hang`

Kill the child but keep reading (and immediately forgetting) input.  Never send
output.  Hopefully this will throw somebody's exploit off and waste their time.

#### `kill`

Kill the process.  No output will be sent.

#### `flush` [`input`|`output`|`both`]

Flush input/output buffers.  Filters will be forced to release all bytes
immediately.  If no argument is given both input and output buffers will be
flushed.

#### `patch <group> <replacement>`

Replace the part of the stream that was matched by the filter's `<regex>` with
`<replacement>`.  The format of `<group>` is `\x` where `x` is an integer. The
given subgroup of the `<regex>` will be replaced.  Subgroups may be referred to
in `<replacement>` with `\x`.  All filters in the same direction will be rewound
to the first replaced byte in the buffer, so beware of infinite loops.  This
will loop:

```
  i: /foo \S+/
     patch \0 "foo baz"
```

but this will not:

```
  i: /foo (\S+)/
     patch \1 "baz"
```

If `<replacement>` has the form `file <file>`, then the the chosen subgroup
will be replaced with the contents of `<file>`.

#### `exec <program>`

Call `execv` on `<program>` thus replacing the inliner.  Example usage:

```
  exec ./cat_30min_old_flag.sh
```

#### `log <message>`

Write `<message>` to the log file.  If no log file is specified (with `set
logfile <path>`) this is a no-op.  Subgroups of `<regex>` may be referred to
with `\x`:

```
  o: /cat|dog|bird|giraffe/
     log "I saw a \0!"
```

#### `input <data>`

Send `<data>` to the wrapped program.  No filters will see `<data>`.  Subgroups
of `<regex>` may be referred to.

#### `output <data>`

Send `<data>` to the world.  No filters will see `<data>`.  Subgroups of
`<regex>` may be referred to.

#### `guard <str> [not] in <file>`

Assert that `<str>` (which may refer to subgroups of `<regex>`) is or is not
present somewhere in `<file>`.  E.g:

```
  o: /You win: (\S+)/
     guard "\1" in flag
     kill
```

or

```
  i: /cmd (\S+)/
     guard "\1" not in allowed_commands
     hang
```

## Libstatus

A library which prints some stats and exits can be found in `libstatus/`.  It
can be build with:

```
  $ make libstatus
```

It can be loaded with `LD_PRELOAD`, and is intended for just checking that
things are working and set up right.

A template config file when setting up a new service is thus:

```
  set target <thetarget>
  env LD_PRELOAD libstatus.so
```

Be aware that libstatus will `_exit`, so it should be disabled once it is
confirmed that the service is working.

## Example

 1. Go to `example/`
 2. Type `./run.sh`
 3. Press `<enter>`
