# De-slop rules for C and eBPF

A review checklist for this repository, adapted from Go guidance written for
the same purpose ([go-deslop.md](https://gist.github.com/pipethedev/0bc97d0d4a13edafbad95a00ad8b7ffe))
and grounded in the Linux kernel coding style, NASA/JPL's "Power of 10" and
OpenBSD's `style(9)`.

The target is C that an experienced kernel or systems programmer would write.
It is plain and explicit, with concrete types, short functions and no layer
without a job. Every line should be traceable from where data enters to
where it is used.

The primary rule:

> **Validate untrusted bytes at the boundary. Trust concrete types after it.**

In skbouncer the boundaries are four: packet bytes in the kernel program,
the policy file, dockerd's replies, and the command line. Code past those
points works on checked structs and needs no second round of checks.

While the campaign's tag `eval-1.1` is the measured version, these rules are
applied as a review only. A change to `src/` after the measurement means
the report describes code that was not measured.

---

## 1. Types and data

1. **No `void *` where a concrete type works.** A `void *ctx` is right for a
   callback interface such as `ring_buffer__new()` or `skb_cgroup_walk()`.
   Anywhere else, pass the real struct.
2. **Decode once, at the boundary.** Parse the policy JSON into
   `struct skb_policy` in one place. Nothing downstream should touch a
   `json_t`. The same holds for dockerd replies and for packet bytes, which
   become a `struct skb_event` once.
3. **No conversion helpers for values that are already typed.** A function
   such as `as_u16()` or `safe_str()` means a type was lost upstream. Fix the
   type at its source and delete the helper.
4. **No fallback to zero.** Code that turns a missing value into 0 or `""` and
   carries on hides bugs. Either the value can be absent, and the absence has
   a meaning stated in the code, or it cannot, and its absence is an error.
5. **Fixed-width types only where the width matters.** Wire formats and maps
   shared with the kernel use `__u16`, `__u32`. Loop counters and sizes use
   `unsigned`, `size_t` or `int` as the C library does.
6. **No wrapper structs around one field.** A struct holding a single
   `uint64_t` adds a name and a dereference without adding a concept.
7. **No typedefs for structs or pointers.** The kernel style rule: write
   `struct skb_event *`, so the reader sees that it is a struct and a pointer.

## 2. Functions and structure

8. **Remove pass-through functions.** A function whose body is one call to
   another function, with the same arguments, is a second name for the
   same thing. Keep it only when it hides a dependency the caller must not
   see. The `skb_loader_*` map functions keep libbpf's skeleton private to
   `loader.c` and pass that test.
9. **Do not extract a helper used once** unless it names a real concept, such
   as `not_a_hello()` or `walk_hello()`. A helper that only moves five lines
   elsewhere makes the reader jump for nothing.
10. **Short functions that do one thing.** If a function needs a comment
    halfway down to say what its second half does, the second half is a
    function.
11. **Early returns over nesting.** Check the failure, return, and keep the
    main path at the left margin. Three levels of indentation is a warning.
12. **No temporary variable that is used once and adds no name.** Keep a
    temporary only when its name explains the value.
13. **No module that only forwards to another module.** Collapse layers that
    pass calls through unchanged.
14. **No option structs for two arguments.** An options struct earns its place
    when callers set different subsets of many fields, as with
    `struct skb_loader_opts`.
15. **No global state without a reason in a comment.** A static variable that
    a function keeps between calls must say why. `enforce.c`'s
    `scope_ids` is cleared and refilled on each sync, and says so.

## 3. Errors

16. **Check every return value that can fail,** and act on it. A call whose
    failure is ignored on purpose gets a `(void)` cast or a comment.
17. **Return `-errno` or 0 in one convention per module.** Do not mix
    `-errno`, `-1` with `errno` set, and `NULL`, within one interface.
18. **Report an error once, where it is handled.** A function that returns an
    error to its caller does not print it as well. The caller that decides
    what to do with it prints it.
19. **Do not swallow errors into a default.** `if (err) return 0;` turns a
    failure into a success. The only exception is a documented fail-open
    decision, such as `on_unknown` defaulting to allow.
20. **`goto err` for cleanup is idiomatic.** One label per function, releasing
    in reverse order of acquisition, is clearer than repeated cleanup in each
    branch. It is not slop.
21. **No checks for conditions that cannot happen.** A NULL check on a
    pointer the caller just allocated and checked, or a range check on a
    value already validated at the boundary, adds noise and suggests the
    reader cannot trust the code. Delete it, or turn it into an `assert()`
    if the invariant is subtle.

## 4. Memory and ownership

22. **State who owns each pointer** in the function's header comment when
    ownership is not obvious ("The map owns the string").
23. **Free in the reverse order of allocation,** in the function or module
    that allocated.
24. **Stack buffers with a stated bound,** sized by a named constant or the
    type (`INET_ADDRSTRLEN`, `IF_NAMESIZE`), never a magic 256.
25. **`snprintf` over `sprintf`, and check truncation where it changes
    meaning,** for example in a path that is opened afterwards.

## 5. Control flow and style

26. **Plain loops over clever ones.** No side effects inside conditions
    (`|| n++`), no empty-bodied loops used as searches, no comma operators.
27. **Readable switches.** A `switch` over an enum lists every value and
    returns from each case.
28. **No boolean comparisons with `true` or `false`.** Write `if (seen)`.
29. **Constants where they name a meaning.** `TLS_RECORD_HLEN`, not `5`.
    A literal whose meaning is obvious in place (`0`, `1`, `2` in `n * 2`)
    stays a literal.
30. **No premature optimisation.** A linear search over a 50-entry table is
    fine. Measure before replacing it.
31. **Kernel layout:** tabs, 8-column indent, 80-column lines where
    reasonable, braces as the kernel style prescribes.

## 6. Comments

32. **A comment says why, or warns of a trap.** It never restates the code.
33. **No narration of the development process** in source (milestone names,
    "fixed in", "now uses").
34. **No comment that only names the next line** (`/* loop over rules */`).
35. **One place for each explanation.** If the same fact is explained in
    three files, keep it in the one a reader meets first and delete the rest.
36. Comments follow the report's writing rules: flat sentences, British
    spelling, no "X, not Y", no rule of three.

## 7. eBPF specifics

37. **Bounds checks the verifier needs are not slop.** Every read against
    `data_end`, every `bpf_skb_load_bytes()` length bounded by a constant,
    every loop with a fixed maximum, stays, even where it looks redundant to
    a C reader. Each deserves a short comment if its reason is not obvious.
38. **`__always_inline` only where the verifier or performance needs it.** A
    helper the compiler would inline anyway does not need the attribute.
39. **One copy of logic shared with userspace,** in `include/skbouncer.h`,
    as `static inline` functions (`skb_is_grease()`). The policy check exists
    twice by necessity, in `check_policy()` and `skb_policy_explain()`, and
    the two must say that they mirror each other.
40. **Maps sized by named constants** from the shared header, so userspace and
    kernel agree.

## 8. Tests and tooling

41. **Tests check outcomes against an independent source,** such as the
    server's own log or `bpftool`, never against the code under test.
42. **A test helper is as plain as the code it tests.** The same rules apply
    to Python checkers and shell harnesses.

---

## Search patterns

Use these to find places to inspect. A match is a question, not a verdict.

```
void *            (void)            NULL;             == NULL   != NULL
goto              static            typedef           #ifdef    #if 0
malloc  calloc    realloc  free     strdup            sprintf   strcpy
_helper  _util  _wrapper  _manager  _handler  _process  _do_
safe_  as_  to_  get_  maybe_       TODO  XXX  FIXME
|| [a-z_]+\+\+    ;\s*$ (empty statement)    , [a-z_]+ = (comma)
```

## The de-slop test

Before keeping a line, a function or a file, ask:

1. Does this handle something that can happen? If not, delete it.
2. Is this complexity caused by a type lost upstream? If so, fix the type.
3. Does this function name a real concept, or only move lines? If the
   second, inline it.
4. Does this layer do anything besides forward? If not, collapse it.
5. Would a kernel maintainer write it this way? If not, write it that way.

## Preserve

These look like slop to a reader from a higher-level language and are not.

- `goto err` cleanup with one exit path.
- Checking every return value, including `snprintf` and `close` where a
  failure changes behaviour.
- Bounds checks and bounded loops in eBPF code, required by the verifier.
- `static` for every function not exported in a header.
- Thin accessor functions that keep a library's types private to one file.

## Process

1. Find where data enters: packet bytes, policy file, dockerd, command line.
2. Check that each boundary validates fully, once.
3. Follow the data inward and remove checks, conversions and wrappers the
   boundary already made unnecessary.
4. Run the search patterns over each file and apply the de-slop test to each
   match.
5. Make one kind of change per commit, so each diff can be reviewed alone.
6. Run the full verifier chain after each commit. A change in behaviour
   means the cleanup went too far.

## The most important rule

Simple code that is easy to trace beats clever code that is short. Fewer
lines is a side effect, not the goal.
