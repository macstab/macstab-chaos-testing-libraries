# Upgrading

What changes for a rule file that worked with the previous release. Additions are not
listed here -- a rule file that does not use them is unaffected by them.

## 2.0.0 → 2.1.0

### Rule files that 2.0.0 accepted are now rejected

Parsing is all-or-nothing: one invalid line leaves the library with **no rules at all**,
and the status file `/tmp/.chaos-<lib>.status` says `state=error` with `line=`, `reason=`
and `text=`. A file that 2.0.0 loaded can therefore stop working entirely rather than
losing one line, which is the one upgrade step to check before anything else:

```sh
sed -n 1,4p /tmp/.chaos-io.status   # state=ok, or the line that was refused
```

Each of these was accepted before and could not do what its author meant. They are
rejected rather than warned about because there is no later major release to defer to,
and a rule that loads and never fires is the failure this release exists to remove.

| Rule | Before | Now |
|---|---|---|
| `clock_gettime/4294967297:OFFSET:1000` | the id was cut to 32 bits, so the rule hit `CLOCK_MONOTONIC` -- a different clock than the one written | `reason=invalid rule` |
| `open:ERRNO:EIO@size>100` | `@size` on an operation that reports no byte count: the rule could never match | `reason=invalid rule` |
| `relative/path:read:ERRNO:EIO` | an io selector that is neither `*` nor absolute: it matched nothing | `reason=invalid rule` |
| `dns://x:REWRITE:a#b` | the value was cut at the `#`, so the rule redirected to `a` | `reason=invalid rule` |
| `*:read:ERRNO:EIO@until=0` | `0` is the stored value for "no upper bound", so the window meant the opposite of what it said | `reason=invalid rule` |
| `unix:///run/x.sock:connect:REDIRECT:10.0.0.1:5432` | an address and a port cannot be written over a `sockaddr_un`: it could never fire | `reason=invalid rule` |

A `#` that starts a comment still needs a blank, tab, CR or the start of the line before
it; that has not changed. Only a `#` glued to the text before it is now refused instead of
silently shortening the value.

### Rules that fire differently

| Change | What to expect |
|---|---|
| **A `tcp4://*:<port>` rule now matches a dual-stack listener** (`AF_INET6` on `::` with `IPV6_V6ONLY=0`), as `tcp6://` already did. | A rule that did nothing against a JVM or Go server now fires. A concrete IPv6 address stays IPv6-only, and `IPV6_V6ONLY=1` stays IPv6-only. |
| **`close:RESET` applies only where the process is the socket's sole owner.** | On a pre-forking server (PostgreSQL, nginx, gunicorn) the postmaster's copy is no longer reset, because resetting it left a live `SO_LINGER` on a descriptor that outlives the close. Suppressions are counted in the hits file as `suppressed.shared=` and `suppressed.unknown=`, and they consume no hit and no `@first` claim, so the numbers drop where they used to be too high. |
| **Which call a probability picks is computed from the rule and the call, not from a per-thread stream.** | Fault *rates* are unchanged; *which* call is faulted is not. A test that pinned a particular sequence of faults sees another sequence. `CHAOS_SEED=<n>` in the environment now makes the whole sequence reproducible, which it could not be before. |
| **A forked child's `FAIL_AFTER` counter starts again under `chaos-init`**, as it always did under `LD_PRELOAD`. | A threshold rule now fires per child rather than once for the whole process tree. |
| **`time()` under `chaos-init` returns the shifted seconds** (x86-64 only; aarch64 has no such call). | A time rule now reaches a program that uses the return value of `time()`. Before, it answered 0 and a `time(NULL)` was left to the kernel entirely. |

### Platform

The arm64 shared objects are aligned to 64 KiB pages, which is what lets them load on a
kernel configured with them (CentOS/RHEL arm64, some Ampere images). They are about 20 KiB
larger per object as a result; amd64 is unchanged.
