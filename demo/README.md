# `demo/` — one `docker compose` profile per fault

Fifteen profiles in one compose file, each showing one injected fault to an unmodified
program. A one-shot `build` service compiles the six libraries **from this checkout**
into a shared volume, so no published release is needed; each profile then writes one
rule file and runs a stock tool or a small probe under `LD_PRELOAD`.

## Run

```bash
git clone https://github.com/macstab/macstab-chaos-testing-libraries chaos && cd chaos
docker compose -f demo/docker-compose.yml run --rm mem1    # builds, runs the fault, exits
docker compose -f demo/docker-compose.yml down -v          # removes the built volume
```

Replace `mem1` with any profile below. `run --rm <profile>` runs `build` first on
every invocation (the profiles depend on its successful completion). `CHAOS_REPO`
points `build` at another checkout; the default is the parent of `demo/`.

All fifteen with a pass/fail tally (needs bash and the compose plugin):

```bash
bash demo/run-all.sh       # builds once, runs every profile: "15 PASS / 0 FAIL (of 15)"
```

`run-all.sh` passes a profile when its combined output matches the expected pattern
(case-insensitive), exits with the number of failed profiles, and removes the volume
at the end. A failed build is not reported separately; every profile then fails.

## The fifteen profiles

`io3`, `net3` and `dns3` (marked ★) are the faults of the accompanying write-up: a torn
WAL write, a mid-stream reset, and a DNS override. The output column was captured from
real runs; byte counts and timings vary between runs.

| Profile | Library · fault | Rule file contents | Output |
|---|---|---|---|
| `io1` | io · read returns `EIO` | `/data:read:EIO:1.0` | `cat: /data/f: Input/output error` |
| `io2` | io · bit flip on read (`CORRUPT`) | `/data:read:CORRUPT:0.5` | `read 18: CHECKSUM MISMATCH — silent corruption detected` |
| `io3` ★ | io · torn write (short count) | `/data:write:TORN:1.0` | `write(4096) returned 1317 — TORN short write, 2779 bytes lost` |
| `net1` | net · `connect` refused | `tcp4://127.0.0.1:6379:connect:ECONNREFUSED:1.0` | `connect -> [errno 111] Connection refused` |
| `net2` | net · `connect` timed out | `tcp4://127.0.0.1:6379:connect:ETIMEDOUT:1.0` | `connect -> [errno 110] Connection timed out` |
| `net3` ★ | net · `send` on a live session reset | `tcp4://*:9092:send:ECONNRESET:1.0` | `send -> [errno 104] Connection reset by peer` |
| `dns1` | dns · `REWRITE` to localhost | `dns://example.com:REWRITE:localhost` | `example.com → 127.0.0.1` |
| `dns2` | dns · transient `EAI_AGAIN` | `dns://example.com:EAI_AGAIN:1.0` | `getent … exit=2` (resolution failed) |
| `dns3` ★ | dns · `OVERRIDE` to a literal IP | `dns://example.com:OVERRIDE:127.0.0.1` | `example.com → 127.0.0.1` (no resolver query) |
| `time1` | time · `CLOCK_REALTIME` +1 h | `clock_gettime/realtime:OFFSET:3600000` | `delta=3600s` (a fresh token reads as expired) |
| `time2` | time · `CLOCK_MONOTONIC` backward | `clock_gettime/monotonic:OFFSET:0`, rewritten to `-5000` | `BROKEN: monotonic went BACKWARD — elapsed=-5000.0 ms` |
| `mem1` | memory · anonymous `mmap` → `ENOMEM` | `mmap/anon:ERRNO:ENOMEM` | `mmap(anon) FAILED: [errno 12] Cannot allocate memory` |
| `mem2` | memory · `mmap` +150 ms | `mmap:LATENCY:150` | `mmap took ~150 ms` |
| `proc1` | process · thread exhaustion | `pthread_create:FAIL_AFTER:EAGAIN,8` | `thread 9: pthread_create FAILED (Resource temporarily unavailable)` |
| `proc2` | process · `execve` blocked | `execve:ERRNO:EACCES` (+ `posix_spawn`, `posix_spawnp`) | `subprocess blocked (child exit=13) — parent still running` |

## How the profiles work

- **Build, not download.** `build` runs `make native` in `gcc:bookworm` and copies
  `build/libchaos-*.so` into the `chaoslibs` volume, which the profiles mount read-only
  at `/libs`. Builder and profiles share the image, so the objects always match the
  profiles' glibc.
- **Rules first.** Each profile writes `/tmp/.chaos-<lib>.conf` inside its own
  container before the preloaded program starts; the library constructor loads it, so
  the fault applies from the program's first call.
- **Probes.** `probes/*.c` are compiled inside the container at run time. `io1`,
  `dns1`, `dns2` and `dns3` use stock tools (`cat`, `getent`) and need no probe.
- **`net2` returns at once.** The `ETIMEDOUT` is injected before the real `connect`,
  so the call fails immediately with the error a backend gone dark produces after the
  kernel's timeout; no packet is sent and nothing waits.
- **`net3` faults only the client.** `send` and `recv` rules match either end of a
  connected socket, so the server runs **without** the preload. With the library in
  both processes, `tcp4://*:9092:send` would also match the server's sends (its local
  port is 9092).
- **`time2` needs the change check to see the rewrite.** A constant `OFFSET` preserves
  deltas, so the probe rewrites the rule file between two `CLOCK_MONOTONIC` reads. A
  library looks at its rule file at most every 1 ms once rules are loaded; when the
  second read follows the write within that millisecond it still sees `OFFSET:0`, and
  the probe prints `elapsed non-negative`. `clock_gettime/monotonic:REGRESS:5000`
  produces the same backward step from a single unchanged rule file.
