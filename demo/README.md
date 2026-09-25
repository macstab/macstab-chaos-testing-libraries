# `demo/` — runnable proofs, one `docker compose` profile per fault

Fifteen faults, fifteen profiles, one compose file. Each profile builds the six `.so` **from source** into a
shared volume (guaranteed to work on any Docker host — no published release required), then runs a tiny probe
under `LD_PRELOAD` and prints the injected failure. Every output below was captured by actually running it.

## Run

```bash
git clone https://github.com/macstab/macstab-chaos-testing-libraries chaos && cd chaos
docker compose -f demo/docker-compose.yml run --rm mem1     # builds from source, runs the fault, exits
docker compose -f demo/docker-compose.yml down -v           # clean the built volume
```

Swap `mem1` for any profile below. (`run --rm X` runs the one-shot `build` service first automatically; `down -v`
clears the built volume if you want a clean slate.)

Or run **all fifteen** at once and get a green tally:

```bash
bash demo/run-all.sh          # builds once, runs all 15 profiles → "15 PASS / 0 FAIL (of 15)"
```

## The fifteen profiles

The three profiles marked **★** are the exact faults written up in the blog (`io` torn WAL, `net`
mid-stream reset, `dns` OVERRIDE); the rest are their siblings on the same libraries.

| Profile | Library · fault | Config written to `/tmp/.chaos-<lib>.conf` | Verified output |
|---|---|---|---|
| `io1`   | io · read returns `EIO`            | `/data:read:EIO:1.0`                       | `cat: /data/f: Input/output error` |
| `io2`   | io · bit-flip on read (`CORRUPT`)  | `/data:read:CORRUPT:0.5`                   | `read 18: CHECKSUM MISMATCH — silent corruption detected` |
| `io3` ★ | io · torn write (short count)      | `/data:write:TORN:1.0`                     | `write(4096) returned 1317 — TORN short write, 2779 bytes lost` |
| `net1`  | net · `connect` refused            | `tcp4://127.0.0.1:6379:connect:ECONNREFUSED:1.0` | `connect -> [errno 111] Connection refused` |
| `net2`  | net · `connect` hangs → times out  | `tcp4://127.0.0.1:6379:connect:ETIMEDOUT:1.0`    | `connect -> [errno 110] Connection timed out` |
| `net3` ★| net · one `send` mid-session resets | `tcp4://*:9092:send:ECONNRESET:1.0`       | `send -> [errno 104] Connection reset by peer` |
| `dns1`  | dns · `REWRITE` to localhost       | `dns://example.com:REWRITE:localhost`      | `example.com → 127.0.0.1` |
| `dns2`  | dns · transient `EAI_AGAIN`        | `dns://example.com:EAI_AGAIN:1.0`          | `getent … exit=2` (resolution failed) |
| `dns3` ★| dns · `OVERRIDE` to a literal IP   | `dns://example.com:OVERRIDE:127.0.0.1`     | `example.com → 127.0.0.1` (literal, no lookup) |
| `time1` | time · `CLOCK_REALTIME` +1h        | `clock_gettime/realtime:OFFSET:3600000`    | `delta=3600s` (a fresh token reads as expired) |
| `time2` | time · `CLOCK_MONOTONIC` backward  | `clock_gettime/monotonic:OFFSET:0` → `-5000` | `BROKEN: monotonic went BACKWARD — elapsed=-5000.0 ms` |
| `mem1`  | memory · anon `mmap` → `ENOMEM`    | `mmap/anon:ERRNO:ENOMEM`                   | `mmap(anon) FAILED: [errno 12] Cannot allocate memory` |
| `mem2`  | memory · `mmap` +150 ms latency    | `mmap:LATENCY:150`                         | `mmap took ~150 ms` |
| `proc1` | process · thread exhaustion        | `pthread_create:FAIL_AFTER:EAGAIN,8`       | `thread 9: pthread_create FAILED (Resource temporarily unavailable)` |
| `proc2` | process · `execve` blocked          | `execve:ERRNO:EACCES` (+`posix_spawn`)     | `subprocess blocked (child exit=13) — parent still running` |

## Notes that keep it precise

- **Build, not download.** The `build` service runs `make native` in `gcc:bookworm` and copies
  `build/libchaos-*.so` into the `chaoslibs` volume. All target images are Debian-**bookworm** (glibc), matching
  the built objects. To use the released artifacts instead, replace `build` with the `fetch` sidecar from the
  blog's integration section.
- **net endpoint matching is per-operation — this is the whole subtlety.** libchaos-net resolves `send` on the
  socket's **peer** (remote) address (`chaos_net_socket.c:502`) but `recv` on the **local** address (`:609`), and
  `connect` on the destination `sockaddr`. So `net3`'s `tcp4://*:9092:send:ECONNRESET` fires client-side (peer
  port = 9092), and `net3` runs its server **without** the preload so only the client's `send` is faulted. A
  client's `recv`, by contrast, would *not* match `tcp4://*:<remote-port>` (its local port is ephemeral) — recv
  faults fire on the **accept** side. `net2` uses `connect:ETIMEDOUT` for the same reason: it matches the
  destination directly, giving a reliable client-side timeout against a backend gone dark.
- **`time2`** rewrites the config between two `CLOCK_MONOTONIC` reads on purpose — a *constant* offset preserves
  deltas; the mid-flight jump is what drives elapsed time negative.
- **Probes** live in `probes/*.c` and are compiled inside the container at run time; `io1`/`dns1`/`dns2` use
  coreutils (`cat`, `getent`) and need no probe.
