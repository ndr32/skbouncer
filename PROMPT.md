# Loop task: M7.3 — fuzz and attribution harnesses

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

Two new harnesses for `eval/PLAN.md`: `eval/fuzz.sh` (experiment 3, C16)
and `eval/attrib.sh` (experiment 7, C24). Like `eval/collect.sh`, they run
skbouncer in audit mode, save raw data and score nothing. skbouncer is
frozen at the `eval-1` tag; `eval/collect.sh` and `eval/cost.sh` show the
house style.

## eval/fuzz.sh

```
eval/fuzz.sh --out DIR [--n N] [--seed S]
```

Sends malformed ClientHellos through skbouncer, one per TCP connection.
Defaults: N = 5000, S = 1.

1. Originals: at least four real ClientHello records (record header and
   body) taken from `eval/census/logs/`, including a classical OpenSSL
   client, a post-quantum one, the TLS 1.2-only client and a browser.
2. Mutants: N, from the originals, deterministic in S, so two runs with one
   seed send identical bytes. Four kinds, each at least 10% of N:
   - `flip`: random bytes changed;
   - `truncate`: the record cut short at a random length;
   - `length`: a length field set wrong (record, handshake, session id,
     cipher list, extensions, or one extension);
   - `insert`: random bytes inserted.
3. Network: a server container (`skb-tls-test`) running a sink on one port
   that reads each connection to EOF and logs the peer's port and the byte
   count. An anchor container with Python, joined by the client. skbouncer
   in audit mode on the anchor's veth (`--container`), `--format json`.
4. Client: one Python process in the anchor's namespace. For each original,
   then each mutant: connect, record the local port, send the bytes in one
   `sendall`, shut down writing, read to EOF, close.
5. After the last connection: record whether skbouncer is still running and
   how many `skb_tc` programs are on the veth, then stop it with SIGINT.
6. `DIR/mutants.jsonl`, one object per connection in send order:
   `{"i", "kind", "sport", "hex", "received", "events"}`. `kind` is
   `original` or a mutation kind; `received` is the sink's byte count for
   that port; `events` is every skbouncer event whose `sport` is this one.
7. `DIR/run.json`: `{"n", "seed", "sent", "alive_at_end", "attached_at_end",
   "counters": {"detected", "delivered", "dropped", "short"}}`.
8. `DIR/env.txt` from `eval/env.sh`, and the raw `skbouncer.jsonl`,
   `skbouncer.err` and sink log.

## eval/attrib.sh

```
eval/attrib.sh --out DIR --containers N [--handshakes K]
```

N containers make K TLS handshakes each, all containers at once. Default
K = 5. N is a multiple of 10.

1. A server container (`skb-tls-test`) running one `openssl s_server` per
   client container, each on its own port, with `-naccept K`.
2. Client containers (`skb-tls-test`), each named. Half of them stand alone
   with their own veth. The other half are in groups of five that share
   one network namespace: the first of each group has the veth and the
   other four join it with `--network container:<first>`.
3. One skbouncer instance per veth, in audit mode, `--container` on the
   container that owns the veth, `--format json`. All attached before any
   handshake starts.
4. Start every container's K handshakes at the same moment
   (`openssl s_client` to its own port, one after another inside the
   container). Wait for all, then stop every instance with SIGINT.
5. `DIR/containers.jsonl`, one object per container:
   `{"name", "shared", "veth", "ip", "dport", "handshakes_ok", "events"}`.
   `handshakes_ok` counts `CONNECTION ESTABLISHED` in its client output;
   `events` is every event, from any instance, whose `dport` is this
   container's port.
6. `DIR/run.json`: `{"containers", "handshakes", "instances",
   "counters": [one {"veth", "detected", "delivered", "dropped", "short"}
   per instance]}`.
7. `DIR/env.txt` from `eval/env.sh`, and each instance's raw output.

## Done means `scripts/verify-M7.3.sh` passes

It runs `fuzz.sh` twice with 300 mutants and seed 7, and `attrib.sh` with
10 containers and 3 handshakes, and checks them against its own decode.
About five minutes. It prints, without failing on it, how many fields
skbouncer flagged complete that differ from its decode of a mutant: that
is the measurement, about a frozen tool.

## Rules

- skbouncer is frozen: never edit `src/`, `include/`, `Makefile` or
  `policy/`. The verifier fails if they differ from `eval-1`.
- Never edit `scripts/verify-*.sh`, `tests/`, `scripts/loop.sh`,
  `scripts/guard.sh`, `eval/census/`, `eval/env.sh`, `eval/collect.*`,
  `eval/cost.*`, `eval/functional.sh` or the client lists. If you believe a
  verifier is wrong, say so in `PROGRESS.md` and stop.
- Audit mode only. Never run enforce mode.
- Name everything `skb-fuzz-*` or `skb-attrib-*` and remove it on exit,
  on failure and Ctrl-C too.
- `sudo -n` works for `./skbouncer` and `bpftool` only.
- Never run `apt`, `apt-get`, `apt-mark`. Never regenerate `src/bpf/vmlinux.h`.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
