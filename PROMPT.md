# Loop task: M7.1 — evaluation collector

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

`eval/collect.sh` runs a set of TLS clients against a server with skbouncer
watching, and saves raw data. It scores nothing: the experiments score what
it saves, later. skbouncer itself is frozen.

```
eval/collect.sh --out DIR --mtu N [--timestamps on|off] [--n K] [--policy FILE] CLIENTS
```

`CLIENTS` has one `label|image|command` per line; `#` lines and blank lines
are skipped. The command runs with `sh -c` in `image`. `@SIP@`, `@PORT@` and
`@SNI@` become the server's IP, the connection's port, and `api.example.com`,
which must resolve to the server. Defaults: timestamps on, K = 1.

## What it does

1. Everything it creates is named `skb-eval-*` and is removed when it exits,
   on failure and Ctrl-C too.
2. A Docker network with MTU N. A server container (`skb-tls-test`) with every
   key exchange group enabled, as in `eval/census/run.sh`, so no client
   triggers a HelloRetryRequest. One `openssl s_server -msg -naccept 1` per
   connection, each on its own port, logging to `DIR/server/<port>.log`.
3. An anchor container on the network, with `net.ipv4.tcp_timestamps` set by
   `--timestamps`. Each connection's client runs in its own named container
   that joins the anchor's network namespace (`--network container:<anchor>`):
   all traffic leaves through one veth, and each client keeps its own cgroup.
4. skbouncer in audit mode on the anchor's veth, ingress, `--format json`,
   with `-p` when `--policy` is given. Started before the first client,
   stopped with SIGINT after the last. Raw output in `DIR/skbouncer.jsonl`
   and `DIR/skbouncer.err`.
5. Before any client, the MSS: `getsockopt(TCP_MAXSEG)` on an established
   TCP connection from the anchor's namespace to the server. That is the
   payload one segment carries. It must not come from skbouncer.
6. `DIR/env.txt`, the output of `eval/env.sh`.
7. `DIR/run.json`:
   `{"mtu", "timestamps": "on"|"off", "n", "network", "anchor", "mtu_observed", "mss", "counters": {"detected", "delivered", "dropped", "short"}}`.
   `mtu_observed` is the anchor's `eth0` MTU; `counters` come from
   skbouncer's exit line.
8. `DIR/connections.jsonl`, one object per connection, K per client in file
   order:
   `{"label", "image", "container", "rep", "port", "mtu", "timestamps", "mss", "client_ok", "server", "events"}`.
   - `rep` counts 1 to K. `container` is the client container's name.
   - `client_ok`: the server log shows the client's Finished message. Not
     the client's exit status: curl against `s_server` times out after a
     good handshake.
   - `server`: decoded from the server log, the ground truth.
     `{"record_len", "legacy_version", "ciphers", "versions"}`, with every
     cipher and every `supported_versions` value as integers in wire order,
     GREASE included; `versions` is `[]` when the extension is absent.
   - `events`: every skbouncer event whose `dport` is this port, verbatim.

Also `eval/clients.txt`: the census clients (`eval/census/openssl.sh`,
`others.sh`, `browsers.sh`; not `samples.sh`) in the `CLIENTS` format, with
the census labels.

skbouncer names a container by asking dockerd, which lists running
containers only. Every event must name its client's container.

## Done means `scripts/verify-M7.1.sh` passes

It runs the collector at MTU 1500 and 1280 with timestamps on and 1500 with
them off, and checks the saved ground truth against its own decode of the
server logs. About two minutes.

## Rules

- skbouncer is frozen: never edit `src/`, `include/`, `Makefile` or `policy/`.
  The verifier fails if they differ from `main`.
- Never edit `scripts/verify-*.sh`, `tests/`, `scripts/loop.sh`,
  `scripts/guard.sh`, `eval/census/` or `eval/env.sh`. If you believe a
  verifier is wrong, say so in `PROGRESS.md` and stop.
- Audit mode only. Never run enforce mode.
- `sudo -n` works for `./skbouncer` and `bpftool` only; the collector needs
  nothing else as root.
- Never run `apt`, `apt-get`, `apt-mark`. Never regenerate `src/bpf/vmlinux.h`.
- Leave nothing running, attached or created; the verifier checks.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
