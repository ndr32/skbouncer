# Progress log

Append only. Each iteration starts with no memory of the last one; record
failures in as much detail as successes.

## M2 — ClientHello detection on tc egress

Status: complete, tagged beta1.

### Baseline

- `make` builds clean; `./skbouncer` runs, loads only as root.
- M1 complete (2026-09-21), kernel 7.0.0-31-generic:

      264: sched_cls  name skb_egress  tag 691ef55febf78432  gpl
           loaded_at 2026-09-21T08:57:04+0000  uid 0
           xlated 16B  jited 20B  memlock 4096B  btf_id 179

  sched_cls confirms SEC("tc") resolves to the type clsact egress needs.
  Name is not truncated, so `bpftool prog show name skb_egress` works.
- `skbouncer.bpf.c` is a stub returning TC_ACT_OK. No maps, nothing attached.
- `struct skb_event` already has the M2 fields, plus `trunc_reason` for M3.

### Iterations

<!-- append below -->

#### 2026-09-21 — iteration 1

Implemented and verified. Detection is: IPv4 + TCP, payload starts with
`16 03 xx LL LL` and the first handshake byte is `01`, with `record_len`
sanity-bounded to 4..16384.

**Packet access.** Headers are read with direct access and a `data_end`
check each; the TLS bytes are read with `bpf_skb_load_bytes()` instead.
Reason: at egress `tcp_sendmsg()` parks the payload in page frags, so the
first payload byte is usually *not* in the linear area. Direct access there
would have meant `bpf_skb_pull_data()` on every TCP segment, which unclones
the skb. One 6-byte helper call per segment is cheaper and cannot go out of
bounds. No loops anywhere, so nothing to bound yet.

No verifier rejection at any point, so there is no verifier output to quote.

**Results.**

1. `make` clean, no warnings (after fixing three of my own: `PRIu64` is
   `"lu"` but `__u64` here is `unsigned long long`; cast and use `%llu`).
2. `sudo ./skbouncer -i lo` attaches. `bpftool net show`:

       tc:
       lo(1) clsact/egress skb_egress:[274] id 274

3. Real handshakes, one event each, no duplicates and no misses:

       109196.537297998 29467  192.168.86.131:39516 -> 172.66.147.243:443  1557
       109200.662711946 29554  192.168.86.131:39522 -> 172.66.147.243:443  1557

   Two `docker run` invocations, two events, two distinct cgroup ids.
   Checked the id is genuinely the container's: for container
   `572ead19ab70`, `stat -c %i` on
   `/sys/fs/cgroup/system.slice/docker-572ead....scope` is 29641 and the
   event carried `cgroup_id=29641`. So `bpf_skb_cgroup_id()` at tc egress
   gives exactly what M4 needs.
4. Silent on non-TLS: two plain HTTP requests over `lo`, one over `ens33`,
   and three pings all produced zero events.

**Worth noticing for M3.** `record_len=1557` on `ens33`, where the MSS
payload is 1448. That ClientHello was already spread over two segments and
we still emitted exactly one event, because only the first segment carries
the record header. That is the fragmentation case the project is about, and
it is present in stock curl without any PQC arm.

**Deviation on exit criterion 3.** The literal command
`docker run --rm curlimages/curl -sI https://example.com` cannot run on this
host: containers on the default bridge have no connectivity at all. From a
bridge container, `ping 172.17.0.1` (its own gateway) is 100% loss and
`connect()` to a public IP fails in ~3s. Not a DNS problem — the container
gets `nameserver 192.168.86.2` and `--dns` does not help. `ip_forward=1`,
no `daemon.json`, `Firewall Backend: iptables`, `ufw` has `ENABLED=no`.
Diagnosing further needs `iptables -L` / `nft list ruleset`, and sudo here is
NOPASSWD only for `bpftool` and `./skbouncer`, so it stopped there.

Verified instead with `docker run --rm --network host curlimages/curl -sI
https://example.com` — a real container, real handshake, real container
cgroup id, same code path. The one thing this does *not* cover is a
*forwarded* skb: in bridge mode the ClientHello reaches `ens33` egress after
routing, with `skb->sk == NULL`, so `bpf_skb_cgroup_id()` will return 0.
Detection still works there (it reads the packet, not the socket), but
container attribution will not. **That is an M4 blocker and needs the host
bridge fixed before M4 starts.**

**Housekeeping.** A killed run used to leave its tc filter behind, so attach
now uses `BPF_TC_F_REPLACE` with a fixed handle/priority. `clsact` is shared
with the rest of the system, so the hook is only destroyed if we were the
ones who created it.

- [x] DONE M2


## M2.5 — make the fragmentation signal measurable

Status: not started.

### Baseline

- M2 verified independently: 3 handshakes -> 3 events, 5 non-TLS -> 0 events.
- `captured_len`, `trunc_reason`, `handshake_len`, `legacy_version` are
  declared but never assigned.
- `bpf_ringbuf_reserve()` failure returns TC_ACT_OK with no counter.
- `sizeof(struct skb_event)` is 560; 512 is the unused snapshot. Ringbuf is
  256 KiB, so capacity is 468 events rather than ~5400.
- Docker bridge was broken (docker0 had no IPv4 address) and is now fixed;
  containers reach the internet, so `--network host` is no longer needed.

### Iterations

<!-- append below -->
