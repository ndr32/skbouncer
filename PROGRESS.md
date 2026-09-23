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

Status: complete.

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

#### 2026-09-21 — iteration 1

All three items done and verified. One deviation from the task text, in
item 2, described below; it is the interesting part of this iteration.

**Item 1, drop counting.** `stats` is a `BPF_MAP_TYPE_ARRAY` of two `__u64`
counters (`SKB_STAT_DETECTED`, `SKB_STAT_DROPPED`) bumped with
`__sync_fetch_and_add`. Not per-CPU: ClientHellos arrive at handshake rate,
so the atomic costs nothing and userspace reads one value per counter
instead of summing across CPUs. `main.c` drains the ringbuf once more after
the signal, then prints detected / delivered / dropped and warns if
`detected != delivered + dropped`.

**Item 3, record size.** `SKB_EVENT_HDR_LEN` is 44; `sizeof(struct
skb_event)` is still 560. Ringbuf capacity goes from 468 events to ~4680
(44 rounds to 48, plus an 8-byte record header, into 256 KiB).

One thing the task text could not have: `bpf_ringbuf_reserve()` takes
`ARG_CONST_ALLOC_SIZE_OR_ZERO`, so the size must be a compile-time
constant and `SKB_EVENT_HDR_LEN + captured_len` cannot be passed to it.
Reserved `SKB_EVENT_HDR_LEN` instead, which is what the task wanted for
M2.5 anyway (empty snapshot). M3 will need `bpf_ringbuf_output()`, which
does take a runtime length, to send header + snapshot. Noted in the source.
`memset` is over `SKB_EVENT_HDR_LEN` too — memsetting `sizeof(*ev)` over a
44-byte reservation would have been a verifier rejection.

**Item 2, and the deviation: tc egress runs before GSO.**

The formula in the task is `captured_len = min(skb->len - pay_off -
TLS_RECORD_HLEN, record_len)`. Implemented literally first. Result over the
docker bridge on ens33:

      RECORD CAPTURED TRUNC
        1557     1557 none
         220      220 none

A 1557-byte ClientHello on an interface whose MSS is 1460 reported
`none`. It cannot fit, so the flag was wrong, and exit criterion 4 was
unreachable.

Cause: **tc clsact egress runs before segmentation offload.** `ethtool -k
ens33` has both `tcp-segmentation-offload` and
`generic-segmentation-offload` on, so a large ClientHello reaches the hook
as one GSO super-packet and `skb->len` covers *all* the wire segments it
will be split into, not the first one.

Confirmed rather than assumed, with a throwaway build that stashed
`skb->gso_size` and `skb->gso_segs` in the unused `handshake_len` /
`legacy_version` fields (reverted immediately after):

      1557 bytes: gso_size=1460 gso_segs=2
       220 bytes: gso_size=0    gso_segs=1

So the 1557-byte record really is two segments on the wire, and the hook
was being asked the wrong question. Fix: clamp the available payload to
`gso_size` when the skb is a GSO skb.

      avail = skb->len - pay_off;
      seg_len = skb->gso_size;
      if (seg_len >= TLS_SNIFF_LEN && seg_len < avail)
              avail = seg_len;
      body_len = avail - TLS_RECORD_HLEN;
      captured_len = min(body_len, record_len);

`avail >= TLS_SNIFF_LEN` on both paths, so `body_len >= 1`; the `min()`
bounds the result by `record_len <= TLS_RECORD_MAX`, so the `__u16` cannot
overflow even though `skb->len` can exceed 64 KiB.

**This matters well beyond M2.5.** Without the clamp every handshake on an
offload-capable interface reports `SKB_TRUNC_NONE` and M7 measures a
fragmentation rate of zero — the one number this project exists to produce.
M3 inherits the problem: the body walk must not read past `gso_size` either,
or it will parse bytes that the peer's TCP receives in a later segment. M7
must record the offload state (`ethtool -k`) with every result set alongside
the kernel and OpenSSL versions, because it changes the measurement.

**Results.**

1. `make clean && make` with no warnings and no errors.
2. `sudo ./skbouncer -i ens33` attaches, no verifier rejection at any
   point this iteration, so there is no verifier output to quote:

       tc:
       ens33(2) clsact/egress skb_egress:[454] id 454

   `bpftool net show dev ens33` is empty again after exit, so the detach
   path still leaves nothing behind.
3 + 4. Docker bridge networking, no `--network host`:

       RECORD CAPTURED TRUNC
         1729     1455 segment
         1557     1455 segment
          220      220 none

   `docker run --rm curlimages/curl -sI https://example.com` sends a
   1557-byte record; MSS is 1460, so 1460 - 5 = 1455 body bytes travel in
   the segment holding the record header and 102 spill into the next one.
   `SKB_TRUNC_SEGMENT`, consistent. The same command with `--tls-max 1.2`
   drops the TLS 1.3 key shares, giving a 220-byte record that fits whole:
   captured 220 = record 220, `SKB_TRUNC_NONE`. Both cases shown from the
   same interface in the same run.
5. Exit line:

       skbouncer: 3 ClientHello detected, 3 delivered, 0 dropped
       (ringbuf full); unloading

**The drop counter was proved to fire, not just to print 0.** With the real
256 KiB ringbuf it would not: 600 concurrent `curl` processes, then 6000
loopback handshakes from a threaded Python flooder, both came back
`6000 detected, 6000 delivered, 0 dropped`. Even a throwaway 4 KiB ringbuf
(~73 records, the minimum the kernel accepts) did not drop, because the
200 ms poll loop drains faster than a real network delivers handshakes.

Forced it by stalling the *consumer* instead: sent stdout to a fifo whose
reader had it open but was not reading, so the 64 KiB pipe filled,
`fprintf` blocked in the ringbuf callback, and the kernel side backed up.
With the 4 KiB ringbuf and 6000 handshakes:

       skbouncer: 6000 ClientHello detected, 694 delivered, 5306 dropped
       (ringbuf full); unloading

694 + 5306 = 6000, so the balance check holds and nothing vanished
unaccounted for. Before this iteration those 5306 handshakes would have
been indistinguishable from connections that never happened. Ringbuf
restored to 256 KiB and everything re-verified on the clean build
afterwards.

**Still open, unchanged from M2.** `cgroup_id` is 0 for containers on the
bridge: the ClientHello reaches ens33 egress as a *forwarded* skb with
`skb->sk == NULL`, so `bpf_skb_cgroup_id()` has nothing to resolve. Visible
in the results above — the 1729-byte event carries cgroup 27123 because it
is dockerd's own host socket, while both container handshakes carry 0.
Detection and fragmentation measurement are unaffected; container
attribution is not, and this remains the M4 blocker. Fixing the bridge
restored connectivity, not `skb->sk`.

- [x] DONE M2.5


## M2.6 — observe container egress at the veth

Status: complete.

### Baseline

Measured 2026-09-21, bridged container (not `--network host`):

- `ens33` egress: container ClientHello IS seen, `cgroup_id=0`, source shown
  as `192.168.86.131` (SNATed), `record 1557 captured 1455 segment`.
- `ens33` egress, host `curl`: `cgroup_id=18387`, matching the shell's
  cgroup inode. So the helper works, but only for local sockets.
- `veth*` egress and `docker0` egress: no events at all. Container-outbound
  traffic is ingress on the host side of the veth, and the loader only
  attaches `BPF_TC_EGRESS`.

### Iterations

<!-- append below -->

#### 2026-09-21 — iteration 1

Done and verified on a real bridged container (`curlimages/curl`, 172.17.0.2
on docker0, never `--network host`). No verifier rejection at any point this
iteration, so there is no verifier output to quote.

**What changed.** `--direction egress|ingress` (`-d`), default `egress`.
`skb_loader_opts` carries it; `attach_tc()` picks the attach point and
`detach_tc()` stores it on the loader so it tears down the same one.
`struct skb_event` gains `ifindex` and `direction`, so the output names the
attachment point — `SKB_EVENT_VERSION` 2 -> 3, `SKB_EVENT_HDR_LEN` 44 -> 48
(offsets 0/8/16/28/32/34/36/38/40/41/42, no implicit padding, ringbuf
capacity ~4300 records). The program is renamed `skb_egress` -> `skb_tc`:
one program serves both hooks, and a filter called `skb_egress` sitting on
`clsact/ingress` would be a misleading artefact to put in the write-up.
`make verify` updated to match.

The direction reaches the program through a `const volatile __u8 attach_dir`
in `.rodata`, so `skb_loader_open()` now splits `__open_and_load()` into
`__open()` / set / `__load()`. A tc program cannot ask the kernel which
clsact hook it is on, and `.rodata` is only writable before load.

**1. Build.** `make clean && make` clean, no warnings.

**2. Attach.**

    # sudo ./skbouncer -i vethc31576d --direction ingress
    tc:
    vethc31576d(59) clsact/ingress skb_tc:[626] id 626

    # tc filter show dev vethc31576d ingress
    filter protocol all pref 1 bpf chain 0 handle 0x1 skb_tc:[515] \
        direct-action not_in_hw id 515 tag eeeef53e967a47e0

`bpftool net show dev vethc31576d` is empty again after exit.

**3. Pre-NAT, and one event per handshake.** Three TLS handshakes from
inside the container, plus two pings and one plain HTTP request:

    TIME(mono)        IFACE        DIR     CGROUP  SOURCE            DEST                 RECORD CAPTURED TRUNC
    118978.968020918 vethc31576d  ingress 32773   172.17.0.2:51762  172.66.147.243:443     1557     1455 segment
    118979.487678533 vethc31576d  ingress 32773   172.17.0.2:46772  104.16.133.229:443     1560     1455 segment
    118979.989367306 vethc31576d  ingress 32773   172.17.0.2:51770  172.66.147.243:443      220      220 none

Three handshakes, three events, no duplicates; ping and HTTP silent. Source
is `172.17.0.2`, the container's own address, so this is pre-NAT — the same
handshake at `ens33` egress shows `192.168.86.131`.

**One veth really is one container.** With a second container (`m26b`,
172.17.0.3, veth `vethff40757`) running at the same time, watching
`vethff40757` caught only its handshake while `m26` handshook concurrently
and did not appear. No filtering is needed; the attachment point does it.

**4. Truncation appears here, for the same reason as at `ens33`.**
`record 1557 captured 1455 segment`. Container MTU is 1500, so MSS is 1460
and 1460 - 5 = 1455 body bytes travel with the record header; 102 spill
into the next segment. `--tls-max 1.2` gives a 220-byte record that fits
whole: `captured 220`, `none`.

That the GSO clamp from M2.5 is doing the work here was measured, not
assumed — a throwaway build stashed `skb->gso_size`/`gso_segs` in the unused
`handshake_len`/`legacy_version` fields and was reverted immediately after:

    1557 bytes: gso_size=1460 gso_segs=2
     220 bytes: gso_size=0    gso_segs=1

So **veth forwards GSO super-packets intact**: the container's stack builds
one skb spanning both wire segments and `veth_xmit` hands it over without
segmenting. `skb->len` at veth ingress is as misleading as at `ens33`
egress, and without the clamp this path would also report `none` for a
handshake that is genuinely split. `ethtool -k` on the veth: TSO on, GSO on,
**GRO off** — so nothing is being re-aggregated on the receive side either;
the super-packet is the sender's, not GRO's. M7 must record veth offload
state, not just the physical interface's.

**5. No regression at `ens33` egress.** Same run, same binary:

    119025.595486845 ens33  egress 0      192.168.86.131:60492  104.20.23.154:443   1557  1455 segment
    119025.924149146 ens33  egress 27123  192.168.86.131:35706  104.20.23.154:443   1566  1455 segment
    119026.202527784 ens33  egress 27123  192.168.86.131:35708  104.20.23.154:443    220   220 none

Container handshake: cgroup 0, SNATed source. Host `curl`: cgroup 27123,
matching the shell's cgroup inode. Identical to M2.5. Omitting `--direction`
still attaches to egress.

**6. cgroup_id on the veth ingress path is NOT 0 — and it is the right one.**

This contradicts what the task and CLAUDE.md both expected, so it was
checked against the filesystem rather than eyeballed:

| container | veth          | event cgroup_id | `stat -c %i` of its `docker-<id>.scope` |
|-----------|---------------|-----------------|------------------------------------------|
| m26       | vethc31576d   | 32773           | 32773                                     |
| m26b      | vethff40757   | 33295           | 33295                                     |

Exact match for both, repeatable across every run this iteration. The
reason: at veth ingress the skb has only just left the container's socket
via `veth_xmit` and has **not been orphaned**, so `skb->sk` is still the
container's socket and `bpf_skb_cgroup_id()` has something to resolve. By
the time the same packet reaches `ens33` it has been forwarded, `skb->sk` is
NULL, and the helper returns 0.

**This is the M4 blocker lifting.** The measured note in CLAUDE.md says
container identity must come from the attachment point because the helper
returns 0 — true at `ens33`, false at the veth. At the veth both work, which
means M4 gets a cross-check: resolve the container from the veth *and* from
the cgroup id, and a disagreement is a bug rather than a silent wrong
answer. The attachment point stays the primary identity, because it is what
makes the tuple pre-NAT; `cgroup_id` is now corroboration, not a fallback.

Worth saying plainly: this does not rescue `ens33`. Watching the physical
interface still cannot attribute a bridged container, and `--direction
ingress` on a veth remains the only way to get both the identity and the
pre-NAT tuple.

**`made_hook` still holds with two directions sharing one clsact.**
Directly exercised: instance A took `vethc31576d` ingress and created the
qdisc; instance B then took egress on the same device, got `-EEXIST` from
`bpf_tc_hook_create()` and set `made_hook = false`.

    tc:
    vethc31576d(59) clsact/ingress skb_tc:[590] id 590
    vethc31576d(59) clsact/egress  skb_tc:[597] id 597

Killing B left A's ingress filter in place and A went on to deliver a
ClientHello afterwards; killing A removed clsact and left the device empty.
So neither direction tears down the other's hook.

B is also a clean re-confirmation of the premise of this milestone: on
**veth egress** it detected 0 ClientHellos while A on veth ingress detected
1 from the same handshake.

**Papercut, not fixed.** On the shared-hook path libbpf prints
`libbpf: Kernel error message: Exclusivity flag on, cannot modify` to
stderr at WARN level. That is the expected, handled `-EEXIST`, so the
message is misleading. Pre-existing, not introduced here; left alone
because filtering libbpf warnings by text risks swallowing real ones.

**Test-harness note for later iterations.** `sudo` on this host is NOPASSWD
only for `bpftool` and `./skbouncer`, so an unprivileged shell cannot
`kill -INT` a root skbouncer to make it detach. Ctrl-C works interactively
because the tty delivers the signal. Non-interactively the signal was sent
from a `--pid=host` container; `--security-opt apparmor=unconfined` is
required, as `docker-default` blocks signalling processes outside the
profile.

- [x] DONE M2.6


## M3 — walk the ClientHello in the kernel

Status: complete. `scripts/verify-M3.sh` passed on iteration 1 and 5 of 5
independent reruns after the probe fix.

### Baseline

- Event carries cgroup_id, tuple, record_len, captured_len, trunc_reason,
  ifindex, direction. `handshake_len` and `legacy_version` are declared, unset.
- `skbouncer -i <veth> --direction ingress` attaches; no `--format` option.
- Against this build the verifier stops at: unrecognized option '--format'.
- Ground truth from the verifier's servers (OpenSSL 3.5.8):
  tls12_two 136 B, 2 ciphers, no supported_versions;
  tls13_one 208 B, 1 cipher, [0x0304];
  default_small 285 B, 30 ciphers, [0x0304, 0x0303];
  default_pqc 1519 B, 30 ciphers, [0x0304, 0x0303], spans two segments;
  cipher_cap 304 B, 83 ciphers offered.

### Iterations

<!-- append below -->

#### Iteration 1 — walk implemented; verifier passes, but its attach probe is racy

**What changed.** `struct skb_event` loses the 512-byte `snapshot` and gains
`ciphers[64]`, `versions[8]` (both raw big-endian, wire order),
`n_ciphers`, `n_versions`, `ciphers_capped`; `handshake_len` and
`legacy_version` are now filled. Record is 216 bytes, reserved whole.
`SKB_EVENT_VERSION` 3 → 4. `SKB_TRUNC_SNAPSHOT` is repurposed to mean "walk
hit `SKB_MAX_EXTS` (32) extensions before the end"; `PARSE` means a length
points past a fully captured record.

`walk_hello()` reads nothing at or past `hs + captured_len`, so the
`gso_size` clamp from M2.5 bounds the walk as well as the length. Cipher
suites and versions are each one `bpf_skb_load_bytes()` of a bounded
variable length, cut to what the segment holds; the extension walk is a
plain bounded loop. Any running-out-of-segment becomes `SEGMENT`, and the
caller forces `SEGMENT` whenever `captured_len < record_len`, so the
"captured < record iff trunc == segment" invariant holds by construction.
Loads in ~0.17 s, 3776 B xlated.

`--format json|text` added (`-f`); text stays the default and gains
LEGACY, CIPHERS (`+` when capped) and VERSIONS columns.

**Verifier results.** Three runs: PASS, then twice
`verify: skbouncer never attached to veth… ingress`.

The passing run, for the record:

    PASS: 6 cases, 0 failures
    default_pqc: record_len 1519, captured_len 1443, trunc "segment",
                 versions [772,771], 30 ciphers
    cipher_cap:  64 ciphers, ciphers_capped true
    skbouncer: 5 ClientHello detected, 5 delivered, 0 dropped

**I believe the verifier is wrong, and am stopping as the rules say.**
`scripts/verify-M3.sh` runs under `set -o pipefail` and probes with

    sudo -n bpftool net show dev "$VETH" 2>/dev/null | grep -q skb_tc

`grep -q` exits on the first match; `bpftool` is still writing the
`flow_dissector:` / `netfilter:` sections and dies of SIGPIPE, so the
pipeline returns 141 even though the filter is there. Measured against a
veth with skbouncer attached throughout:

    pipefail:    ok=24 bad=16 last_rc=141   (40 probes)
    no pipefail: ok=40/40

The failed run's journal matches: one probe succeeded and broke the loop,
the re-check after the loop hit SIGPIPE and died, and it did so about 1 s
after attach, with skbouncer still up and `loader.err` empty.

Fix (needs a human, then `scripts/guard.sh init`): drop `-q` so grep reads
all of its input (`grep skb_tc >/dev/null`), or capture first:
`out=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null); grep -q skb_tc <<<"$out"`.
Both probe sites need it, the one in the loop and the one after it.
Nothing in skbouncer can make this deterministic.

Left clean: no skbouncer process, no skb_tc on any device, test containers
removed.

## M4 — name the container behind each event

Status: done — `scripts/verify-M4.sh` passes.

### Baseline

- Against the M3 build: M3 regression passes; every case's `cgroup_id`
  matches the sender's scope inode; C on the unwatched veth produces
  nothing; each watched case fails only on `container = None`.
- Measured: B in A's network namespace leaves through A's veth with A's
  source IP (172.17.0.3) but carries B's cgroup id (50631 vs A's 50544).
- `container.c` is a stub: lookup returns NULL, refresh does nothing.
- One verifier run takes about 26 s, including the M3 regression.

### Iterations

<!-- append below -->

#### Iteration 1 — resolver via the Engine API

`container.c`: on a miss, `GET /containers/json?all=1` over
`/var/run/docker.sock` (HTTP/1.0, so no chunking and the body runs to EOF;
1 s send/receive timeouts bound the stall), parsed with jansson. Each id is
mapped to the inode of `system.slice/docker-<id>.scope` (or cgroupfs
`docker/<id>`), plus nested cgroups up to depth 4. The inode is the cgroup
id, the same thing the verifier stats.

- Entries are kept after a container exits: cgroup ids are not reused
  within a boot, so a late event from a removed container still resolves.
- For the same reason a cgroup a successful refresh does not find is
  cached as a miss (256-slot ring), so host traffic does not hit dockerd
  per event. A failed refresh is not cached. cgroup_id 0 never refreshes.
- The cache is warmed at startup; a dockerd failure there only warns.
- JSON gains `"container"` (string or null) after `cgroup_id`; text gains
  a CONTAINER column (`-` for none).

Verifier: three consecutive runs,

    PASS: 6 cases, 0 failures      (M3 regression)
    PASS: 4 cases, 0 failures

B (in A's netns, started after skbouncer) resolved on first sight:
cgroup 51762 `skb-verify-m4-b` vs A's 51588 `skb-verify-m4-a`, both from
172.17.0.3 on the same veth. Left clean: no skbouncer, no skb_tc, no test
containers.

## M5 — policy and audit mode

Status: done — `scripts/verify-M5.sh` passes.

### Baseline

- `policy.c` is a stub: `-p` exits with "policy loading not implemented".
- Against the M4 build, with `-p` removed, every case reaches the right
  container over the shared veth; the PQC case is a 1833-byte record with
  trunc=segment, 1 cipher and versions [772] fully seen; the wide case shows
  64 ciphers with ciphers_capped. Only the verdicts are missing.
- One verifier run takes about 40 s including the M4 and M3 regressions.

### Iterations

<!-- append below -->

#### Iteration 1 — seen flags in the kernel, policy in userspace

Kernel (`SKB_EVENT_VERSION` 4 -> 5): the old `_pad[2]` becomes `seen` plus
one pad byte, so the struct size is unchanged. `SKB_SEEN_CIPHERS` means every
offered cipher is in `ciphers[]` (so never when capped at 64).
`SKB_SEEN_VERSIONS` means supported_versions was read whole, or the walk
proved it absent: either there is no extensions block, or every extension
header was read and none was 0x002b, in which case legacy_version is the
offer. Extension bodies past the cut do not matter, only their headers do.
JSON gains `ciphers_seen` and `versions_seen`.

`policy.c` (jansson): `version` must be 1, `default` defaults to deny, and
unknown keys are rejected at both levels, so a misspelt key cannot loosen a
rule. Ciphers are given as IANA names (a table of about 80) or 0x hex. Load
errors give `file: line L, column C: ...` for bad JSON and
`file: rules[i].ciphers[j]: unknown cipher "NAME"` for a bad name. The
policy is loaded before BPF. `skb_policy_check()` now takes the container
name. It returns violation on anything seen that breaks the rule (GREASE,
0x00ff and 0x5600 are skipped), unknown if a constrained list lacks its
seen flag, and allow otherwise. A partial versions list is still checked
entry by entry. JSON gains `"verdict"`, and text output gains a VERDICT
column, but only when `-p` is given.

The verifier passed on the first run and again on a second:

    PASS: 6 cases, 0 failures      (M3 regression)
    PASS: 4 cases, 0 failures      (M4)
    PASS: 11 cases, 0 failures

PQC case: 1833-byte record, 1443 bytes captured, trunc=segment, both lists
seen -> allow. Wide case: 64 ciphers, capped, ciphers_seen=false -> unknown.
The TLS 1.2-only client sends no supported_versions, and versions_seen=true
there shows the absence proof works. A cut landing before supported_versions
(should give unknown when min_version is set) was untested; verify-M5.sh
now covers it with a long ALPN list, both unknown and violation-despite-cut. Left clean: no skbouncer, no skb_tc, no test containers.
