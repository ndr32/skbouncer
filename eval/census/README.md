# ClientHello census

How big real ClientHellos are, and where they split, measured 2026-09-23.
Independent of skbouncer: sizes come from the TLS server's view of the bytes
it received (`openssl s_server -msg`), decoded by `parse.py`.

- Server: OpenSSL 3.5.8 with every key exchange group enabled, so no case
  triggers a HelloRetryRequest. Clients connect with SNI `api.example.com`.
- Clients: OpenSSL 3.5.8 across key exchange groups; curl 8.22, Python 3.14,
  Node 26 (all OpenSSL 3.5.8); Go 1.27 (crypto/tls); browsers reproduced by
  `lexiforest/curl-impersonate`. Chrome permutes extension order per
  connection, so Chrome 150, Firefox 147 and Safari 26 are sampled 20 times.
- Split model: the first TCP segment carries MTU - 52 bytes (IPv4 20 + TCP 20
  + timestamps 12). Matches the kernel measurement at MTU 1500 (M3: 1443
  bytes of record body captured). Other MTUs are modelled, not yet measured.

Reproduce: `FRESH=1 eval/census/run.sh` then
`python3 eval/census/analyze.py eval/census/results.jsonl`.

## Finding

Every post-quantum client splits at every common MTU; every classical client
fits. OpenSSL-based clients and Go put `supported_versions` before the key
share, so a TLS-version policy can still be judged from the first segment.
Current browsers put it after the 1.2 KB post-quantum key share: Firefox 147
0/20 and Safari 26 0/20 connections keep it in the first segment at MTU 1500,
Chrome 150 6/20. Cipher lists always survive. Full tables: RESULTS.md.
