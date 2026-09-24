## Split per client and path MTU (IPv4, TCP timestamps on)

`·` fits · `S` split, ciphers and versions still in segment 1 · `V` split before supported_versions ends · `C` split inside the cipher list

| Client | Record | Key shares | 1500 Ethernet | 1492 PPPoE | 1460 GCP | 1450 VXLAN | 1420 WireGuard | 1400 IPsec | 1280 Tailscale |
|---|---:|---|---|---|---|---|---|---|---|
| openssl 3.5.8 default | 1543 | X25519MLKEM768 + X25519 | S | S | S | S | S | S | S |
| openssl X25519 only (classical) | 309 | X25519 | · | · | · | · | · | · | · |
| openssl secp256r1 only (classical) | 342 | secp256r1 | · | · | · | · | · | · | · |
| openssl X25519MLKEM768 only | 1485 | X25519MLKEM768 | S | S | S | S | S | S | S |
| openssl SecP256r1MLKEM768 | 1518 | SecP256r1MLKEM768 | S | S | S | S | S | S | S |
| openssl SecP384r1MLKEM1024 | 1934 | SecP384r1MLKEM1024 | S | S | S | S | S | S | S |
| openssl MLKEM768 (pure PQ) | 1453 | MLKEM768 | S | S | S | S | S | S | S |
| openssl MLKEM1024 (pure PQ) | 1837 | MLKEM1024 | S | S | S | S | S | S | S |
| openssl TLS 1.2 only | 210 | — | · | · | · | · | · | · | · |
| curl 8.22 (OpenSSL 3.5.8) | 1561 | X25519MLKEM768 + X25519 | S | S | S | S | S | S | S |
| python 3.14 urllib (OpenSSL 3.5.8) | 1517 | X25519MLKEM768 + X25519 | S | S | S | S | S | S | S |
| node 26 https (OpenSSL 3.5.8) | 1587 | X25519MLKEM768 + X25519 | S | S | S | S | S | S | S |
| go 1.27 net/http (crypto/tls) | 1532 | X25519MLKEM768 + X25519 | S | S | S | S | S | S | S |
| browser chrome116 | 512 | X25519 | · | · | · | · | · | · | · |
| browser chrome124 | 1784 | X25519Kyber768Draft00 + X25519 | S | S | S | S | S | S | S |
| browser chrome131 | 1784 | X25519MLKEM768 + X25519 | V | V | V | V | V | V | V |
| browser chrome150 | 1758 | X25519MLKEM768 + X25519 | S | S | S | S | S | S | S |
| browser edge101 | 512 | X25519 | · | · | · | · | · | · | · |
| browser firefox133 | 1860 | X25519MLKEM768 + X25519 + secp256r1 | V | V | V | V | V | V | V |
| browser firefox147 | 1896 | X25519MLKEM768 + X25519 + secp256r1 | V | V | V | V | V | V | V |
| browser safari184 | 512 | X25519 | · | · | · | · | · | · | · |
| browser safari260 | 1537 | X25519MLKEM768 + X25519 | V | V | V | V | V | V | V |
| browser safari260_ios | 512 | X25519 | · | · | · | · | · | · | · |
| browser tor145 | 581 | X25519 + secp256r1 | · | · | · | · | · | · | · |

## Repeated samples (20 connections each)

| Client | Record min–max | supported_versions ends at (min–max) | verdict certain @1500 | verdict certain @1492 | verdict certain @1460 | verdict certain @1450 | verdict certain @1420 | verdict certain @1400 | verdict certain @1280 |
|---|---|---|---|---|---|---|---|---|---|
| chrome150 | 1726–1822 | 147–1822 | 6/20 | 6/20 | 4/20 | 4/20 | 4/20 | 4/20 | 4/20 |
| firefox147 | 1800–1896 | 1564–1564 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
| safari260 | 1537–1537 | 1530–1530 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |
