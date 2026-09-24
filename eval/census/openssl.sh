# Sourced by run.sh. OpenSSL 3.5.8 across key exchange options.
OS="openssl s_client -connect @SIP@:@PORT@ -servername @SNI@ </dev/null"
run_case "openssl 3.5.8 default"             skb-tls-test "$OS"
run_case "openssl X25519 only (classical)"   skb-tls-test "$OS -groups X25519"
run_case "openssl secp256r1 only (classical)" skb-tls-test "$OS -groups secp256r1"
run_case "openssl X25519MLKEM768 only"       skb-tls-test "$OS -groups X25519MLKEM768"
run_case "openssl SecP256r1MLKEM768"         skb-tls-test "$OS -groups SecP256r1MLKEM768"
run_case "openssl SecP384r1MLKEM1024"        skb-tls-test "$OS -groups SecP384r1MLKEM1024"
run_case "openssl MLKEM768 (pure PQ)"        skb-tls-test "$OS -groups MLKEM768"
run_case "openssl MLKEM1024 (pure PQ)"       skb-tls-test "$OS -groups MLKEM1024"
run_case "openssl TLS 1.2 only"              skb-tls-test "$OS -tls1_2"

