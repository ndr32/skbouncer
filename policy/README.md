# Policy format

```json
{
  "version": 1,
  "default": "deny",
  "rules": [
    { "container": "payments-api",
      "min_version": "1.3",
      "ciphers": ["TLS_AES_128_GCM_SHA256", "0x1302"] },
    { "container": "batch-*", "min_version": "1.2" }
  ]
}
```

- `rules` are tried in order; the first whose `container` matches wins.
  `container` is a shell-style pattern (`*`, `?`, `[...]`) matched against
  the container name. Events with no container match no rule.
- `default` (`"allow"` or `"deny"`) applies when no rule matches.
- `min_version`: `"1.0"`, `"1.1"`, `"1.2"` or `"1.3"`. Omitted: any.
- `ciphers`: IANA names or hex (`"0xc02f"`). Omitted: any. An unknown
  name is a load error, so a typo cannot silently allow nothing.

## Verdicts

A ClientHello complies with a rule when **every** cipher it offers is in
`ciphers` and **every** version it offers is at least `min_version`.
Offering a weaker option at all is a violation, since the server may pick
it. Offered versions are `supported_versions` if present, else
`legacy_version`. GREASE values and the SCSVs 0x00ff and 0x5600 are ignored.

- `violation` — something observed breaks the rule. Certain even if the
  record was truncated.
- `unknown` — nothing observed breaks it, but a list the rule constrains
  was not seen in full (cut by truncation, or more than 64 ciphers).
- `allow` — otherwise.
