# CMS / X.509 chain-validation test vectors

A small RSA-2048 PKI hierarchy plus fixtures for the PKI chain-validation
hardening tests (`hitls-pki`: CMS signer-chain trust + X.509 minimum
security-bits enforcement).

## Trust hierarchy

```
root_ca (self-signed, RSA-2048)
└── mid_ca (RSA-2048, CA)
    ├── device1 (RSA-2048, leaf, digitalSignature) — CMS signer
    ├── device2 (RSA-2048, leaf)
    └── weak1024 (RSA-1024, leaf) — deliberately weak, for the secbits floor
```

`*.key` are the matching private keys. `mid_ca_*.crl` are CRLs used by the
revocation tests.

## Fixtures added for chain-validation hardening

| File | Purpose | Generated with |
|---|---|---|
| `device1_signed_attached.cms` | Attached CMS SignedData over `chain_msg.txt`, signed by `device1`, embedding `device1`+`mid_ca` | `openssl cms -sign -nodetach -in chain_msg.txt -signer device1.crt -inkey device1.key -certfile mid_ca.crt -outform DER -md sha256` |
| `chain_msg.txt` | Plaintext content of the CMS above | — |
| `weak1024.crt` / `weak1024.key` | RSA-1024 leaf signed by `mid_ca` (80-bit strength) | `openssl genrsa 1024` + `openssl x509 -req -CA mid_ca.crt -CAkey mid_ca.key -sha256` |

## Independent-oracle cross-checks (OpenSSL 3.6)

CMS signer-chain trust:

```
openssl cms -verify -in device1_signed_attached.cms -inform DER -CAfile root_ca.crt   # OK
openssl cms -verify -in device1_signed_attached.cms -inform DER -CAfile device1.crt   # REJECTED (no path to a root)
```

X.509 minimum security-bits (auth_level: 1 = 80 bits, 2 = 112 bits):

```
openssl verify -auth_level 1 -CAfile root_ca.crt -untrusted mid_ca.crt weak1024.crt   # OK   (1024-bit == 80 bits)
openssl verify -auth_level 2 -CAfile root_ca.crt -untrusted mid_ca.crt weak1024.crt   # FAIL (below 112-bit floor)
openssl verify -auth_level 2 -CAfile root_ca.crt -untrusted mid_ca.crt device1.crt    # OK   (2048-bit == 112 bits)
```

The Rust tests pin the same pass/reject boundaries, so a wrong implementation
cannot false-pass against these vectors.
