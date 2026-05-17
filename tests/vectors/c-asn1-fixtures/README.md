# c-asn1-fixtures — vendored openHiTLS PKI test corpus

This directory mirrors the openHiTLS C SDV test-data corpus used by the
X.509 / CSR / CRL / CMS / PKCS#12 parse tests. It is the
`docs/c-test-migration-plan.md` **Phase C §4.1** deliverable — the fixture
base that the migrated PKI negative-parse tests (`asn1_negative` and the
CSR/CRL families of Phase B) load via `include_bytes!` / `std::fs`.

## Provenance

Mirrored verbatim (`rsync -a`) from the openHiTLS C repository:

| Local subtree | Upstream source |
|---------------|-----------------|
| `cert/` | `openhitls/testcode/testdata/cert/` |
| `certificate/` | `openhitls/testcode/testdata/certificate/` |

1298 files, ~8.7 MB — DER / PEM / CRL / CRT / KEY / CSR / CMS / P12 test
artifacts. Every PKI SDV `.data` file references fixtures under these two
subtrees (`../testdata/cert/...`).

## License

openHiTLS is licensed **MulanPSL-2.0**, the same license as openHiTLS-rs, so
mirroring this test corpus is license-compatible. The files are generated
test artifacts (certificates, CRLs, CSRs, keys) — there is no third-party IP
beyond the openHiTLS project itself.

## Integrity

`MANIFEST.sha256` records the SHA-256 of every mirrored file (sorted, paths
relative to this directory). Re-derive after a re-mirror:

```sh
cd tests/vectors/c-asn1-fixtures
find cert certificate -type f | LC_ALL=C sort | while IFS= read -r f; do
  shasum -a 256 "$f"
done > MANIFEST.sha256
```

Do **not** hand-edit the mirrored files — they are an upstream snapshot. To
refresh, re-`rsync` from openHiTLS and regenerate the manifest.
