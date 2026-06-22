# SM2 CMS test vectors (independent oracle)

Generated with OpenSSL 3.6 from one SM2 key/cert. **Note the explicit
`distid`**: GB/T 35275 / GM/T 0003 fix the SM2 distinguishing-ID to
`1234567812345678`, which is what this library uses. OpenSSL's *default* SM2
ID is empty, so the CMS must be signed with `-keyopt distid:1234567812345678`
to be GM-standard-conformant (and verifiable by a GM peer).

```
openssl ecparam -genkey -name SM2 -out k.pem
openssl req  -new -x509 -key k.pem -sm3 -out cert.pem -days 3650 -subj /CN=sm2test
openssl cms  -sign -in data.txt -signer cert.pem -inkey k.pem -md sm3 \
    -keyopt distid:1234567812345678 -outform DER -nodetach -out sm2_cms.der
openssl x509  -in cert.pem -outform DER -out sm2_cert.der
openssl pkcs8 -topk8 -nocrypt -in k.pem -outform DER -out sm2_key_pkcs8.der
```

- `sm2_cms.der`       — SignedData (SM3 + SM2-with-SM3, GM distid, signer cert embedded, attached content "test data\n")
- `sm2_cert.der`      — the self-signed SM2-with-SM3 signer certificate
- `sm2_key_pkcs8.der` — the SM2 private key (PKCS#8)
