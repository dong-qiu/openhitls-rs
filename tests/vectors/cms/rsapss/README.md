# RSA-PSS CMS test vectors (independent oracle)

Generated with OpenSSL 3.6:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k.pem
openssl req -new -x509 -key k.pem -sha256 -sigopt rsa_padding_mode:pss \
    -out cert.pem -days 3650 -subj /CN=psstest                 # cert is itself RSA-PSS-signed
openssl cms -sign -in data.txt -signer cert.pem -inkey k.pem -md sha256 \
    -keyopt rsa_padding_mode:pss -outform DER -nodetach -out rsapss_cms.der
openssl x509  -in cert.pem -outform DER -out rsapss_cert.der
openssl pkcs8 -topk8 -nocrypt -in k.pem -outform DER -out rsapss_key_pkcs8.der
```

- `rsapss_cms.der`       — SignedData (SHA-256 + RSASSA-PSS), signer cert embedded, content "test data\n"
- `rsapss_cert.der`      — the self-signed RSASSA-PSS signer certificate (sig alg = rsassaPss)
- `rsapss_key_pkcs8.der` — the RSA private key (PKCS#8)
