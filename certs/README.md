# `certs/`

This directory is expected to contain certificates, keys, and revocation data used by `ocsp-responder`.

Files are intentionally gitignored (see `.gitignore`). Do not commit private keys.

## Expected Files

- `ocsp-signer.crt`: OCSP delegated signing certificate (must have `extKeyUsage = OCSPSigning`)
- `ocsp-signer.key`: Private key for the OCSP signer certificate
- `intermediate-ca.crt` (or any issuer certificate): Issuer certificate for the end-entity certificates checked by this responder
- `ca.crl`: Certificate Revocation List (CRL) in PEM or DER format (for `source.type: file`)

Exact filenames are configurable in `config/ocsp-responder.yaml`.

## Create An OCSP Signer Certificate (OpenSSL example)

1. Create a private key and CSR:

```bash
openssl genrsa -out certs/ocsp-signer.key 2048
openssl req -new -key certs/ocsp-signer.key -out /tmp/ocsp-signer.csr \
  -subj "/CN=OCSP Responder"
```

2. Create an OpenSSL extension file that includes OCSPSigning:

```bash
cat > /tmp/ocsp-signer.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=OCSPSigning
EOF
```

3. Sign the CSR with your CA:

```bash
openssl x509 -req -in /tmp/ocsp-signer.csr -CA certs/issuer.crt -CAkey certs/issuer.key \
  -CAcreateserial -out certs/ocsp-signer.crt -days 365 -sha256 \
  -extfile /tmp/ocsp-signer.ext
```

## Export A CRL (OpenSSL example)

How you generate/export a CRL depends on your CA setup. With an OpenSSL CA configuration:

```bash
openssl ca -gencrl -out /tmp/ca.crl.pem -config openssl.cnf
openssl crl -in /tmp/ca.crl.pem -outform DER -out certs/ca.crl
```

`ocsp-responder` accepts both PEM and DER CRLs.

