## Contents

| file | description |
|---|---
| `holder_ec_priv.pem` | test holder ECDSA private key |
| `holder_ec_pub.jwk` | jwk formatted version of the test holder public key |
| `holder_ec_pub.pem` | test holder public key |
| `issuer_cert_irma_app.pem` | self-signed certificate using `issuer_ec_priv.pem` and `irma.app` as the host name |
| `issuer_cert_openid4vc_staging_yivi_app.pem` | self-signed certificate using `issuer_ec_priv.pem` and `openid4vc.staging.yivi.app` as the host name |
| `issuer_ec_priv.pem` | test issuer private key |
| `issuer_ec_pub.jwk` | jwk formatted version of the test issuer public key |
| `issuer_ec_pub.pem` | test holder private key |


Pem formatted ECDSA keys were generated using the following commands:

```bash
# generate priv key
openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem

# generate pub key
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

Pem formatted keys are converted to jwk formatted keys using [jwker](https://github.com/jphastings/jwker).


Certificates are generated using the `gen-cert.sh` script.
You can change the private key and DNS/URI by changing the parameters on the first two lines.
```bash
PRIV_KEY="issuer_ec_priv.pem"
URI="openid4vc.staging.yivi.app"
DIR="cert"

mkdir -p $DIR

echo "
basicConstraints = critical,CA:false
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = 1.3.130.2.0.0.1.7
subjectAltName = @alt_names

[alt_names]
URI.1 = https://$URI
DNS.1 = $URI
" > "$DIR/end-entity.ext"

# signing request
openssl req -new -key "$PRIV_KEY" -out "$DIR/cert.csr" \
  -subj "/C=NL/O=Yivi/CN=$URI"

# create the certificate
openssl x509 -req -in "$DIR/cert.csr" -signkey "$PRIV_KEY" -out "$DIR/cert.pem" \
  -days 3650 -sha256 -extfile "$DIR/end-entity.ext"
```
