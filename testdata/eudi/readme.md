## Contents

| file | description |
|---|---
| `holder_ec_priv.pem` | test holder ECDSA private key |
| `holder_ec_pub.jwk` | jwk formatted version of the test holder ECDSA public key |
| `holder_ec_pub.pem` | test holder ECDSA public key |
| `issuer_cert_irma_app.pem` | self-signed certificate using `issuer_ec_priv.pem` and `irma.app` as the host name |
| `issuer_cert_openid4vc_staging_yivi_app.pem` | self-signed certificate using `issuer_ec_priv.pem` and `openid4vc.staging.yivi.app` as the host name |
| `issuer_ec_priv.pem` | test issuer ECDSA private key |
| `issuer_ec_pub.jwk` | jwk formatted version of the test issuer ECDSA public key |
| `issuer_ec_pub.pem` | test holder ECDSA private key |


Pem formatted ECDSA keys were generated using the following commands:

```bash
# generate priv key
openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem

# generate pub key
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

Pem formatted keys are converted to jwk formatted keys using [jwker](https://github.com/jphastings/jwker).


Self-signed certificates are generated using the `gen-cert.sh` script.
You can change the private key and DNS/URI by changing the parameters on the first two lines.

Certificate chains are generated with the `gen-cert-chain.sh` script.
You can change the private key and DNS/URI by changing the parameters on the first two lines.
