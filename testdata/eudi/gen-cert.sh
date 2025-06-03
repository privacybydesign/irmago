
DIR="cert"

mkdir -p $DIR

PRIV_KEY="issuer_ec_priv.pem"
URI="openid4vc.staging.yivi.app"


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
