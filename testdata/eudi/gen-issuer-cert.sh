
DIR="cert_issuer"

mkdir -p $DIR

PRIV_KEY="issuer_ec_priv.pem"
URI="openid4vc.staging.yivi.app"


echo "
[ req ]
default_md 			  = sha256
distinguished_name 	= req_distinguished_name
prompt 			      = no
req_extensions    = v3_req
x509_extensions		= v3_ext

[ req_distinguished_name ]
C 	= NL
ST 	= Utrecht
L 	= Utrecht
O 	= Yivi
CN 	= $URI

[ v3_req ]
subjectAltName = @alt_names
basicConstraints = critical,CA:false
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
2.1.123.1 = ASN1:UTF8String:{\\\"registration\\\":\\\"https://portal.dev/organizations/yivi/\\\",\\\"organization\\\":{\\\"legalName\\\":{\\\"en\\\":\\\"Yivi B.V.\\\",\\\"nl\\\":\\\"Yivi B.V.\\\"}},\\\"ap\\\":{\\\"authorized\\\":[{\\\"credential\\\":\\\"test.test.email\\\",\\\"attributes\\\":[\\\"email\\\", \\\"domain\\\"]}, {\\\"credential\\\":\\\"test.test.mobilephone\\\",\\\"attributes\\\":[\\\"mobilephone\\\"]}]}}

[ alt_names ]
URI.0 = https://$URI
DNS.0 = $URI

[ v3_ext ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
" > "$DIR/end-entity.ext"


# signing request
openssl req -new -key "$PRIV_KEY" -out "$DIR/cert.csr" \
  -subj "/C=NL/O=Yivi/CN=$URI"

# create the certificate
openssl x509 -req -in "$DIR/cert.csr" -signkey "$PRIV_KEY" -out "$DIR/cert.pem" \
  -days 3650 -sha256 -extfile "$DIR/end-entity.ext" \
  -extensions v3_req

