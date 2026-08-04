
SCHEME=http://
HOST=localhost

# generate verifier priv key
# openssl ecparam -name prime256v1 -genkey -noout -out verifier_ec_priv.pem

# generate verifier pub key
# openssl ec -in verifier_ec_priv.pem -pubout -out verifier_ec_pub.pem

# generate CA priv key
# openssl ecparam -name prime256v1 -genkey -noout -out ca_ec_priv.pem

# generate CA pub key
# openssl ec -in ca_ec_priv.pem -pubout -out ca_ec_pub.pem

# create root/ca certificate
# openssl req -x509 -new -key ca_ec_priv.pem -sha256 -days 3650 -out ca.crt \
#   -subj "/C=NL/O=Demo Verifier CA/CN=Demo Requestors Root"

# create verifier certificate request
# organizationIdentifier (OID 2.5.4.97) is the attribute a LoTE entry pairs with
# a certificate or SKI to key an entity: the certificate says which key, this says
# which legal entity, and a match needs both. The integration tests exercise that
# pairing, so the leaf has to carry one.
openssl req -new -key verifier_ec_priv.pem -out verifier.csr \
  -subj "/C=NL/O=Yivi/CN=localhost/serialNumber=1234/organizationIdentifier=VATNL-000000000"

# sign verifier certificate request
# 3650 days, not the 825 a TLS end-entity certificate would get: this is committed
# test material, and a two-year fuse means the suite fails on a Tuesday for reasons
# nobody remembers. The key is reused, so the subject key identifier — which list
# entries key on — survives this re-issue.
openssl x509 -req -in verifier.csr -CA ca.crt -CAkey ca_ec_priv.pem -CAcreateserial \
  -out verifier.crt -days 3650 -sha256 \
  -extfile end-entity.cfg -extensions v3_req

# put both ca and verifier certs in chain
# On Windows: Get-Content verifier.crt, ca.crt | Set-Content chain.pem
cat verifier.crt ca.crt > chain.pem


# create a p12 file from the certificate chain
openssl pkcs12 -export \
  -inkey verifier_ec_priv.pem \
  -in verifier.crt \
  -certfile ca.crt \
  -name verifier_cert \
  -out keystore.p12 \
  -passout pass:changeit

# allow everyone to read it
chmod a+r keystore.p12

# remove unused files
rm ca.srl verifier.csr
