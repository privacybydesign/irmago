// Package testissuer is a minimal in-memory mdoc issuer used to build fake
// credentials for tests. It is NOT intended for production use.
//
// The issuer produces a fake EU Age Verification credential as specified at
// https://ageverification.dev/av-doc-technical-specification/:
//   - docType:   eu.europa.ec.av.1
//   - namespace: eu.europa.ec.av.1
//   - attributes: age_over_18 (mandatory) + any requested age_over_NN
//
// The issuer mints a self-signed IACA root, signs a Document Signer cert
// chained to it, and produces a COSE_Sign1 over the MobileSecurityObject.
package testissuer
