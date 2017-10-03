irmago
======

**DO NOT USE!** This library is in heavy development and is in constant flux. It is not ready for use.

Irmago is an IRMA client in Go: it can receive IRMA attributes, store them, disclose them to others, and use them to create attribute-based signatures. In more detail: 

 * It is the client (like the [IRMA Android app](https://github.com/credentials/irma_android_cardemu)) in the [IRMA protocol](https://credentials.github.io/protocols/irma-protocol/)
 * It parses [credential and issuer definitions and public keys](https://github.com/credentials/irma_configuration)
 * It also implements the [keyshare protocol](https://github.com/credentials/irma_keyshare_server) and handles registering to keyshare servers.
