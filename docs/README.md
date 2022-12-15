# Docummentation

Most documentation can be found on [https://irma.app/docs](https://irma.app/docs).

Additionally, you can find the following sequence diagrams here:  
- [All session endpoints](./allSessionEndpoints.puml) marked in a complete disclosure flow.
- [A chained sessions flow](./chainedSession.puml) with an issuance followed by disclosure.
- [Disclosure flow](./IRMAflowDisclosure.puml) 
- [Issuance flow](./IRMAflowIssuance.puml) 
- [Keyshare server endpoints](./keyshareEndpoints.puml) - not a sequence but the single keyshare server endpoints in a diagram. The issuer functionality of the keyshare server is also omitted here.
- [Keyshare session with device binding](./keyshareEndpointsECDSA.puml) - the endpoint changes done to ensure app is bound to the device. This diagramm focuses on the keyshare server and does not include proofing to the issuer/verifier that the app is bound to the device.
- [Simplified keyshare server diagram](./keyshareSimple.puml)
- [Issuance flow with pairing functionality](./pairing.puml) - marks the endpoint invocations when pairing is enabled.
- [Session sates](./sessionStates.puml) with JSON blobs in comments. This diagram was made during the implementation of the stateless IRMA server and may not be up-to-date. For up-to-date information check [https://irma.app/docs](https://irma.app/docs).