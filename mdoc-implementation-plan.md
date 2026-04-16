# mdoc Implementation Plan for Yivi Wallet

Supporting mdoc as a credential type with ISO/IEC 18013-5 (proximity) and OpenID4VP (remote) as disclosure protocols.

---

## Context

The EU Driving Licence Directive will mandate ISO/IEC 18013-5 as the reference standard for mDL issuance and verification. The Yivi wallet currently supports Idemix and SD-JWT VC credentials. The `go-passport-issuer` service already validates eMRTD chips (passports, eDLs, ID cards) using ICAO 9303 passive/active authentication, but outputs Idemix/SD-JWT credentials. The goal is to extend the stack to also issue and disclose **mdoc credentials** natively.

---

## Progress Summary (as of 2026-04-16)

| # | Component | Status |
|---|---|---|
| 1 | mdoc credential format | ✅ Done |
| 2 | Selective disclosure engine | ✅ Done |
| 3 | Device authentication & key binding | 🟡 Partial — DeviceSignature done; secure-element storage and DeviceMac variant deferred |
| 4 | Proximity transport | 🟡 Partial — data plane (engagement, session encryption, messages) done; BLE/NFC transport drivers deferred |
| 5 | OID4VP remote flow (mdoc additions) | ✅ Done |
| 6 | Trust infrastructure (IACA / DS verification) | ❌ Not started |
| 7 | OpenID4VCI `mso_mdoc` issuance | 🟡 Partial — CBOR construction + COSE_Sign1 signing done in a test issuer; OID4VCI wiring deferred |

### Cross-cutting work also landed

- **Storage integration** — mdoc credentials persist through the existing `CredentialStore` with `Format="mso_mdoc"`; device keys live in the existing `HolderBindingKey` table. Adapter: `eudi/services/mdoc_credential_service.go`.
- **Fake Age Verification test issuer** — `eudi/credentials/mdoc/testissuer/` mints a self-signed IACA → DS chain, builds an `eu.europa.ec.av.1` mdoc, and dumps fixtures under `testdata/`.

### Code layout

```
eudi/credentials/mdoc/
  mdoc.go                   # IssuerSigned, MSO, IssuerAuth, IssuerSignedItem
  selective_disclosure.go   # SelectFromIssuerSigned, BuildDeviceResponse
  oid4vp.go                 # BuildOID4VPSessionTranscript, SignDeviceAuth, VerifyDeviceAuth
  testissuer/               # fake AV credential issuer (tests + fixtures)
  proximity/                # DeviceEngagement + SessionEncryption (data plane only)
eudi/services/
  mdoc_credential_service.go  # stores mdoc in existing SQLCipher storage
eudi/openid4vp/
  eudi_mdoc_dcql/             # DcqlCredentialQueryHandler for mso_mdoc
  dcql/credential_query_handler.go  # DisclosureContext added (ResponseUri plumbing)
```

---

## Components to Implement

### 1. mdoc Credential Format (ISO 18013-5 §7) — ✅ Done

The core data model Yivi does not currently support. Requires a CBOR parser/builder for:

- ✅ `Document` structure (CBOR-encoded top-level container) — `mdoc.ExtractIssuerSignedFromDeviceResponse`, `mdoc.BuildDeviceResponse`
- ✅ `MobileSecurityObject` (MSO) — issuer-signed structure containing value digests per namespace
- ✅ `IssuerAuth` — a `COSE_Sign1` wrapping the MSO (with `X5Chain()` helper for DS cert extraction)
- ✅ `IssuerSignedItems` — individual data elements with salted SHA-256 digests; on-wire bytes preserved for digest re-verification
- 🟡 mDL namespace (`org.iso.18013.5.1`) data-element catalogue — the framework handles any namespace generically; the AV namespace (`eu.europa.ec.av.1`) is exercised end-to-end, but no formal registry of mDL element types/validators ships yet (wallet only needs to parse whatever the issuer signed).

Library choice: `github.com/fxamacker/cbor/v2` plus Go stdlib `crypto/*`. No COSE library needed for parsing; `veraison/go-cose` remains a candidate once IACA signature verification lands.

### 2. Selective Disclosure Engine for mdoc — ✅ Done

Unlike Idemix (ZKP-based), mdoc selective disclosure works by the holder revealing pre-images of salted hashes. Requires:

- 🟡 Consent/selection UI layer that understands mdoc namespaces and elements — the wallet-side data path is ready: stored credentials expose a `{namespace: {element: value}}` projection and the DCQL handler emits `clientmodels.Attribute` entries with `[ns, element]` claim paths. Actual UI wiring in the mobile apps is pending.
- ✅ Logic to construct a selective `IssuerSigned` response — `mdoc.SelectFromIssuerSigned` returns a byte-preserving subset so MSO digests continue to verify; `mdoc.EncodeIssuerSigned` re-assembles the CBOR without disturbing the signed bytes.
- ✅ Mapping between Yivi's attribute-consent model and mdoc's namespace/element model — OpenID4VP claim paths `[namespace, element]` (per §6.4.2) are translated in `eudi_mdoc_dcql.groupClaimPathsByNamespace`.

### 3. Device Authentication & Key Binding — 🟡 Partial

Required for both proximity and remote flows:

- 🟡 **Device key generation** — EC P-256 key generated in software (`crypto/ecdsa`) at issuance and persisted PKCS#8-encoded in the existing `HolderBindingKey` table. ❌ **Not in secure element yet** — Android Keystore / iOS Secure Enclave integration is still needed; this is the biggest remaining gap for production use.
- 🟡 **DeviceAuth** — `DeviceSignature` (COSE_Sign1, ES256, detached payload) implemented in `mdoc.SignDeviceAuth` + `mdoc.VerifyDeviceAuth`. ❌ `DeviceMac` (COSE_Mac0) variant not implemented — only matters when the wallet and verifier share a symmetric key derived from proximity ECDH, so this is deferred until a proximity verifier needs it.
- ✅ **SessionTranscript construction** — both variants shipped:
    - OID4VP: `mdoc.BuildOID4VPSessionTranscript(clientId, responseUri, nonce)` per OpenID4VP §B.2
    - Proximity: the `mdoc/proximity` package feeds the raw ISO 18013-5 §9.1.5 transcript straight into session encryption

### 4. ISO 18013-5 Proximity Transport Layer — 🟡 Data plane done; transport bindings deferred

For the roadside check / police scenario — the part OpenID4VP does not cover. The **data plane** (everything that doesn't touch physical radios) is TDD-covered against ISO 18013-5 Annex D vectors; the transport drivers are the remaining work.

- ✅ **QR Code engagement** — `proximity.ParseDeviceEngagement` / `proximity.EncodeDeviceEngagement` round-trip against Annex D; BLE connection method encoded (UUIDs, central/peripheral flags).
- ❌ **NFC engagement** — not implemented. The NFC handover payload shape is a known ISO 18013-5 CBOR structure; deferring until an actual NFC driver is in scope.
- 🟡 **BLE data transfer** — the `BLEConnectionMethod` struct carries the UUIDs/mode flags and round-trips through `DeviceEngagement`, but there is **no BLE central/peripheral driver** (GATT service, L2CAP, packetisation). Platform-specific work that can't be cleanly TDD'd; parked until hardware integration starts.
- ✅ **Session encryption** — `crypto/ecdh` for P-256, `crypto/hkdf` for SK.Device / SK.Reader derivation (salt = SHA-256 of tag-24-wrapped session transcript), AES-256-GCM with the spec's `0x00000000 ‖ ivIdentifier ‖ counter` nonce. Byte-for-byte match against Annex D.
- ✅ **SessionEstablishment** and **SessionData** message handling, including the termination status message and bidirectional counter tracking.

### 5. ISO 18013-7 / OID4VP Remote Flow (mdoc-specific additions) — ✅ Done

Yivi already supports OID4VP for SD-JWT, but mdoc requires additions:

- ✅ **`mso_mdoc` format identifier** in DCQL credential queries — `clientmodels.Format_Mdoc` constant; `MdocDcqlHandler.CanHandleCredentialQuery` matches on `format + doctype_value`.
- ✅ **`DeviceResponse` CBOR structure** as the `vp_token` value — base64url-encoded per OpenID4VP §6.4.2; handler emits the string through the existing `dcql.QueryResponse` channel.
- ✅ **OID4VP-specific `SessionTranscript`** — `mdoc.BuildOID4VPSessionTranscript` implements `[null, null, [clientIdHash, responseUriHash, nonce]]` per OpenID4VP §B.2. The `DcqlCredentialQueryHandler.PrepareDisclosure` signature was widened to `DisclosureContext{Nonce, ClientId, ResponseUri}` to thread `response_uri` through; SD-JWT handlers were migrated in the same change and ignore the new field.
- ✅ **DCQL claim-path mapping** — `[namespace, elementIdentifier]` two-component paths (per OpenID4VP §6.4.2 for mdoc) translate to `SelectFromIssuerSigned` input.

⚠️ **Interop caveat** — the DeviceAuth signature round-trips against our own `VerifyDeviceAuth`, but OpenID4VP Appendix B has moved between drafts. First contact with a third-party mdoc verifier will probably surface byte-level disagreements (exact hash inputs, tag wrapping) that need chasing.

⚠️ **Handler registration** — `MdocDcqlHandler` satisfies `DcqlCredentialQueryHandler` and is unit-covered, but the mobile apps' `openid4vp.NewClient(...)` call sites have **not** been updated to pass an instance. One-line addition per call site.

### 6. Trust Infrastructure — ❌ Not started

**Not yet implemented** — despite the existing `go-passport-issuer` having certificate chain validation for eMRTD chips, mdoc trust validation is structurally different:

| Aspect | Existing (MRTD/ICAO 9303) | Required (ISO 18013-5 mdoc) |
|---|---|---|
| Encoding | ASN.1 / CMS SignedData | CBOR / COSE_Sign1 |
| Root CA type | ICAO CSCA | IACA (Issuer Authority CA) |
| DS cert location | Embedded in EF.SOD CMS structure | In `x5chain` header of COSE_Sign1 IssuerAuth |
| Verification call | `gmrtd` SOD.Verify() | COSE_Sign1 verification against IACA cert pool |

**What needs to be built:**

- ❌ CBOR/COSE_Sign1 verifier for IssuerAuth (currently the storage adapter accepts any bytes the caller passes in; this is the biggest production gap)
- ❌ IACA certificate pool loading (configurable paths, analogous to existing CSCA pool in `main.go`)
- 🟡 Document Signer (DS) certificate extraction from COSE `x5chain` header — `mdoc.IssuerAuth.X5Chain()` helper exists; not yet wired into a trust-check path
- ❌ Certificate revocation checking (CRL/OCSP) for DS certificates
- ❌ EU trusted issuer list integration (Commission will publish a list of authorised mDL issuers)

**What can be reused from `go-passport-issuer`:**

- Cert pool loading pattern from `main.go` (`loadDrivingLicenceCertPool`)
- Configurable cert paths per document type
- General passive auth → data integrity check pipeline architecture

### 7. Issuance via OpenID4VCI (mdoc format) — 🟡 CBOR construction done; protocol wiring deferred

- ❌ **`mso_mdoc` credential format** support in the OID4VCI credential request/response (no `credential_configuration_id` for mdoc, no credential-endpoint code path). The wallet side bypasses OID4VCI today: `services.StoreMdocCredential(bytes, deviceKey)` accepts pre-built IssuerSigned CBOR from any source.
- ❌ **Proof of possession** (`jwt` or `cwt` proof type) — not implemented. The device key is generated in the test issuer, not via an OID4VCI proof round-trip.
- ✅ **CBOR credential construction** — `testissuer.BuildAVCredential` produces a full `IssuerSigned` (namespaces + `IssuerAuth` COSE_Sign1 over a tag-24-wrapped MSO) end-to-end. Same code can power a real issuer once the protocol glue is added.
- ✅ **COSE_Sign1 signing** of the MSO using a Document Signer key (ES256, self-signed IACA→DS chain in the test issuer).

---

## Suggested Phasing

### Phase 1 — Remote disclosure (lowest friction, reuses existing OID4VP transport)
1. mdoc credential format (component 1)
2. Trust infrastructure / IACA validation (component 6)
3. Issuance via OID4VCI `mso_mdoc` format (component 7)
4. OID4VP remote flow mdoc additions (component 5)
5. Selective disclosure engine (component 2)

### Phase 2 — Proximity disclosure (new transport surface area)
6. Device authentication & key binding (component 3)
7. ISO 18013-5 proximity transport: QR + NFC engagement, BLE transfer, session encryption (component 4)

The BLE/NFC proximity stack is the largest new surface area and targets the roadside/police check scenario. It is independent of Phase 1 and can be developed in parallel once the credential format is stable.

---

## Remaining Work (punch list)

Ordered roughly by production-readiness impact:

1. **Trust infrastructure (component 6)** — biggest gap for accepting real issuer credentials. Needs an IACA cert pool config, COSE_Sign1 verification of `IssuerAuth` during storage, DS revocation checks.
2. **Secure-element device keys (component 3, device key generation)** — swap the software-only `ecdsa.GenerateKey` + PKCS#8 storage for Android Keystore / iOS Secure Enclave bindings. The existing `HolderBindingKey` table has algorithm metadata that should accommodate this.
3. **OpenID4VCI `mso_mdoc` receipt (component 7)** — wire `services.StoreMdocCredential` into an actual `/credential` endpoint flow with a `cwt` or `jwt` proof of possession over the device key.
4. **MdocDcqlHandler registration** — add the handler to `openid4vp.NewClient(...)` in the mobile app entry points. Single-line change per call site, gated on the apps owning it.
5. **Third-party OID4VP interop testing** — DeviceAuth signature matches our own verifier; exercise against a reference mdoc verifier (e.g. EUDI Reference Wallet, `multipaz-verifier`) and fix any spec-draft-drift.
6. **`ProcessedPayload` column migration** — rename/split `ProcessedSdJwtPayload` in `CredentialBatch` into a format-neutral column so the comment stops apologising for it.
7. **BLE transport driver (component 4)** — GATT service, central/peripheral modes, packetisation. Platform-specific; blocks physical proximity only.
8. **NFC engagement (component 4)** — handover payload + tag read/write. Blocks physical proximity.
9. **DeviceMac variant (component 3)** — needed only if a proximity verifier wants MAC-based DeviceAuth instead of signatures.

---

## Key References

- **ISO/IEC 18013-5:2021** — Data model, proximity transport, device authentication
- **ISO/IEC 18013-7** — Remote mdoc presentation (OID4VP binding)
- **OpenID4VCI** — Issuance protocol (`mso_mdoc` credential format)
- **OpenID4VP** — Remote disclosure protocol
- **ARF Annex 4** — EU reference architecture blueprints for supervised and unsupervised proximity flows
- **Commission Implementing Regulation (EU) 2024/2982** — Protocols and interfaces for EUDI Wallets (references ISO/IEC 18013-5/7)
