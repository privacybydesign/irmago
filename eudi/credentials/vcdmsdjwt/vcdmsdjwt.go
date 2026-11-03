package vcdmsdjwt

import "github.com/privacybydesign/irmago/eudi/sdjwt"

// MediaTypeVcSdJwt is the JWS `typ` of an SD-JWT-secured VCDM 2.0 credential
// (VC-JOSE-COSE §3.2). `dc+sd-jwt` belongs to IETF SD-JWT VC and is refused.
const MediaTypeVcSdJwt = "vc+sd-jwt"

// SdJwtVcdm is an encoded SD-JWT-secured VCDM credential (issuer-signed JWT and
// optional disclosures, no key binding JWT). It is a defined type over
// sdjwt.SdJwt — not an alias — so the compiler flags any place a raw SD-JWT is
// used where an SD-JWT-secured VCDM credential is expected, mirroring how
// sdjwtvc.SdJwtVc relates to sdjwt.SdJwt.
type SdJwtVcdm sdjwt.SdJwt

// SdJwtVcdmKb is an encoded SD-JWT-secured VCDM credential that may carry a key
// binding JWT (determined during processing). See SdJwtVcdm for why this is a
// defined type rather than an alias.
type SdJwtVcdmKb sdjwt.SdJwtKb
