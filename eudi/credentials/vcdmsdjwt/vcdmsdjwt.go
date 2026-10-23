package vcdmsdjwt

import "github.com/privacybydesign/irmago/eudi/sdjwt"

// SD-JWT media types (JWS `typ` header) under which an SD-JWT-secured VCDM 2.0
// credential can arrive. `vc+sd-jwt` always denotes SD-JWT-secured VCDM;
// `dc+sd-jwt` is shared with the IETF SD-JWT VC layer and is content-dispatched
// on the decoded payload (see package doc and vcdm.Detect).
const (
	MediaTypeVcSdJwt = "vc+sd-jwt"
	MediaTypeDcSdJwt = "dc+sd-jwt"
)

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
