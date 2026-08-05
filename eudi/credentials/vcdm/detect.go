package vcdm

// DataModel identifies which credential *data model* a decoded payload uses.
// This is the "cornerstone" dispatch of the VCDM effort: the data model (W3C
// VCDM vs IETF SD-JWT VC) is detected by inspecting the decoded — but
// not-yet-trusted — structure, and is orthogonal to the securing mechanism.
// Dispatch on the structure; trust only after the securing layer has verified
// the proof.
type DataModel int

const (
	// DataModelUnknown means the payload matches neither known data model.
	DataModelUnknown DataModel = iota
	// DataModelVCDM is a W3C Verifiable Credentials Data Model document
	// (`@context`[0] is the base URL and `type` includes VerifiableCredential).
	DataModelVCDM
	// DataModelSdJwtVc is an IETF SD-JWT VC (draft-ietf-oauth-sd-jwt-vc),
	// identified by a `vct` type claim.
	DataModelSdJwtVc
)

func (m DataModel) String() string {
	switch m {
	case DataModelVCDM:
		return "W3C VCDM"
	case DataModelSdJwtVc:
		return "IETF SD-JWT VC"
	default:
		return "unknown"
	}
}

// vctClaimKey is the IETF SD-JWT VC type claim (draft-ietf-oauth-sd-jwt-vc). It
// is spelled as a literal here so this data-model core stays free of any
// dependency on the sdjwtvc policy layer — detection must not couple the data
// model to a securing package.
const vctClaimKey = "vct"

// Detect classifies a decoded payload by data model. VCDM is checked first and
// positively (a well-formed VCDM document never also carries a `vct`); an
// otherwise-unrecognised payload carrying `vct` is treated as an IETF SD-JWT
// VC. This inspects unverified structure — callers must still verify the
// securing proof before trusting the result.
func Detect(payload map[string]any) DataModel {
	if IsVCDM(payload) {
		return DataModelVCDM
	}
	if _, ok := payload[vctClaimKey]; ok {
		return DataModelSdJwtVc
	}
	return DataModelUnknown
}

// IsVCDM reports whether payload looks like a W3C VCDM document: its
// `@context`[0] is the VCDM 2.0 base URL and its `type` includes
// VerifiableCredential. It checks only the two discriminating markers, not full
// structural conformance — use Document.Validate for that, after proof
// verification.
func IsVCDM(payload map[string]any) bool {
	doc := Document(payload)
	ctx, ok := doc.PrimaryContext()
	if !ok || ctx != ContextV2 {
		return false
	}
	return doc.HasType(TypeVerifiableCredential)
}
