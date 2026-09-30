package mdoc

// Document type and namespace identifiers.
//
// These lived in profile.go, which also carried per-docType issuance and
// disclosure policy for the EUDI Age Verification profile. That policy was
// removed on the grounds that conformance to an attestation profile is the
// issuing party's responsibility rather than the holder's: a wallet cannot fix a
// credential an Attestation Provider minted outside its own profile, and
// refusing one only turns the AP's defect into the user's.
//
// What came back with the identifiers, briefly, was 18013-5 7.2.1's mDL
// carve-out -- that reader authentication may not gate an mDL's mandatory data
// elements. It has since gone too, and for a better reason than the profile
// policy did: 18013-7 Clause 7 lifts that prohibition for the DC API, which is
// the only transport this tree implements. See ReleasableWithoutReaderAuth.
//
// One slice of the profile policy has since been reinstated deliberately, in
// requireAgeVerificationBaseline: an eu.europa.ec.av.1 attestation without
// age_over_18 is refused at issuance. The argument above still holds for
// everything else the removed policy did, and that check is narrower than what
// went -- one element, one docType, issuance only, and presence only. The
// reasoning for the exception is written there rather than here.
const (
	AgeVerificationDocType   = "eu.europa.ec.av.1"
	AgeVerificationNameSpace = "eu.europa.ec.av.1"
)

// AgeOver18Element is the one data element AV Annex A §A.4.2 marks Mandatory in
// issuance: "this attribute is present in all Proof of Age attestations". Every
// other age_over_NN is Optional there.
//
// Note "indicates whether the user is above 18", not "that": the attribute is
// mandatory in an attestation issued to a minor too, carrying false. Presence is
// therefore a statement about conformance only, never about the holder's age.
const AgeOver18Element = "age_over_18"
