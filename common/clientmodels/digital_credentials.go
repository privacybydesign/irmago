package clientmodels

// DigitalCredentialsRegistryEntry is one credential a website can ask the
// wallet for through the W3C Digital Credentials API, as the app registers it
// with the platform. The platform only routes a request to the wallet when the
// request matches a registered entry, and shows the entry in its credential
// picker.
//
// The entry is platform neutral. What a platform can register differs: the
// Android Credential Manager takes dc+sd-jwt and mso_mdoc entries, iOS only
// mso_mdoc. The app registers the formats its platform knows and leaves the
// rest out.
//
// An entry never carries a claim value. The platform stores what is registered
// outside the wallet, and matching a request needs only the type and the claim
// names.
type DigitalCredentialsRegistryEntry struct {
	// Id tells the entries of one registry apart and is stable for as long as
	// the entry describes the same credential type in the same format.
	Id string `json:"id"`

	// Format is the credential format a request has to ask for.
	Format CredentialFormat `json:"format"`

	// Type is what a request names the credential by: the vct of a dc+sd-jwt,
	// the docType of an mso_mdoc.
	//
	// For a vc+sd-jwt it is the type identity the wallet files the credential
	// under, which tells the entries apart but is not what a request matches
	// on: DCQL type_values name the expanded types. No platform registry takes
	// this format yet; one that does needs the expanded types added here.
	Type string `json:"type"`

	// Name and IssuerName are resolved to the current locale. IssuerName is
	// empty when the issuer is not known by a name.
	Name       string `json:"name"`
	IssuerName string `json:"issuer_name"`

	// The logo of the credential type, if it has one: LogoPath when it is a
	// plain file on disk, Logo when the wallet only has it in its own
	// (encrypted) storage. At most one of the two is set.
	LogoPath *string `json:"logo_path,omitempty"`
	Logo     *Image  `json:"logo,omitempty"`

	// Claims are the claims a request can ask for. Never empty.
	Claims []DigitalCredentialsRegistryClaim `json:"claims"`
}

// DigitalCredentialsRegistryClaim is a claim of a registered credential.
type DigitalCredentialsRegistryClaim struct {
	// Path is the claim path a request names the claim by. For an mso_mdoc it
	// is always the namespace followed by the element identifier. It holds
	// object keys only: the elements of an array are registered as the array.
	Path []string `json:"path"`

	// Name is the claim's display name in the current locale, or the last
	// element of Path when it has none.
	Name string `json:"name"`
}
