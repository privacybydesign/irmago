package services

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// LogicalCredentialID computes the data-model-agnostic logical identity used to
// group the same credential held in multiple formats under one CredentialBatch
// (map ticket #686). It is a SHA-256 over the issuer and the credential's
// normalized *content* claims — deliberately NOT its `type`/`vct` — so an
// SD-JWT-secured VCDM credential (`vc+sd-jwt`), its Data-Integrity form
// (`ldp_vc`), and an IETF SD-JWT VC (`dc+sd-jwt`) that carry the same data from
// the same issuer all yield the same id and group together.
//
// Content is normalized per data model (see VcdmContentClaims /
// SdJwtVcContentClaims) so a nested VCDM `credentialSubject` and a flat SD-JWT
// VC claim set of the same data reduce to the same map. The issuer salt keeps
// identical content from different issuers from colliding into one logical
// credential.
//
// The encoding is canonical: json.Marshal sorts object keys at every level, and
// the fixed struct wrapper disambiguates the issuer from the content (so issuer
// "ab"+content and issuer "a"+content can't hash alike). Array element order is
// preserved and therefore significant, matching the per-format hashes.
//
// Caveat (accepted in #686): grouping across data models only works when the
// issuer emits the same claim keys, shapes and values in each format; a differing
// claim set or shape yields a different id and so a separate batch.
func LogicalCredentialID(issuer string, content map[string]any) (string, error) {
	keyed := struct {
		Issuer  string         `json:"issuer"`
		Content map[string]any `json:"content"`
	}{Issuer: issuer, Content: content}

	encoded, err := json.Marshal(keyed)
	if err != nil {
		return "", fmt.Errorf("LogicalCredentialID: failed to marshal: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum), nil
}

// VcdmContentClaims extracts the normalized content claims from a VCDM document:
// the members of its single `credentialSubject`, with the subject identifier
// `id` removed. The subject id is dropped because its representation differs
// across data models (VCDM `credentialSubject.id` vs the SD-JWT VC `sub`), while
// the content claims themselves (e.g. a scoped unique id) already distinguish
// subjects. A multi-subject `credentialSubject` (array) has no flat SD-JWT VC
// counterpart to group with, so it is returned wrapped unchanged.
func VcdmContentClaims(doc vcdm.Document) map[string]any {
	subjects, err := doc.CredentialSubjects()
	if err != nil || len(subjects) != 1 {
		return map[string]any{vcdm.CredentialSubjectKey: doc[vcdm.CredentialSubjectKey]}
	}
	content := make(map[string]any, len(subjects[0]))
	for key, value := range subjects[0] {
		if key == vcdm.IDKey {
			continue
		}
		content[key] = value
	}
	return content
}

// SdJwtVcContentClaims extracts the normalized content claims from an IETF
// SD-JWT VC processed payload: every claim except the SD-JWT / JWT standard and
// registered claims (sdjwtvc.StandardClaims — which includes `sub`, `iss`,
// `vct`, `_sd`, `status`, …). The result is the flat user-data claim set, the
// counterpart of a VCDM credential's unwrapped credentialSubject.
func SdJwtVcContentClaims(payload map[string]any) map[string]any {
	content := make(map[string]any, len(payload))
	for key, value := range payload {
		if _, isStandard := sdjwtvc.StandardClaims[key]; isStandard {
			continue
		}
		content[key] = value
	}
	return content
}

// LogicalIdentityFromProcessedPayload computes the #686 logical identity from a
// stored processed payload — the JSON persisted as
// CredentialBatch.ProcessedSdJwtPayload / FormatBinding.ProcessedPayload. It
// dispatches content normalization by data model so the id is identical whether
// computed at store time from a freshly verified credential or during migration
// of an already-stored one: VCDM formats normalize via VcdmContentClaims (the
// credentialSubject), all other (IETF SD-JWT VC) formats via SdJwtVcContentClaims.
//
// The VCDM branch also accepts a full SD-JWT processed payload (envelope + SD-JWT
// claims around the credentialSubject): VcdmContentClaims reads only
// credentialSubject, so the envelope and securing claims are ignored either way.
// Future VCDM securing formats (ldp_vc, vc+jwt) join the VCDM branch here.
func LogicalIdentityFromProcessedPayload(format models.CredentialFormat, issuerURL string, processedPayload []byte) (string, error) {
	var payload map[string]any
	if err := json.Unmarshal(processedPayload, &payload); err != nil {
		return "", fmt.Errorf("LogicalIdentityFromProcessedPayload: failed to unmarshal payload: %w", err)
	}

	var content map[string]any
	if format == models.CredentialFormatSdJwtVcdm {
		content = VcdmContentClaims(vcdm.Document(payload))
	} else {
		content = SdJwtVcContentClaims(payload)
	}
	return LogicalCredentialID(issuerURL, content)
}
