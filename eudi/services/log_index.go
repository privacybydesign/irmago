package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// logIndexVersion is the version of indexEntry. Bump it whenever indexEntry
// changes what it derives; the next query then re-derives every entry.
//
//   - 1: the derived columns and attribute rows.
//   - 2: attribute rows gained their pattern key.
const logIndexVersion = 2

// logIndexBatch is how many entries the index pass handles per transaction.
const logIndexBatch = 200

// indexEntry fills the derived columns of an entry from what it stores: the
// sortable time, the party key, the search text, credential roles and
// positions, and the attribute rows.
func indexEntry(e *models.EudiLogEntry) {
	ns := e.CreatedAt.UnixNano()
	if e.CreatedAtNs != nil {
		ns = *e.CreatedAtNs
	}
	e.CreatedAtNs = &ns

	partyKey := ""
	if e.Type != string(clientmodels.LogType_CredentialRemoval) {
		partyKey = e.RequestorId
	}
	e.PartyKey = &partyKey

	var text []string
	text = append(text, e.RequestorId)
	text = append(text, storedTexts(e.RequestorName)...)
	if e.SignedMessage != nil {
		text = append(text, *e.SignedMessage)
	}

	for i := range e.Credentials {
		c := &e.Credentials[i]
		role := string(roleOf(e.Type, c))
		c.Role = &role
		if c.Position == nil {
			position := i
			c.Position = &position
		}

		text = append(text, c.CredentialId)
		text = append(text, storedTexts(c.Name)...)
		text = append(text, storedTexts(c.IssuerName)...)

		var attrs []struct {
			ClaimPath   []any                        `json:"claim_path"`
			DisplayName json.RawMessage              `json:"display_name"`
			Value       *clientmodels.AttributeValue `json:"value"`
		}
		_ = json.Unmarshal(c.Attributes, &attrs)
		c.AttributeRows = make([]models.EudiLogAttribute, 0, len(attrs))
		for _, a := range attrs {
			c.AttributeRows = append(c.AttributeRows, db.NewAttributeRow(e.ID, c.ID, clientmodels.ClaimPathKey(a.ClaimPath), clientmodels.ClaimPatternKey(a.ClaimPath)))
			text = append(text, storedTexts(a.DisplayName)...)
			text = append(text, attributeValueText(a.Value))
		}
	}

	searchText := normaliseForSearch(strings.Join(text, " "))
	e.SearchText = &searchText
	version := logIndexVersion
	e.IndexVersion = &version
}

// storedTexts is every text in a stored text field: the string, or each
// translation of a map.
func storedTexts(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var ts map[string]string
	if err := json.Unmarshal(raw, &ts); err == nil {
		result := make([]string, 0, len(ts))
		for _, t := range ts {
			result = append(result, t)
		}
		return result
	}
	return nil
}

// attributeValueText is the searchable text of a value. Images are left out.
func attributeValueText(v *clientmodels.AttributeValue) string {
	switch {
	case v == nil:
		return ""
	case v.String != nil:
		return *v.String
	case v.Int != nil:
		return fmt.Sprint(*v.Int)
	}
	return ""
}

// normaliseForSearch lowercases s, strips hyphens and removes accents, so
// "Café-Noir" and "cafenoir" match. It folds what the app's own search
// normalisation does, and more: any combining mark, not only Latin-1.
func normaliseForSearch(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, "-", ""))
	folded, _, err := transform.String(transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC), s)
	if err != nil {
		return strings.Join(strings.Fields(s), " ")
	}
	return strings.Join(strings.Fields(folded), " ")
}

// searchTokens splits a search query into the normalised words it is made of.
func searchTokens(query string) []string {
	return strings.Fields(normaliseForSearch(query))
}

func (s *eudiLogService) IndexLogs() error {
	for {
		entries, err := s.store.NeedingIndex(logIndexVersion, logIndexBatch)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}
		for _, e := range entries {
			indexEntry(e)
		}
		if err := s.store.SaveIndex(entries); err != nil {
			return err
		}
	}
}
