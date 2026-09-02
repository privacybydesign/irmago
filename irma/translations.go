package irma

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// This file reports how completely the user-facing text of a configuration is
// translated. Parsing already warns about languages a scheme *declares* in its
// <Languages> element and then fails to provide (see validateTranslations);
// this is the other direction: given a set of languages a scheme is *about to*
// be translated into, list every text that still needs a translation, so that
// adding a language to a scheme is a checklist rather than a hunt through XML.

// TranslationEntry is one translatable field of one scheme object.
type TranslationEntry struct {
	// Object names the owner in the same words parsing warnings use, e.g.
	// "Credential type irma-demo.RU.studentCard".
	Object string
	// Field is the struct field, which is also the XML/JSON tag: "Name",
	// "Description", "IssueURL", ...
	Field string
	// Missing lists the requested languages for which the field has no
	// non-empty text, in the order the languages were requested.
	Missing []string
}

// TranslationReport is the outcome of Configuration.TranslationCoverage.
type TranslationReport struct {
	// Languages the report was computed for.
	Languages []string
	// Entries holds every translatable field found, translated or not, in a
	// deterministic order (schemes, issuers, credential types with their
	// attributes, requestors, wizards; each sorted by identifier).
	Entries []TranslationEntry
}

// Incomplete returns the entries that miss at least one requested language.
func (r TranslationReport) Incomplete() []TranslationEntry {
	var out []TranslationEntry
	for _, e := range r.Entries {
		if len(e.Missing) > 0 {
			out = append(out, e)
		}
	}
	return out
}

// Translated returns how many of the report's entries carry a translation in
// lang, out of the total number of entries.
func (r TranslationReport) Translated(lang string) (translated, total int) {
	total = len(r.Entries)
	for _, e := range r.Entries {
		if !slices.Contains(e.Missing, lang) {
			translated++
		}
	}
	return translated, total
}

// TranslationCoverage walks every user-facing TranslatedString in the
// configuration — scheme managers, issuers, credential types and their
// attributes, requestors and issue wizards — and reports which of the given
// languages each one lacks.
//
// When langs is empty the report covers the union of the languages the parsed
// schemes declare, or clientmodels.SupportedLanguages when none declares any.
// Passing languages explicitly is how a maintainer checks a scheme against a
// language it does not declare yet: `TranslationCoverage([]string{"fr", "de"})`
// on a Dutch/English scheme is the to-do list for adding French and German.
func (conf *Configuration) TranslationCoverage(langs []string) TranslationReport {
	if len(langs) == 0 {
		langs = conf.declaredLanguages()
	}
	report := TranslationReport{Languages: langs}
	add := func(object string, o any) {
		for _, f := range translatedStringFields(o) {
			report.Entries = append(report.Entries, TranslationEntry{
				Object:  object,
				Field:   f.name,
				Missing: f.value.validate(langs),
			})
		}
	}

	for _, id := range sortedIdentifiers(conf.SchemeManagers) {
		add(fmt.Sprintf("Scheme %s", id), conf.SchemeManagers[id])
	}
	for _, id := range sortedIdentifiers(conf.Issuers) {
		add(fmt.Sprintf("Issuer %s", id), conf.Issuers[id])
	}
	for _, id := range sortedIdentifiers(conf.CredentialTypes) {
		cred := conf.CredentialTypes[id]
		add(fmt.Sprintf("Credential type %s", id), cred)
		for _, attr := range cred.AttributeTypes {
			if attr.RevocationAttribute {
				continue // never shown to a user
			}
			add(fmt.Sprintf("Attribute %s of credential type %s", attr.ID, id), attr)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(conf.Requestors)) {
		add(fmt.Sprintf("Requestor %s", id), conf.Requestors[id])
	}
	for _, id := range sortedIdentifiers(conf.IssueWizards) {
		wizard := conf.IssueWizards[id]
		object := fmt.Sprintf("Issue wizard %s", id)
		add(object, wizard)
		for i, qa := range wizard.FAQ {
			add(fmt.Sprintf("%s QA %d", object, i), &qa)
		}
		for i, discon := range wizard.Contents {
			for j, con := range discon {
				for k, item := range con {
					add(fmt.Sprintf("%s item %d.%d.%d", object, i, j, k), &item)
				}
			}
		}
	}
	return report
}

// declaredLanguages is the union of the <Languages> of all parsed schemes, in
// the order of clientmodels.SupportedLanguages first and then alphabetically,
// or SupportedLanguages itself when no scheme declares any language.
func (conf *Configuration) declaredLanguages() []string {
	set := map[string]struct{}{}
	for _, scheme := range conf.SchemeManagers {
		for _, l := range scheme.Languages {
			set[l] = struct{}{}
		}
	}
	for _, scheme := range conf.RequestorSchemes {
		for _, l := range scheme.Languages {
			set[l] = struct{}{}
		}
	}
	if len(set) == 0 {
		return slices.Clone(clientmodels.SupportedLanguages)
	}
	var langs []string
	for _, l := range clientmodels.SupportedLanguages {
		if _, ok := set[l]; ok {
			langs = append(langs, l)
			delete(set, l)
		}
	}
	return append(langs, slices.Sorted(maps.Keys(set))...)
}

// sortedIdentifiers returns the keys of m ordered by their string form, so the
// report is stable across runs and diffable between scheme versions.
func sortedIdentifiers[K interface {
	comparable
	String() string
}, V any](m map[K]V) []K {
	keys := slices.Collect(maps.Keys(m))
	slices.SortFunc(keys, func(a, b K) int { return strings.Compare(a.String(), b.String()) })
	return keys
}

type translatedField struct {
	name  string
	value TranslatedString
}

// translatedStringFields returns the TranslatedString and non-nil
// *TranslatedString fields of the struct o (or the struct it points to), in
// declaration order. Nil pointer fields are optional texts the scheme chose not
// to provide; they are not translations waiting to happen, so they are skipped.
func translatedStringFields(o any) []translatedField {
	v := reflect.ValueOf(o)
	if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	var fields []translatedField
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := v.Type().Field(i).Name
		switch field.Type() {
		case reflect.TypeFor[TranslatedString]():
			fields = append(fields, translatedField{name, field.Interface().(TranslatedString)})
		case reflect.TypeFor[*TranslatedString]():
			if ptr := field.Interface().(*TranslatedString); ptr != nil {
				fields = append(fields, translatedField{name, *ptr})
			}
		}
	}
	return fields
}
