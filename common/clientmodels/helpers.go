package clientmodels

import (
	"fmt"
	"strings"
)

// SatisfiesRequestedAttributes checks that `given` contains everything needed to satisfy `requested`.
// Returns ok + list of issues with paths (e.g. "address.street", "roles[2]").
func SatisfiesRequestedAttributes(given, requested []Attribute) (bool, []string) {
	var issues []string
	checkAttributeList(&issues, "", given, requested)
	return len(issues) == 0, issues
}

func checkAttributeList(issues *[]string, path string, given, requested []Attribute) {
	givenByID := make(map[string]Attribute, len(given))
	for _, g := range given {
		givenByID[g.Id] = g
	}

	for _, r := range requested {
		p := joinPath(path, r.Id)

		g, ok := givenByID[r.Id]
		if !ok {
			*issues = append(*issues, fmt.Sprintf("missing attribute: %s", p))
			continue
		}

		if r.RequestedValue == nil {
			continue
		}

		if g.Value == nil {
			*issues = append(*issues, fmt.Sprintf("missing value for attribute: %s", p))
			continue
		}

		checkValueSatisfies(issues, p, *g.Value, *r.RequestedValue)
	}
}

func checkValueSatisfies(issues *[]string, path string, given AttributeValue, req AttributeValue) {
	if req.Type != "" && given.Type != req.Type {
		*issues = append(*issues, fmt.Sprintf("type mismatch at %s: have %q want %q", path, given.Type, req.Type))
		return
	}

	switch req.Type {
	case AttributeType_Object:
		checkAttributeList(issues, path, given.Object, req.Object)

	case AttributeType_Array:
		checkArrayAllOfUnordered(issues, path, given.Array, req.Array)

	case AttributeType_Int:
		if req.Int == nil {
			return
		}
		if given.Int == nil || *given.Int != *req.Int {
			*issues = append(*issues, fmt.Sprintf("int mismatch at %s", path))
		}

	case AttributeType_Bool:
		if req.Bool == nil {
			return
		}
		if given.Bool == nil || *given.Bool != *req.Bool {
			*issues = append(*issues, fmt.Sprintf("bool mismatch at %s", path))
		}

	case AttributeType_TranslatedString:
		if req.TranslatedString == nil {
			return
		}
		if given.TranslatedString == nil {
			*issues = append(*issues, fmt.Sprintf("translated_string missing at %s", path))
			return
		}
		for lang, want := range *req.TranslatedString {
			have, ok := (*given.TranslatedString)[lang]
			if !ok || have != want {
				*issues = append(*issues, fmt.Sprintf("translated_string mismatch at %s.%s", path, lang))
			}
		}

	case AttributeType_Image:
		if req.ImagePath == nil {
			return
		}
		if given.ImagePath == nil || *given.ImagePath != *req.ImagePath {
			*issues = append(*issues, fmt.Sprintf("image mismatch at %s", path))
		}

	case AttributeType_Base64Image:
		if req.Base64Image == nil {
			return
		}
		if given.Base64Image == nil || *given.Base64Image != *req.Base64Image {
			*issues = append(*issues, fmt.Sprintf("base64 image mismatch at %s", path))
		}
	}
}

func checkArrayAllOfUnordered(issues *[]string, path string, given, req []AttributeValue) {
	if len(req) == 0 {
		return
	}
	if len(given) < len(req) {
		*issues = append(*issues, fmt.Sprintf("array too short at %s: have %d want >= %d", path, len(given), len(req)))
		return
	}

	used := make([]bool, len(given))
	var dfs func(i int) bool
	dfs = func(i int) bool {
		if i == len(req) {
			return true
		}
		for j := range given {
			if used[j] {
				continue
			}
			if valueSatisfiesNoReport(given[j], req[i]) {
				used[j] = true
				if dfs(i + 1) {
					return true
				}
				used[j] = false
			}
		}
		return false
	}

	if dfs(0) {
		return
	}
	*issues = append(*issues, fmt.Sprintf("array mismatch at %s: could not satisfy all requested elements (unordered all-of)", path))
}

func valueSatisfiesNoReport(given AttributeValue, req AttributeValue) bool {
	if req.Type != "" && given.Type != req.Type {
		return false
	}
	switch req.Type {
	case AttributeType_Object:
		return attributeListSatisfiesNoReport(given.Object, req.Object)
	case AttributeType_Array:
		return arrayAllOfUnorderedNoReport(given.Array, req.Array)
	case AttributeType_Int:
		if req.Int == nil {
			return true
		}
		return given.Int != nil && *given.Int == *req.Int
	case AttributeType_Bool:
		if req.Bool == nil {
			return true
		}
		return given.Bool != nil && *given.Bool == *req.Bool
	case AttributeType_TranslatedString:
		if req.TranslatedString == nil {
			return true
		}
		if given.TranslatedString == nil {
			return false
		}
		for lang, want := range *req.TranslatedString {
			have, ok := (*given.TranslatedString)[lang]
			if !ok || have != want {
				return false
			}
		}
		return true
	case AttributeType_Image:
		if req.ImagePath == nil {
			return true
		}
		return given.ImagePath != nil && *given.ImagePath == *req.ImagePath
	case AttributeType_Base64Image:
		if req.Base64Image == nil {
			return true
		}
		return given.Base64Image != nil && *given.Base64Image == *req.Base64Image
	default:
		return true
	}
}

func arrayAllOfUnorderedNoReport(given, req []AttributeValue) bool {
	if len(req) == 0 {
		return true
	}
	if len(given) < len(req) {
		return false
	}
	used := make([]bool, len(given))
	var dfs func(i int) bool
	dfs = func(i int) bool {
		if i == len(req) {
			return true
		}
		for j := range given {
			if used[j] {
				continue
			}
			if valueSatisfiesNoReport(given[j], req[i]) {
				used[j] = true
				if dfs(i + 1) {
					return true
				}
				used[j] = false
			}
		}
		return false
	}
	return dfs(0)
}

func attributeListSatisfiesNoReport(given, requested []Attribute) bool {
	givenByID := make(map[string]Attribute, len(given))
	for _, g := range given {
		givenByID[g.Id] = g
	}
	for _, r := range requested {
		g, ok := givenByID[r.Id]
		if !ok {
			return false
		}
		if r.RequestedValue == nil {
			continue
		}
		if g.Value == nil {
			return false
		}
		if !valueSatisfiesNoReport(*g.Value, *r.RequestedValue) {
			return false
		}
	}
	return true
}

func joinPath(prefix, id string) string {
	if prefix == "" {
		return id
	}
	return strings.Join([]string{prefix, id}, ".")
}
