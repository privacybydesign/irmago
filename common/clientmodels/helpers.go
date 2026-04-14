package clientmodels

import (
	"fmt"
	"strings"
)

// SatisfiesRequestedAttributes checks that `given` contains everything needed to satisfy `requested`.
// Returns ok + list of issues with paths (e.g. "address.street").
func SatisfiesRequestedAttributes(given, requested []Attribute) (bool, []string) {
	var issues []string
	checkAttributeList(&issues, "", given, requested)
	return len(issues) == 0, issues
}

func checkAttributeList(issues *[]string, path string, given, requested []Attribute) {
	givenByPath := make(map[string]Attribute, len(given))
	for _, g := range given {
		givenByPath[ClaimPathKey(g.ClaimPath)] = g
	}

	for _, r := range requested {
		key := ClaimPathKey(r.ClaimPath)
		p := joinPath(path, key)

		g, ok := givenByPath[key]
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

	case AttributeType_String:
		if req.String == nil {
			return
		}
		if given.String == nil {
			*issues = append(*issues, fmt.Sprintf("string missing at %s", path))
			return
		}
		if *given.String != *req.String {
			*issues = append(*issues, fmt.Sprintf("string mismatch at %s", path))
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

func valueSatisfiesNoReport(given AttributeValue, req AttributeValue) bool {
	if req.Type != "" && given.Type != req.Type {
		return false
	}
	switch req.Type {
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
	case AttributeType_String:
		if req.String == nil {
			return true
		}
		return given.String != nil && *given.String == *req.String
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

func attributeListSatisfiesNoReport(given, requested []Attribute) bool {
	givenByPath := make(map[string]Attribute, len(given))
	for _, g := range given {
		givenByPath[ClaimPathKey(g.ClaimPath)] = g
	}
	for _, r := range requested {
		g, ok := givenByPath[ClaimPathKey(r.ClaimPath)]
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

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + strings.TrimPrefix(child, ".")
}
