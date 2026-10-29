package eudi_jwt

import "strings"

// TypMatches reports whether a JWS `typ` header value names the media type
// want. RFC 7515 §4.1.9 has a recipient treat a value without a '/' as if
// "application/" were prepended, and compare media types case-insensitively,
// so "vc+sd-jwt", "application/vc+sd-jwt" and "VC+SD-JWT" are one type.
func TypMatches(typ any, want string) bool {
	s, ok := typ.(string)
	return ok && s != "" && strings.EqualFold(fullMediaType(s), fullMediaType(want))
}

func fullMediaType(typ string) string {
	if strings.Contains(typ, "/") {
		return typ
	}
	return "application/" + typ
}
