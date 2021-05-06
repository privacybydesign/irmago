package keyshare

import "strings"

func AppendURLPrefix(url, prefix string) string {
	if prefix != "/" && !strings.HasSuffix(url, prefix) {
		// url always ends with / and prefix always starts with /
		url += prefix[1:]
	}
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	url += "irma/"
	return url
}
