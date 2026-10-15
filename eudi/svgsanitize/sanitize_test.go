package svgsanitize

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func sanitize(t *testing.T, src string) string {
	t.Helper()
	out, err := Sanitize([]byte(src))
	require.NoError(t, err)
	return string(out)
}

func TestSanitizeKeepsCardTemplate(t *testing.T) {
	src := `<?xml version="1.0" encoding="UTF-8"?>
<!-- made by hand -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 340 214" width="340" height="214">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#003366"/><stop offset="1" stop-color="#0066cc"/></linearGradient>
  </defs>
  <rect width="340" height="214" rx="12" fill="url(#bg)"/>
  <text x="20" y="40" fill="#fff" font-size="18">{{given_name}} {{family_name}}</text>
  <image x="250" y="20" width="70" height="90" xlink:href="{{portrait}}"/>
  <use href="#bg"/>
</svg>`
	want := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 340 214" width="340" height="214">&#xA;  <defs>&#xA;    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#003366"></stop><stop offset="1" stop-color="#0066cc"></stop></linearGradient>&#xA;  </defs>&#xA;  <rect width="340" height="214" rx="12" fill="url(#bg)"></rect>&#xA;  <text x="20" y="40" fill="#fff" font-size="18">{{given_name}} {{family_name}}</text>&#xA;  <image x="250" y="20" width="70" height="90" xlink:href="{{portrait}}"></image>&#xA;  <use href="#bg"></use>&#xA;</svg>`
	require.Equal(t, want, sanitize(t, src))
}

func TestSanitizeDropsActiveContent(t *testing.T) {
	src := `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<script>alert(1)</script>
<style>@import url(https://evil.example/x.css); rect{fill:red}</style>
<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">hi<script>alert(2)</script></div></foreignObject>
<a href="https://evil.example"><text>click</text></a>
<rect onclick="alert(3)" class="c" fill="url(https://evil.example/p.svg#x)" stroke="red"/>
<image href="https://tracker.example/pixel.png"/>
<image href="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="/>
<image href="data:image/png;base64,iVBORw0KGgo="/>
<use xlink:href="https://evil.example/sprite.svg#icon" xmlns:xlink="http://www.w3.org/1999/xlink"/>
<g style="background:url(https://evil.example/)"><g style="fill:blue"/></g>
<animate attributeName="href" to="javascript:alert(1)"/>
<set attributeName="onmouseover" to="alert(1)"/>
<sodipodi:namedview xmlns:sodipodi="x"/>
<text>{{name}} &amp; &lt;script&gt;</text>
</svg>`
	out := sanitize(t, src)
	lower := strings.ToLower(out)
	for _, banned := range []string{"<script", "alert", "onload", "onclick", "<style", "@import", "foreignobject",
		"evil.example", "tracker.example", "class=", "<a", "<animate", "<set", "namedview", "svg+xml"} {
		require.NotContains(t, lower, banned)
	}
	require.Contains(t, out, `<rect stroke="red"></rect>`)
	require.Contains(t, out, `<image href="data:image/png;base64,iVBORw0KGgo="></image>`)
	require.Contains(t, out, `<g><g style="fill:blue"></g></g>`)
	require.Contains(t, out, `<text>{{name}} &amp; &lt;script&gt;</text>`)
}

func TestSanitizeRejects(t *testing.T) {
	for name, src := range map[string]string{
		"html root":           `<html><svg/></html>`,
		"empty":               ``,
		"text only":           `hello`,
		"malformed":           `<svg><g></svg>`,
		"unclosed":            `<svg><g>`,
		"two roots":           `<svg></svg><svg></svg>`,
		"prefixed other":      `<x:svg xmlns:x="urn:x"></x:svg>`,
		"external dtd entity": `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Sanitize([]byte(src))
			require.Error(t, err)
		})
	}
}

func TestSanitizeTooDeep(t *testing.T) {
	src := "<svg>" + strings.Repeat("<g>", maxDepth) + strings.Repeat("</g>", maxDepth) + "</svg>"
	_, err := Sanitize([]byte(src))
	require.Error(t, err)
}

func TestSanitizeIsIdempotent(t *testing.T) {
	src := `<svg viewBox="0 0 1 1"><text x="1">a
b &amp; "c"</text><rect style="fill:#fff" xml:space="preserve"/></svg>`
	once := sanitize(t, src)
	require.Equal(t, once, sanitize(t, once))
}

// eventAttr matches an on* attribute inside a tag (attribute names are
// always preceded by a space in the serialised output).
var eventAttr = regexp.MustCompile(`<[^>]*\son[a-z]+="`)

func FuzzSanitize(f *testing.F) {
	f.Add([]byte(`<svg><rect fill="url(#a)"/><text>{{x}}</text></svg>`))
	f.Add([]byte(`<svg onload="x"><script>x</script><image href="data:image/png;base64,AA=="/></svg>`))
	f.Add([]byte(`<svg:svg xmlns:svg="http://www.w3.org/2000/svg"><svg:g style="a:url( 'x' )"/></svg:svg>`))
	f.Fuzz(func(t *testing.T, src []byte) {
		out, err := Sanitize(src)
		if err != nil {
			return
		}
		again, err := Sanitize(out)
		if err != nil {
			t.Fatalf("sanitised output does not sanitise again: %v\n%s", err, out)
		}
		if string(again) != string(out) {
			t.Fatalf("not idempotent:\n%s\n%s", out, again)
		}
		lower := strings.ToLower(string(out))
		for _, banned := range []string{"<script", "<style", "<foreignobject"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("output contains %q: %s", banned, out)
			}
		}
		if eventAttr.MatchString(lower) {
			t.Fatalf("output contains an event handler attribute: %s", out)
		}
		// No attribute value may reference anything outside the document.
		if strings.Contains(lower, "http:") || strings.Contains(lower, "https:") {
			// Allowed only inside text nodes and the namespace declarations.
			stripped := strings.ReplaceAll(lower, `xmlns="http://www.w3.org/2000/svg"`, "")
			stripped = strings.ReplaceAll(stripped, `xmlns:xlink="http://www.w3.org/1999/xlink"`, "")
			for _, attr := range []string{`href="http`, `href="https`, `url(http`, `url('http`, `url("http`, `url(&#34;http`, `url(&#39;http`} {
				if strings.Contains(stripped, attr) {
					t.Fatalf("output references external resource: %s", out)
				}
			}
		}
	})
}
