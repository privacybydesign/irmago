// Package svgsanitize reduces an untrusted SVG document (an issuer's SD-JWT VC
// card template) to a small, static subset of SVG the wallet can render
// without risk: shapes, text, gradients, clipping and embedded bitmap images.
//
// It works on an allowlist. Elements outside it are dropped together with
// their whole subtree (so <script>, <style>, <foreignObject>, <a>, <iframe>,
// <animate>, <filter>, editor metadata and the like never reach the output),
// attributes outside it are dropped (so every on* event handler, class, and
// namespaced editor attribute is gone), and the attributes that are kept are
// checked for references that could leave the document: an href may only
// point at a "#fragment", an embedded data:image/(png|jpeg|gif|webp) URI, or be
// a bare "{{svg_id}}" placeholder the app fills; a url(...) reference may only
// point at a "#fragment". Comments, processing instructions and DOCTYPEs are
// dropped. Text content — including the {{svg_id}} placeholders — is kept.
//
// The output is re-serialised from scratch, so it is always well-formed XML
// with a single <svg> root in the SVG namespace, and sanitising the output a
// second time returns it unchanged.
package svgsanitize

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	svgNamespace   = "http://www.w3.org/2000/svg"
	xlinkNamespace = "http://www.w3.org/1999/xlink"

	// maxDepth bounds element nesting, so a pathological document cannot
	// blow up the renderer the app hands the output to.
	maxDepth = 128
)

var allowedElements = setOf(
	"svg", "g", "defs", "symbol", "use",
	"path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
	"text", "tspan", "textPath",
	"linearGradient", "radialGradient", "stop",
	"clipPath", "mask", "pattern", "image",
	"title", "desc",
)

var allowedAttributes = setOf(
	"id", "version", "viewBox", "preserveAspectRatio", "width", "height",
	"x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "fx", "fy", "fr",
	"d", "points", "pathLength", "transform",
	"fill", "fill-opacity", "fill-rule",
	"stroke", "stroke-width", "stroke-opacity", "stroke-linecap", "stroke-linejoin",
	"stroke-dasharray", "stroke-dashoffset", "stroke-miterlimit",
	"opacity", "color", "display", "visibility", "overflow",
	"clip-path", "clip-rule", "mask",
	"font-family", "font-size", "font-weight", "font-style", "font-variant", "font-stretch",
	"text-anchor", "dominant-baseline", "alignment-baseline", "baseline-shift",
	"letter-spacing", "word-spacing", "text-decoration", "writing-mode", "direction",
	"dx", "dy", "rotate", "textLength", "lengthAdjust", "startOffset", "method", "spacing", "side",
	"offset", "stop-color", "stop-opacity",
	"gradientUnits", "gradientTransform", "spreadMethod",
	"patternUnits", "patternContentUnits", "patternTransform",
	"clipPathUnits", "maskUnits", "maskContentUnits",
	"refX", "refY",
	"vector-effect", "paint-order", "shape-rendering", "text-rendering", "image-rendering",
	"href", "style",
)

func setOf(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, i := range items {
		m[i] = struct{}{}
	}
	return m
}

var (
	fragmentRef    = regexp.MustCompile(`^#[A-Za-z_][\w.\-:]*$`)
	placeholderRef = regexp.MustCompile(`^\{\{\s*[A-Za-z_][\w.\-]*\s*\}\}$`)
	dataImageRef   = regexp.MustCompile(`^data:image/(png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/=\s]+$`)
	urlFunction    = regexp.MustCompile(`(?i)url\s*\(`)
	urlFragment    = regexp.MustCompile(`(?i)url\s*\(\s*['"]?#[A-Za-z_][\w.\-:]*['"]?\s*\)`)
)

// ErrNotSvg is returned when the document's root element is not <svg>.
var ErrNotSvg = errors.New("svgsanitize: root element is not <svg>")

// Sanitize parses src as XML and returns the sanitised SVG. It fails when src
// is not well-formed XML, when its root element is not <svg>, or when it nests
// deeper than the supported depth.
func Sanitize(src []byte) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(src))
	dec.Strict = true
	dec.Entity = xml.HTMLEntity

	var out bytes.Buffer
	// stack holds the open element names as they appear in the input (with
	// prefix), so end tags can be matched; RawToken does not check that.
	var stack []xml.Name
	// skipDepth > 0 while inside a dropped subtree.
	skipDepth := 0
	rootSeen, rootClosed := false, false

	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("svgsanitize: %w", err)
		}
		if rootClosed {
			// Anything after the root (trailing comments, whitespace) is ignored;
			// a second element is malformed XML.
			if _, ok := tok.(xml.StartElement); ok {
				return nil, errors.New("svgsanitize: content after root element")
			}
			continue
		}

		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name)
			if len(stack) > maxDepth {
				return nil, fmt.Errorf("svgsanitize: nesting deeper than %d", maxDepth)
			}
			if !rootSeen {
				rootSeen = true
				if !isSvgName(t.Name) || t.Name.Local != "svg" {
					return nil, ErrNotSvg
				}
				out.WriteString(`<svg xmlns="` + svgNamespace + `" xmlns:xlink="` + xlinkNamespace + `"`)
				writeAttrs(&out, t.Attr)
				out.WriteString(">")
				continue
			}
			if skipDepth > 0 {
				skipDepth++
				continue
			}
			if !isSvgName(t.Name) {
				skipDepth = 1
				continue
			}
			if _, ok := allowedElements[t.Name.Local]; !ok {
				skipDepth = 1
				continue
			}
			out.WriteString("<" + t.Name.Local)
			writeAttrs(&out, t.Attr)
			out.WriteString(">")

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != t.Name {
				return nil, fmt.Errorf("svgsanitize: unexpected end element </%s>", qualified(t.Name))
			}
			stack = stack[:len(stack)-1]
			if skipDepth > 0 {
				skipDepth--
				continue
			}
			out.WriteString("</" + t.Name.Local + ">")
			if len(stack) == 0 {
				rootClosed = true
			}

		case xml.CharData:
			if skipDepth > 0 || len(stack) == 0 {
				continue
			}
			if err := xml.EscapeText(&out, t); err != nil {
				return nil, err
			}

		default:
			// xml.Comment, xml.ProcInst, xml.Directive: dropped.
		}
	}

	if !rootSeen {
		return nil, ErrNotSvg
	}
	if !rootClosed {
		return nil, errors.New("svgsanitize: unexpected end of document")
	}
	return out.Bytes(), nil
}

// isSvgName reports whether an element name is in the SVG namespace as far as
// a raw (unresolved) token can tell: unprefixed, or with the conventional
// "svg" prefix.
func isSvgName(n xml.Name) bool {
	return n.Space == "" || n.Space == "svg"
}

func qualified(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

func writeAttrs(out *bytes.Buffer, attrs []xml.Attr) {
	seen := map[string]struct{}{}
	for _, a := range attrs {
		name, value, ok := sanitizeAttr(a)
		if !ok {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out.WriteString(" " + name + `="`)
		_ = xml.EscapeText(out, []byte(value))
		out.WriteString(`"`)
	}
}

// sanitizeAttr returns the output name and value of an attribute, or false
// when it must be dropped.
func sanitizeAttr(a xml.Attr) (string, string, bool) {
	var name string
	switch {
	case a.Name.Space == "" || a.Name.Space == "svg":
		name = a.Name.Local
	case a.Name.Space == "xlink" && a.Name.Local == "href":
		name = "xlink:href"
	case a.Name.Space == "xml" && a.Name.Local == "space":
		if a.Value != "preserve" && a.Value != "default" {
			return "", "", false
		}
		return "xml:space", a.Value, true
	default:
		return "", "", false
	}
	if name != "xlink:href" {
		if _, ok := allowedAttributes[name]; !ok {
			return "", "", false
		}
	}
	value := a.Value

	switch name {
	case "href", "xlink:href":
		v := strings.TrimSpace(value)
		if fragmentRef.MatchString(v) || placeholderRef.MatchString(v) || dataImageRef.MatchString(v) {
			return name, v, true
		}
		return "", "", false
	case "style":
		if !safeStyle(value) {
			return "", "", false
		}
	}
	if !safeURLRefs(value) {
		return "", "", false
	}
	return name, value, true
}

// safeURLRefs reports whether every url(...) in v references a fragment.
func safeURLRefs(v string) bool {
	return len(urlFunction.FindAllStringIndex(v, -1)) == len(urlFragment.FindAllStringIndex(v, -1))
}

// safeStyle rejects inline styles that could load anything or that use CSS
// escapes or comments to hide what they do from the checks above.
func safeStyle(v string) bool {
	lower := strings.ToLower(v)
	for _, banned := range []string{"@import", "expression", "\\", "/*", "<", "javascript:", "behavior", "-moz-binding"} {
		if strings.Contains(lower, banned) {
			return false
		}
	}
	return true
}
