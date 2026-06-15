package httpext

import (
	"fmt"
	"strings"
)

// Challenge is a single parsed challenge from a WWW-Authenticate header (RFC 7235, Section 2.1).
type Challenge struct {
	// Scheme is the authentication scheme name, e.g. "Bearer" or "Basic".
	// RFC 7235 specifies the scheme is case-insensitive; the original casing is preserved here.
	Scheme string
	// Token68 is set for challenges that use the token68 form (e.g. base64 credentials).
	// Mutually exclusive with Params.
	Token68 string
	// Params holds the auth-param key-value pairs with keys lowercased for case-insensitive
	// comparison. Mutually exclusive with Token68.
	Params map[string]string
}

// ParseWWWAuthenticate parses the value of a WWW-Authenticate HTTP response header
// per RFC 7235 (HTTP Authentication) and RFC 7230 (HTTP/1.1 Message Syntax).
// Multiple challenges separated by commas are supported.
func ParseWWWAuthenticate(header string) ([]Challenge, error) {
	p := &wwwAuthParser{s: header}
	return p.parse()
}

type wwwAuthParser struct {
	s   string
	pos int
}

func (p *wwwAuthParser) done() bool { return p.pos >= len(p.s) }

func (p *wwwAuthParser) peek() byte {
	if p.done() {
		return 0
	}
	return p.s[p.pos]
}

// skipOWS skips optional whitespace (SP / HTAB) per RFC 7230, Section 3.2.3.
func (p *wwwAuthParser) skipOWS() {
	for !p.done() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

// isTchar reports whether c is a valid token character (tchar) per RFC 7230, Section 3.2.6.
func isTchar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// isToken68Char reports whether c is a valid non-padding token68 character per RFC 7235, Section 2.1.
// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
func isToken68Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/'
}

// readToken reads one token (1*tchar). Returns ("", false) if no tchar is available.
func (p *wwwAuthParser) readToken() (string, bool) {
	start := p.pos
	for !p.done() && isTchar(p.peek()) {
		p.pos++
	}
	if p.pos == start {
		return "", false
	}
	return p.s[start:p.pos], true
}

// readQuotedString reads a quoted-string and returns its unescaped content
// per RFC 7230, Section 3.2.6.
func (p *wwwAuthParser) readQuotedString() (string, error) {
	if p.peek() != '"' {
		return "", fmt.Errorf("expected '\"' at position %d", p.pos)
	}
	p.pos++
	var sb strings.Builder
	for {
		if p.done() {
			return "", fmt.Errorf("unterminated quoted-string")
		}
		c := p.s[p.pos]
		if c == '"' {
			p.pos++
			return sb.String(), nil
		}
		if c == '\\' {
			p.pos++
			if p.done() {
				return "", fmt.Errorf("truncated quoted-pair in quoted-string")
			}
			next := p.s[p.pos]
			// quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
			if next == '\t' || next == ' ' || (next >= 0x21 && next <= 0x7E) || next >= 0x80 {
				sb.WriteByte(next)
				p.pos++
				continue
			}
			return "", fmt.Errorf("invalid byte 0x%02x in quoted-pair", next)
		}
		// qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
		if c == '\t' || c == ' ' || c == 0x21 ||
			(c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) || c >= 0x80 {
			sb.WriteByte(c)
			p.pos++
			continue
		}
		return "", fmt.Errorf("invalid byte 0x%02x in quoted-string", c)
	}
}

// parse implements: WWW-Authenticate = 1#challenge
func (p *wwwAuthParser) parse() ([]Challenge, error) {
	var challenges []Challenge
	for !p.done() {
		p.skipOWS()
		// RFC 7230 #rule allows leading and consecutive empty list elements (commas).
		for !p.done() && p.peek() == ',' {
			p.pos++
			p.skipOWS()
		}
		if p.done() {
			break
		}
		c, err := p.parseChallenge()
		if err != nil {
			return nil, err
		}
		challenges = append(challenges, c)
	}
	return challenges, nil
}

// parseChallenge implements: challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
func (p *wwwAuthParser) parseChallenge() (Challenge, error) {
	scheme, ok := p.readToken()
	if !ok {
		return Challenge{}, fmt.Errorf("expected auth-scheme at position %d", p.pos)
	}
	c := Challenge{Scheme: scheme}

	if p.done() || p.peek() == ',' {
		return c, nil
	}
	// RFC 7235 requires 1*SP before parameters.
	if p.peek() != ' ' && p.peek() != '\t' {
		return Challenge{}, fmt.Errorf("unexpected character %q after auth-scheme %q at position %d", p.peek(), scheme, p.pos)
	}
	p.skipOWS()
	if p.done() || p.peek() == ',' {
		return c, nil
	}

	// Determine token68 vs auth-params by reading as many token68 chars as possible,
	// then counting trailing '=' padding, and checking what follows.
	t68Start := p.pos
	for !p.done() && isToken68Char(p.peek()) {
		p.pos++
	}
	t68Body := p.s[t68Start:p.pos]

	eqStart := p.pos
	for !p.done() && p.peek() == '=' {
		p.pos++
	}
	eqCount := p.pos - eqStart

	// BWS (optional whitespace) may appear before the '=' of an auth-param, so skip it
	// before deciding whether we have reached the end of the challenge.
	p.skipOWS()

	if len(t68Body) > 0 && (p.done() || p.peek() == ',') {
		// All chars were token68-valid and nothing else remains in this challenge.
		c.Token68 = t68Body + strings.Repeat("=", eqCount)
		return c, nil
	}

	// Not a token68: either the body contained a non-token68 tchar (like '!' or '#'),
	// more content follows the '=' padding (indicating an auth-param value), or whitespace
	// led to additional param content. Backtrack and parse as auth-params.
	p.pos = t68Start
	params, err := p.parseAuthParams()
	if err != nil {
		return Challenge{}, err
	}
	c.Params = params
	return c, nil
}

// isNextAuthParam peeks ahead (from the current position) to determine whether the upcoming
// content looks like an auth-param (token followed by BWS "=") rather than a new challenge
// (token followed by SP, comma, or end of input). The parser position is not modified.
func (p *wwwAuthParser) isNextAuthParam() bool {
	saved := p.pos
	p.skipOWS()
	_, ok := p.readToken()
	if ok {
		p.skipOWS() // BWS before potential '='
		result := !p.done() && p.peek() == '='
		p.pos = saved
		return result
	}
	p.pos = saved
	return false
}

// parseAuthParams implements: #auth-param
// where auth-param = token BWS "=" BWS ( token / quoted-string )
func (p *wwwAuthParser) parseAuthParams() (map[string]string, error) {
	params := make(map[string]string)
	for {
		key, ok := p.readToken()
		if !ok {
			return nil, fmt.Errorf("expected auth-param name at position %d", p.pos)
		}
		p.skipOWS() // BWS before '='
		if p.peek() != '=' {
			return nil, fmt.Errorf("expected '=' after auth-param name %q at position %d", key, p.pos)
		}
		p.pos++     // consume '='
		p.skipOWS() // BWS after '='

		var value string
		var err error
		if p.peek() == '"' {
			value, err = p.readQuotedString()
		} else {
			value, ok = p.readToken()
			if !ok {
				err = fmt.Errorf("expected auth-param value at position %d", p.pos)
			}
		}
		if err != nil {
			return nil, err
		}
		// Auth-param names are case-insensitive per RFC 7235; canonicalize to lowercase.
		params[strings.ToLower(key)] = value

		p.skipOWS()
		if p.done() || p.peek() != ',' {
			break
		}

		// A comma was found: determine whether it continues this challenge's auth-params
		// or starts a new challenge. Consume the comma tentatively.
		p.pos++
		if !p.isNextAuthParam() {
			// Restore the comma; the outer parse() loop will handle the new challenge.
			p.pos--
			break
		}
		p.skipOWS()
	}
	return params, nil
}
