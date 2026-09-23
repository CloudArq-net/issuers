package tenancy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// A rule is one census entry ready to match: its issuer split into host labels
// and path segments, each a literal or a whole <placeholder>. Placeholders
// never share a label or a segment with literal text, which is what lets a
// match say exactly which characters of the issuer a placeholder holds.
type rule struct {
	entry Issuer
	host  []segment
	path  []segment
	// literals counts the characters outside placeholders; of two rules that
	// match one issuer, the one with more is the more specific.
	literals int
	tenant   []segment
}

// segment is a literal, or a placeholder when name is set.
type segment struct {
	literal string
	name    string
}

type matcher struct{ rules []rule }

// compile reads every entry's issuer into a rule, refusing anything that is
// not a well-formed exact issuer or pattern: a malformed pattern read loosely
// would match issuers the census never described.
func compile(entries []Issuer) (*matcher, error) {
	m := &matcher{}
	seen := map[string]string{}
	for _, e := range entries {
		r, key, err := compileRule(e)
		if err != nil {
			return nil, fmt.Errorf("%s (%q): %w", e.Name, e.Issuer, err)
		}
		if other, dup := seen[key]; dup {
			return nil, fmt.Errorf("%s and %s are matched by the same issuer %q", other, e.Name, key)
		}
		seen[key] = e.Name
		m.rules = append(m.rules, r)
	}
	return m, nil
}

func compileRule(e Issuer) (rule, string, error) {
	isPattern := strings.ContainsAny(e.Issuer, "<>")
	if isPattern && !hasHTTPSScheme(e.Issuer) {
		return rule{}, "", errors.New("a pattern must be an https URL")
	}
	host, path, ok := split(e.Issuer)
	if !ok {
		return rule{}, "", errors.New("not an issuer URL")
	}
	var r rule
	names := map[string]bool{}
	// read turns labels or segments into a rule's; fold is what a literal
	// becomes before comparison: lower case in a host, itself in a path.
	read := func(parts []string, fold func(string) string) ([]segment, error) {
		out := make([]segment, len(parts))
		for n, p := range parts {
			switch {
			case isPlaceholder(p):
				if names[p] {
					return nil, fmt.Errorf("the placeholder %s appears twice", p)
				}
				names[p] = true
				out[n] = segment{name: p}
			case strings.ContainsAny(p, "<>"):
				return nil, fmt.Errorf("%q mixes a placeholder with literal text", p)
			default:
				out[n] = segment{literal: fold(p)}
				r.literals += len(p)
			}
		}
		return out, nil
	}
	var err error
	if r.host, err = read(host, lowerASCII); err != nil {
		return rule{}, "", err
	}
	if r.path, err = read(path, func(s string) string { return s }); err != nil {
		return rule{}, "", err
	}
	// The separators are literal characters too: len(host)-1 dots, and a
	// slash before every path segment.
	r.literals += len(host) - 1 + len(path)
	r.entry = e
	key := r.key()
	if !isPattern {
		if e.TenantPlaceholder != "" || e.TenantSyntax != "" {
			return rule{}, "", errors.New("an exact issuer names no tenant")
		}
		return r, key, nil
	}
	if r.tenant, err = template(e.TenantPlaceholder, names); err != nil {
		return rule{}, "", err
	}
	switch e.TenantSyntax {
	case "":
	case "guid":
		if len(r.tenant) != 1 || r.tenant[0].name == "" {
			return rule{}, "", errors.New("a tenant syntax needs a tenant that is one placeholder")
		}
	default:
		return rule{}, "", fmt.Errorf("unknown tenant syntax %q", e.TenantSyntax)
	}
	return r, key, nil
}

// key is the rule's issuer as compile compares them: two entries with one key
// would match the same issuers, and compile refuses them.
func (r rule) key() string {
	join := func(segments []segment, sep string) string {
		parts := make([]string, len(segments))
		for n, s := range segments {
			parts[n] = s.literal + s.name
		}
		return strings.Join(parts, sep)
	}
	if len(r.path) == 0 {
		return join(r.host, ".")
	}
	return join(r.host, ".") + "/" + join(r.path, "/")
}

// template reads a tenant such as "<project>/<location>/<cluster>" into
// literal text and the placeholders it is spelled from, each of which must be
// one of the pattern's.
func template(s string, names map[string]bool) ([]segment, error) {
	var out []segment
	placeholders := 0
	for s != "" {
		open := strings.IndexByte(s, '<')
		if open < 0 {
			out = append(out, segment{literal: s})
			break
		}
		if open > 0 {
			out = append(out, segment{literal: s[:open]})
		}
		end := strings.IndexByte(s[open:], '>')
		if end < 0 {
			return nil, fmt.Errorf("the tenant %q has an unclosed placeholder", s)
		}
		p := s[open : open+end+1]
		if !isPlaceholder(p) || !names[p] {
			return nil, fmt.Errorf("the tenant's %s is not one of the pattern's placeholders", p)
		}
		out = append(out, segment{name: p})
		placeholders++
		s = s[open+end+1:]
	}
	if placeholders == 0 {
		return nil, errors.New("a pattern needs a tenant spelled from its placeholders")
	}
	return out, nil
}

func (m *matcher) match(issuer string) (Issuer, string, bool) {
	host, path, ok := split(issuer)
	if !ok {
		return Issuer{}, "", false
	}
	for n := range host {
		host[n] = lowerASCII(host[n])
	}
	best, tenant := -1, ""
	for n, r := range m.rules {
		values, ok := r.bind(host, path)
		if !ok || best >= 0 && r.literals <= m.rules[best].literals {
			continue
		}
		best, tenant = n, r.spell(values)
	}
	if best < 0 {
		return Issuer{}, "", false
	}
	return m.rules[best].entry.clone(), tenant, true
}

// bind lines an issuer's labels and segments up against the rule's and
// returns what each placeholder holds, or false when any position disagrees.
func (r rule) bind(host, path []string) (map[string]string, bool) {
	if len(host) != len(r.host) || len(path) != len(r.path) {
		return nil, false
	}
	values := map[string]string{}
	for n, s := range r.host {
		if !s.holds(host[n], isLabelByte, values) {
			return nil, false
		}
	}
	for n, s := range r.path {
		if !s.holds(path[n], isSegmentByte, values) {
			return nil, false
		}
	}
	if r.entry.TenantSyntax == "guid" && !isGUID(values[r.tenant[0].name]) {
		return nil, false
	}
	return values, true
}

func (s segment) holds(v string, allowed func(byte) bool, values map[string]string) bool {
	if s.name == "" {
		return v == s.literal
	}
	if v == "" {
		return false
	}
	for n := 0; n < len(v); n++ {
		if !allowed(v[n]) {
			return false
		}
	}
	values[s.name] = v
	return true
}

func (r rule) spell(values map[string]string) string {
	var b strings.Builder
	for _, s := range r.tenant {
		if s.name == "" {
			b.WriteString(s.literal)
		} else {
			b.WriteString(values[s.name])
		}
	}
	return b.String()
}

// split reads an issuer the way the census writes one: https:// or no scheme,
// one trailing slash dropped, and every host label and path segment non-empty.
// It leaves case alone; a caller folds the host by ASCII rules only, so a
// character that lower-cases onto an ASCII letter elsewhere in Unicode cannot
// pass for it.
func split(s string) (host, path []string, ok bool) {
	if n := strings.Index(s, "://"); n >= 0 {
		if !equalFoldASCII(s[:n], "https") {
			return nil, nil, false
		}
		s = s[n+3:]
	}
	s = strings.TrimSuffix(s, "/")
	h, p, hasPath := strings.Cut(s, "/")
	host = strings.Split(h, ".")
	if hasPath {
		path = strings.Split(p, "/")
	}
	if slices.Contains(host, "") || slices.Contains(path, "") {
		return nil, nil, false
	}
	return host, path, true
}

func hasHTTPSScheme(s string) bool {
	return len(s) > len("https://") && equalFoldASCII(s[:len("https://")], "https://")
}

func isPlaceholder(s string) bool {
	if len(s) < 3 || s[0] != '<' || s[len(s)-1] != '>' {
		return false
	}
	for n := 1; n < len(s)-1; n++ {
		if !isSegmentByte(s[n]) {
			return false
		}
	}
	return true
}

func isLabelByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-'
}

func isSegmentByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

func isHexByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// isGUID reports whether s is 8-4-4-4-12 hex digits, the form Microsoft
// documents for a tenant id.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for n := 0; n < len(s); n++ {
		switch n {
		case 8, 13, 18, 23:
			if s[n] != '-' {
				return false
			}
		default:
			if !isHexByte(s[n]) {
				return false
			}
		}
	}
	return true
}

func lowerASCII(s string) string {
	b := []byte(s)
	for n, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[n] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func equalFoldASCII(a, b string) bool {
	return len(a) == len(b) && lowerASCII(a) == lowerASCII(b)
}
