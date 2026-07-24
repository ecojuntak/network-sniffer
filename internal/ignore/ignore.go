// Package ignore filters service-call edges against a user-supplied ignore
// list, so infrastructure and node-level noise (kubelet health probes, mesh
// sidecars, monitoring agents, external IP peers) stays out of the dependency
// map. Patterns are "<namespace>/<workload>", each segment a glob.
package ignore

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// Matcher tests workloads and edges against a compiled ignore list. The zero
// value ignores nothing; build one with Compile.
type Matcher struct {
	rules []rule
}

// rule is one compiled "<namespace>/<workload>" pattern.
type rule struct {
	ns   *regexp.Regexp
	name *regexp.Regexp
	raw  string
}

// Compile builds a Matcher from ignore patterns. Each pattern is
// "<namespace>/<workload>" where every segment is a glob: "*" matches a whole
// segment (including empty, so it also matches the empty namespace of node and
// external peers), a trailing "*" is a prefix match ("vmagent-*"), and any
// other text is literal. An empty segment ("" — e.g. "/ip-*") matches only the
// empty namespace. "*/*" is rejected as too broad, as is a pattern without a
// "/" separator.
func Compile(patterns []string) (*Matcher, error) {
	m := &Matcher{}
	for _, p := range patterns {
		ns, name, ok := strings.Cut(p, "/")
		if !ok {
			return nil, fmt.Errorf("ignore pattern %q: missing '/' separator", p)
		}
		if ns == "*" && name == "*" {
			return nil, fmt.Errorf("ignore pattern %q: '*/*' matches everything and is rejected", p)
		}
		nsRe, err := globToRegexp(ns)
		if err != nil {
			return nil, fmt.Errorf("ignore pattern %q namespace: %w", p, err)
		}
		nameRe, err := globToRegexp(name)
		if err != nil {
			return nil, fmt.Errorf("ignore pattern %q workload: %w", p, err)
		}
		m.rules = append(m.rules, rule{ns: nsRe, name: nameRe, raw: p})
	}
	return m, nil
}

// ShouldIgnore reports whether a workload (namespace, name) matches any rule.
// Both segments of a rule must match. A nil Matcher ignores nothing.
func (m *Matcher) ShouldIgnore(namespace, name string) bool {
	if m == nil {
		return false
	}
	for _, r := range m.rules {
		if r.ns.MatchString(namespace) && r.name.MatchString(name) {
			return true
		}
	}
	return false
}

// ShouldIgnoreCall reports whether either endpoint of the edge is ignored. An
// edge touching an ignored workload is itself noise, so a match on the source
// or the destination drops the whole edge.
func (m *Matcher) ShouldIgnoreCall(sc model.ServiceCall) bool {
	return m.ShouldIgnore(sc.Source.Namespace, sc.Source.Name) ||
		m.ShouldIgnore(sc.Dest.Namespace, sc.Dest.Name)
}

// globToRegexp turns one glob segment into an anchored regexp. Every character
// is treated literally except "*", which becomes ".*". The result is anchored
// so a segment must match in full (an empty glob yields ^$, matching only the
// empty string).
func globToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
		if r == '*' {
			b.WriteString(".*")
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
