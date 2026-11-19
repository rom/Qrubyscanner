package ruby

import (
	"regexp"
	"strconv"
	"strings"
)

// Ruby-ecosystem versions routinely carry a fourth component: Rails and Rack
// security releases ("7.0.8.1", "2.2.6.4") and classic Ruby patch levels
// ("2.0.0p594", "1.9.3-p551"). parseVersion4 keeps all four so ranges can be
// expressed precisely.

var rePatchLevel = regexp.MustCompile(`^(\d+)[-.]?p(\d+)`)

// parseVersion4 extracts up to four numeric components. A Ruby patch level
// ("p594") becomes the fourth component; a pre-release tag in the fourth
// position ("7.1.0.rc1", "3.4.0.preview2") yields -1 so that it sorts before
// the final release. Missing components default to 0.
func parseVersion4(v string) (n [4]int, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "ruby-"), "ruby ")
	v = strings.TrimLeft(v, "vV")
	if v == "" {
		return n, false
	}
	fields := strings.SplitN(v, ".", 5)
	if _, err := strconv.Atoi(trimToDigits(fields[0])); err != nil {
		return n, false
	}
	for i := 0; i < 4 && i < len(fields); i++ {
		f := fields[i]
		if i == 2 {
			if m := rePatchLevel.FindStringSubmatch(f); m != nil {
				n[2], _ = strconv.Atoi(m[1])
				n[3], _ = strconv.Atoi(m[2])
				return n, true
			}
			if isPreRelease(f) {
				n[2] = leadingInt(f)
				n[3] = -1
				return n, true
			}
		}
		if i == 3 {
			switch {
			case len(f) > 1 && f[0] == 'p' && f[1] >= '0' && f[1] <= '9':
				n[3] = leadingInt(f)
			case f != "" && (f[0] < '0' || f[0] > '9'):
				n[3] = -1 // rc1 / beta2 / preview1 / pre
			default:
				n[3] = leadingInt(f)
			}
			continue
		}
		n[i] = leadingInt(f)
	}
	return n, true
}

// isPreRelease reports a third component such as "0-preview1" or "0rc1".
func isPreRelease(f string) bool {
	l := strings.ToLower(f)
	for _, tag := range []string{"preview", "rc", "beta", "alpha", "dev", "pre"} {
		if strings.Contains(l, tag) {
			return true
		}
	}
	return false
}

// parseVersion extracts major.minor.patch from a version string, tolerating
// suffixes such as "-dev", "rc1" or "p594". Missing components default to 0.
func parseVersion(v string) (maj, min, pat int, ok bool) {
	n, ok := parseVersion4(v)
	return n[0], n[1], n[2], ok
}

func leadingInt(s string) int {
	n := 0
	started := false
	for _, r := range s {
		if r < '0' || r > '9' {
			if started {
				break
			}
			continue
		}
		started = true
		n = n*10 + int(r-'0')
	}
	return n
}

func trimToDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			break
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// compareVersion returns -1, 0 or 1 comparing a and b component-wise over up
// to four components.
func compareVersion(a, b string) int {
	an, _ := parseVersion4(a)
	bn, _ := parseVersion4(b)
	for i := 0; i < 4; i++ {
		if an[i] != bn[i] {
			return sign(an[i] - bn[i])
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// branchOf returns "major.minor" for a parseable version, or "".
func branchOf(v string) string {
	maj, min, _, ok := parseVersion(v)
	if !ok {
		return ""
	}
	return strconv.Itoa(maj) + "." + strconv.Itoa(min)
}

// CorrelateVulns correlates Ruby-core leads against the built-in catalogue.
// It is a convenience wrapper over DefaultCatalog().CorrelateRuby.
func CorrelateVulns(variant, version string) []Vulnerability {
	return DefaultCatalog().CorrelateRuby(variant, version)
}

// evaluateEOL reports branch end-of-life using the built-in catalogue.
func evaluateEOL(variant, version string) (bool, string) {
	return DefaultCatalog().EOL(variant, version)
}
