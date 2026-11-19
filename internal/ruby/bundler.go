package ruby

import (
	"regexp"
	"sort"
	"strings"
)

// maxBundlerGems bounds how many gems the inventory retains, so a huge
// lockfile cannot blow up memory or output.
const maxBundlerGems = 600

// BundlerInventory is the dependency inventory parsed from a project's Bundler
// metadata (a partial SBOM).
type BundlerInventory struct {
	// RubyRequire is the Gemfile `ruby` directive (a requirement that Bundler
	// enforces at boot — exact unless written as a constraint).
	RubyRequire string `json:"ruby_require,omitempty" xml:"ruby_require,omitempty"`
	// RubyLocked is the "RUBY VERSION" section of Gemfile.lock: the interpreter
	// the lockfile was last resolved with.
	RubyLocked string `json:"ruby_locked,omitempty" xml:"ruby_locked,omitempty"`
	// BundledWith is the Bundler version recorded in the lockfile.
	BundledWith string       `json:"bundled_with,omitempty" xml:"bundled_with,omitempty"`
	Platforms   []string     `json:"platforms,omitempty" xml:"platforms>platform,omitempty"`
	Gems        []BundlerGem `json:"gems,omitempty" xml:"gems>gem,omitempty"`
}

// BundlerGem is one dependency and how it was learned.
type BundlerGem struct {
	Name    string `json:"name" xml:"name,attr"`
	Version string `json:"version" xml:"version,attr"`
	// Class is the most authoritative source seen: required (a Gemfile
	// constraint), locked (Gemfile.lock — the concrete resolved version) or
	// observed (a gem directory leaked in a backtrace of the running app).
	Class           string          `json:"class" xml:"class,attr"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
}

var bundlerClassRank = map[string]int{"required": 1, "locked": 2, "observed": 3}

var (
	reLockSpec      = regexp.MustCompile(`^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$`)
	reGemfileGem    = regexp.MustCompile(`(?m)^\s*gem\s*\(?\s*["']([A-Za-z0-9_.-]+)["']\s*(?:,\s*["']([^"']+)["'])?`)
	reGemfileRuby   = regexp.MustCompile(`(?m)^\s*ruby\s*\(?\s*["']([^"']+)["']`)
	reGemfileSource = regexp.MustCompile(`(?m)^\s*source\s*\(?\s*["']https?://`)
	reLockRuby      = regexp.MustCompile(`(?m)^RUBY VERSION\s*\n\s+((?:ruby|jruby|truffleruby) [^\n]+)`)
	reLockBundled   = regexp.MustCompile(`(?m)^BUNDLED WITH\s*\n\s+(\S+)`)
	reExactVersion  = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-.]?p\d+)?$`)
	reRubyVersionFl = regexp.MustCompile(`^(?:ruby-)?(\d+\.\d+\.\d+(?:-?p\d+)?)$`)
	reToolVersions  = regexp.MustCompile(`(?m)^ruby\s+(\d+\.\d+\.\d+(?:-?p\d+)?)\s*$`)
)

// isGemfileLock reports whether a body is a Bundler lockfile.
func isGemfileLock(body string) bool {
	return (strings.Contains(body, "GEM\n") || strings.Contains(body, "GEM\r\n")) &&
		strings.Contains(body, "specs:") &&
		(strings.Contains(body, "DEPENDENCIES") || strings.Contains(body, "BUNDLED WITH") || strings.Contains(body, "PLATFORMS"))
}

// isGemfile reports whether a body is a Gemfile.
func isGemfile(body string) bool {
	if strings.Contains(body, "<html") || strings.Contains(body, "<!DOCTYPE") {
		return false
	}
	return reGemfileGem.MatchString(body) && (reGemfileSource.MatchString(body) || strings.Count(body, "\ngem ") >= 2 || reGemfileRuby.MatchString(body))
}

// classifyBundler sniffs a raw body into "lock", "gemfile" or "". Used for
// operator-supplied files, where there is no URL to go by.
func classifyBundler(body string) string {
	switch {
	case isGemfileLock(body):
		return "lock"
	case isGemfile(body):
		return "gemfile"
	default:
		return ""
	}
}

// lockedRubyVersion normalises a lockfile "ruby 3.1.2p20" / "ruby 3.1.4p0
// (jruby 9.4.5.0)" line into (version, variant).
func lockedRubyVersion(line string) (version, variant string) {
	variant = "Ruby"
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "jruby"):
		variant = "JRuby"
	case strings.Contains(l, "truffleruby"):
		variant = "TruffleRuby"
	}
	return rubyVersionFromDescription(line), variant
}

// buildBundlerInventory merges a Gemfile and Gemfile.lock into one inventory.
// Either body may be empty. It returns nil when nothing was parsed.
func buildBundlerInventory(gemfile, lock string) *BundlerInventory {
	inv := &BundlerInventory{}
	gems := map[string]BundlerGem{}
	put := func(name, version, class string) {
		if name == "" {
			return
		}
		cur, ok := gems[name]
		if ok && bundlerClassRank[cur.Class] > bundlerClassRank[class] {
			return
		}
		if !ok && len(gems) >= maxBundlerGems {
			return
		}
		gems[name] = BundlerGem{Name: name, Version: clampLen(version, 60), Class: class}
	}

	if gemfile != "" && isGemfile(gemfile) {
		if m := reGemfileRuby.FindStringSubmatch(gemfile); m != nil {
			inv.RubyRequire = clampLen(m[1], 40)
		}
		for _, m := range reGemfileGem.FindAllStringSubmatch(gemfile, maxBundlerGems) {
			put(m[1], m[2], "required")
		}
	}
	if lock != "" && isGemfileLock(lock) {
		section := ""
		inSpecs := false
		for _, line := range strings.Split(strings.ReplaceAll(lock, "\r\n", "\n"), "\n") {
			if line != "" && line[0] != ' ' {
				section = strings.TrimSpace(line)
				inSpecs = false
				continue
			}
			trim := strings.TrimSpace(line)
			switch section {
			case "GEM", "GIT", "PATH", "PLUGIN SOURCE":
				if trim == "specs:" {
					inSpecs = true
					continue
				}
				if inSpecs {
					if m := reLockSpec.FindStringSubmatch(line); m != nil {
						put(m[1], m[2], "locked")
					}
				}
			case "PLATFORMS":
				if trim != "" && len(inv.Platforms) < 12 {
					inv.Platforms = append(inv.Platforms, clampLen(trim, 40))
				}
			}
		}
		if m := reLockRuby.FindStringSubmatch(lock); m != nil {
			inv.RubyLocked = clampLen(strings.TrimSpace(m[1]), 60)
		}
		if m := reLockBundled.FindStringSubmatch(lock); m != nil {
			inv.BundledWith = clampLen(m[1], 20)
		}
	}

	if len(gems) == 0 && inv.RubyRequire == "" && inv.RubyLocked == "" {
		return nil
	}
	for _, g := range gems {
		inv.Gems = append(inv.Gems, g)
	}
	sort.Slice(inv.Gems, func(i, j int) bool { return inv.Gems[i].Name < inv.Gems[j].Name })
	return inv
}

// gemVersion returns the concrete version of a gem in the inventory, or "".
// Gemfile constraints ("~> 7.0") are not concrete and are skipped.
func (inv *BundlerInventory) gemVersion(name string) string {
	if inv == nil {
		return ""
	}
	for _, g := range inv.Gems {
		if g.Name == name && g.Class != "required" {
			return g.Version
		}
	}
	return ""
}

// correlateBundler attaches gem-level leads to concrete (locked/observed)
// gems. Gems in `skip` were already correlated at the top level.
func correlateBundler(cat *Catalog, inv *BundlerInventory, facts ObservedFacts, skip map[string]bool) {
	if cat == nil || inv == nil {
		return
	}
	for i := range inv.Gems {
		g := &inv.Gems[i]
		if g.Class == "required" || skip[componentKey(g.Name)] {
			continue
		}
		g.Vulnerabilities = cat.CorrelatePackage(g.Name, g.Version, facts)
		sortVulns(g.Vulnerabilities)
	}
}
