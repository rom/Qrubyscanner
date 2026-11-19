// Package ruby contains the heuristics that decide whether a service is backed
// by Ruby, and — in deep mode — fingerprints its version, variant, frameworks,
// gems/app server and correlates known version-based vulnerabilities.
//
// Everything this package does is passive fingerprinting and evidence
// collection: it reads banners, headers, cookies and response bodies and
// reasons about them. It does not attempt to exploit anything.
package ruby

// Verdict is a coarse, human-facing classification derived from Confidence.
type Verdict string

const (
	VerdictConfirmed Verdict = "confirmed"
	VerdictLikely    Verdict = "likely"
	VerdictPossible  Verdict = "possible"
	VerdictNone      Verdict = "none"
)

// Evidence is a single observation that contributed to the verdict.
type Evidence struct {
	// Signal is a stable, machine-friendly identifier, e.g.
	// "header.x-powered-by" or "body.ruby-backtrace".
	Signal string `json:"signal"`
	// Source names where the observation came from (a URL or header name).
	Source string `json:"source"`
	// Detail is a human readable explanation.
	Detail string `json:"detail"`
	// Data is the raw matched snippet (bounded), useful as proof in reports.
	Data string `json:"data,omitempty"`
	// Weight is this signal's contribution to the confidence score.
	Weight int `json:"weight"`
	// Confidence is a human tier (low/medium/high) derived from Weight.
	Confidence string `json:"confidence"`

	// --- Provenance metadata (where / how / what) ---
	// Where names the location of the match, e.g. "response header
	// 'X-Powered-By'", "response body", "cookie", "request URL".
	Where string `json:"where,omitempty"`
	// How names the matching technique, e.g. "header substring match",
	// "regular expression", "cookie-name match", "URL suffix".
	How string `json:"how,omitempty"`
	// Pattern is the literal matcher used (the substring or regex source).
	Pattern string `json:"pattern,omitempty"`
	// Snippet is the matched text with a little surrounding context.
	Snippet string `json:"snippet,omitempty"`
	// Line is the 1-based line number in the response body, when applicable.
	Line int `json:"line,omitempty"`
	// Probe is the request (method + URL) whose response produced the match.
	Probe string `json:"probe,omitempty"`
	// Status is the HTTP response code of the probe that produced the match
	// (0 when the evidence did not come from an HTTP response).
	Status int `json:"status,omitempty"`
}

// confidenceTier maps a signal weight to a low/medium/high label.
func confidenceTier(weight int) string {
	switch {
	case weight >= 60:
		return "high"
	case weight >= 30:
		return "medium"
	default:
		return "low"
	}
}

// Vulnerability is a known issue correlated purely from the detected version.
// It is an informational lead, not a confirmed, exploited finding.
type Vulnerability struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Title            string `json:"title"`
	AffectedVersions string `json:"affected_versions"`
	Description      string `json:"description"`
	Reference        string `json:"reference,omitempty"`
	// MatchBasis explains how the correlation was made.
	MatchBasis string `json:"match_basis"`
	// Prerequisites qualifies the lead by resolving each structured condition
	// (required framework/app server/OS/gem/environment) against what the scan observed.
	Prerequisites []PrereqResult `json:"prerequisites,omitempty"`
	// Applicability summarises the prerequisites: "observed" (conditions hold),
	// "contradicted" (evidence a condition does NOT hold — likely not applicable
	// here), or "" (no structured prerequisites, or all unknown: a plain lead).
	Applicability string `json:"applicability,omitempty"`
}

// PrereqResult is one resolved prerequisite for a vulnerability lead.
type PrereqResult struct {
	Detail string `json:"detail"`
	State  string `json:"state"` // observed | contradicted | unknown
}

// VersionObservation is one version value seen during detection, with where it
// came from. The raw string is kept verbatim (including any distro/backport
// suffix such as "2.7.4p191" or "3.1.2-1ubuntu1").
type VersionObservation struct {
	Version string `json:"version" xml:"version"`
	Source  string `json:"source" xml:"source"`
	Rank    int    `json:"rank,omitempty" xml:"rank,omitempty"`
}

// Detection is the full Ruby assessment of one service.
type Detection struct {
	IsRuby     bool    `json:"is_ruby"`
	Verdict    Verdict `json:"verdict"`
	Confidence int     `json:"confidence"` // 0-100

	Variant       string `json:"variant,omitempty"`        // Ruby (CRuby/MRI), JRuby, TruffleRuby
	Version       string `json:"version,omitempty"`        // best single Ruby version, e.g. 3.3.5
	VersionSource string `json:"version_source,omitempty"` // how the best version was learned
	// Branch is the Ruby release branch (major.minor) when only the branch could
	// be learned (e.g. from a RubyGems ABI directory such as ".../ruby/3.2.0/").
	// It is also filled from Version when that is known.
	Branch    string `json:"branch,omitempty" xml:"branch,omitempty"`
	EndOfLife bool   `json:"end_of_life,omitempty"`
	EOLDetail string `json:"eol_detail,omitempty"`
	// VersionObservations lists every version seen with its source; Version is
	// the highest-ranked of these.
	VersionObservations []VersionObservation `json:"version_observations,omitempty" xml:"version_observations>observation,omitempty"`
	// VersionConflict is set when observations disagree at the major.minor level
	// (which can mean different backend nodes, a cached reply, or two apps).
	VersionConflict bool `json:"version_conflict,omitempty" xml:"version_conflict,omitempty"`

	// Frameworks are web frameworks and applications (Rails, Sinatra, GitLab,
	// Discourse, …). FrameworkVersions holds any versions learned for them and
	// for versioned stack components (Rack, Phusion Passenger, WEBrick, …).
	Frameworks        []string          `json:"frameworks,omitempty"`
	FrameworkVersions map[string]string `json:"framework_versions,omitempty" xml:"-"`
	// Gems are libraries observed from signatures, middleware lists and
	// backtrace paths (the full Gemfile.lock inventory lives in Bundler).
	Gems    []string `json:"gems,omitempty"`
	Modules []string `json:"modules,omitempty"`
	// Addons are Ruby tools, dev aids and dashboards that give the stack away
	// (e.g. Sidekiq Web, Better Errors, Rails Web Console, ActiveAdmin).
	Addons []string `json:"addons,omitempty"`
	// AppServer is a best-effort guess of the Ruby application server (e.g.
	// "Puma", "Phusion Passenger", "WEBrick", "Unicorn", "Thin").
	AppServer string `json:"app_server,omitempty"`
	// RailsEnv is the Rails/Rack environment when it was observed or can be
	// inferred from development-only pages ("development", "production", …).
	RailsEnv string `json:"rails_env,omitempty" xml:"rails_env,omitempty"`

	// FaviconHash is the Shodan-style mmh3 hash of the site favicon, when one
	// was fetched (deep mode). Useful for pivoting/fingerprinting.
	FaviconHash string `json:"favicon_hash,omitempty"`

	RailsInfoExposed bool   `json:"rails_info_exposed,omitempty"`
	RailsInfoURL     string `json:"rails_info_url,omitempty"`
	// RailsInfo holds structured values observed on an exposed
	// /rails/info/properties page (observed, not inferred). Nil when not found.
	RailsInfo *RailsInfoFacts `json:"rails_info,omitempty" xml:"rails_info,omitempty"`

	Evidence        []Evidence      `json:"evidence,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`

	// Bundler is the dependency inventory parsed from exposed or
	// operator-supplied Bundler metadata (Gemfile / Gemfile.lock). Nil when
	// none was found.
	Bundler *BundlerInventory `json:"bundler,omitempty" xml:"bundler,omitempty"`
}

// scoreToVerdict maps a confidence score to a verdict band.
func scoreToVerdict(score int) Verdict {
	switch {
	case score >= 70:
		return VerdictConfirmed
	case score >= 50:
		return VerdictLikely
	case score >= 25:
		return VerdictPossible
	default:
		return VerdictNone
	}
}
