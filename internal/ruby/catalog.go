package ruby

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// FeedSchema is the schema identifier external feeds should declare.
const FeedSchema = "qrubyscanner-vuln-feed/1"

// RangeSpec describes an affected version range. A version matches when every
// populated bound is satisfied:
//
//	Branch      restricts to a single major.minor (e.g. "3.3")
//	Introduced  version >= Introduced
//	Fixed       version <  Fixed
//	LessThan    version <  LessThan  (alias for an open-ended upper bound)
//
// At least one bound must be set for the range to match anything.
type RangeSpec struct {
	Branch     string `json:"branch,omitempty"`
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LessThan   string `json:"lt,omitempty"`
	// Equals matches a single exact version (used by discrete CSAF products).
	Equals string `json:"eq,omitempty"`
}

func (r RangeSpec) empty() bool {
	return r.Branch == "" && r.Introduced == "" && r.Fixed == "" && r.LessThan == "" && r.Equals == ""
}

func (r RangeSpec) matches(v string) bool {
	if r.empty() {
		return false
	}
	if r.Equals != "" {
		return compareVersion(v, r.Equals) == 0
	}
	if r.Branch != "" {
		maj, min, ok := parseBranch(r.Branch)
		vmaj, vmin, _, vok := parseVersion(v)
		if !ok || !vok || maj != vmaj || min != vmin {
			return false
		}
	}
	if r.Introduced != "" && compareVersion(v, r.Introduced) < 0 {
		return false
	}
	if r.Fixed != "" && compareVersion(v, r.Fixed) >= 0 {
		return false
	}
	if r.LessThan != "" && compareVersion(v, r.LessThan) >= 0 {
		return false
	}
	return true
}

// FeedEntry is one catalogue entry (a CVE or advisory) plus its affected ranges.
type FeedEntry struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Reference   string      `json:"reference,omitempty"`
	Note        string      `json:"note,omitempty"`
	Affected    []RangeSpec `json:"affected"`
	// Prereqs are structured applicability conditions resolved against the
	// scan's observed evidence (optional; absent ⇒ a plain version-range lead).
	Prereqs []Prereq `json:"prereqs,omitempty"`
	// AlertUnknownVersion asks for an informational ("info" severity) lead when
	// Ruby is detected but its version is not disclosed. Reserve it for issues
	// serious enough that "could not be ruled out" is worth an operator's time.
	AlertUnknownVersion bool `json:"alert_unknown_version,omitempty"`
}

// Prereq is a structured applicability condition for a lead.
//
//	Kind "framework":  Want is one or more framework names separated by "|"
//	                   (e.g. "rails|sinatra"). Observed when any is detected;
//	                   never contradicted, since absence is not proof.
//	Kind "app-server": Want is an app-server family token (puma, passenger,
//	                   webrick, unicorn, thin, falcon).
//	Kind "os":         Want is an OS token (windows, linux, darwin, bsd).
//	Kind "gem":        Want is a gem name (observed only; never contradicted).
//	Kind "env":        Want is a Rails/Rack environment (e.g. "development").
type Prereq struct {
	Kind   string `json:"kind"`
	Want   string `json:"want"`
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// ObservedFacts is the evidence a scan gathered, used to resolve prerequisites.
type ObservedFacts struct {
	AppServer  string          // inferred app server (e.g. "Puma", "Phusion Passenger")
	System     string          // platform string (e.g. "x86_64-linux" from rails/info)
	Env        string          // Rails/Rack environment when observed
	Frameworks map[string]bool // lowercased framework/application names present
	Gems       map[string]bool // lowercased gem names present
}

func (e FeedEntry) matches(v string) bool {
	for _, r := range e.Affected {
		if r.matches(v) {
			return true
		}
	}
	return false
}

// VulnFeed is the on-disk / remote JSON format for external vulnerability data.
type VulnFeed struct {
	Schema    string      `json:"schema"`
	Generated string      `json:"generated,omitempty"`
	Ruby      []FeedEntry `json:"ruby,omitempty"`
	// CMS holds advisories keyed by framework / application / stack component
	// name (Rails, Rack, Sinatra, GitLab, Mastodon, Phusion Passenger, …).
	CMS map[string][]FeedEntry `json:"cms,omitempty"`
	// Packages holds advisories keyed by a RubyGems gem name.
	Packages map[string][]FeedEntry `json:"packages,omitempty"`
	EOL      map[string]string      `json:"eol,omitempty"`
}

// Catalog holds the active vulnerability and end-of-life data: the built-in
// curated set, merged with any external feeds.
type Catalog struct {
	ruby []FeedEntry
	cms  map[string][]FeedEntry
	pkg  map[string][]FeedEntry
	eol  map[string]string
}

// DefaultCatalog returns a fresh catalog built from the curated built-in data.
func DefaultCatalog() *Catalog {
	c := &Catalog{
		ruby: append([]FeedEntry(nil), builtinRuby...),
		cms:  map[string][]FeedEntry{},
		pkg:  map[string][]FeedEntry{},
		eol:  map[string]string{},
	}
	for k, v := range builtinCMS {
		c.cms[strings.ToLower(k)] = append([]FeedEntry(nil), v...)
	}
	for k, v := range builtinPackages {
		c.pkg[strings.ToLower(k)] = append([]FeedEntry(nil), v...)
	}
	for k, v := range builtinEOL {
		c.eol[k] = v
	}
	return c
}

// Merge folds an external feed into the catalog (appending entries and
// overriding EOL dates by branch).
func (c *Catalog) Merge(f *VulnFeed) {
	if f == nil {
		return
	}
	c.ruby = append(c.ruby, f.Ruby...)
	if c.cms == nil {
		c.cms = map[string][]FeedEntry{}
	}
	for k, entries := range f.CMS {
		key := strings.ToLower(k)
		c.cms[key] = append(c.cms[key], entries...)
	}
	if c.pkg == nil {
		c.pkg = map[string][]FeedEntry{}
	}
	for k, entries := range f.Packages {
		key := strings.ToLower(k)
		c.pkg[key] = append(c.pkg[key], entries...)
	}
	if c.eol == nil {
		c.eol = map[string]string{}
	}
	for branch, date := range f.EOL {
		c.eol[branch] = date
	}
}

// Counts reports how many Ruby-core entries and how many framework,
// application and gem entries the catalog holds.
func (c *Catalog) Counts() (ruby, cms int) {
	ruby = len(c.ruby)
	for _, e := range c.cms {
		cms += len(e)
	}
	for _, e := range c.pkg {
		cms += len(e)
	}
	return
}

// cRuby reports whether a variant uses the reference implementation's C
// core. JRuby and TruffleRuby reimplement the core and follow their own
// numbering for it, so C-core advisories are not correlated against them.
func cRuby(variant string) bool {
	return variant == "" || variant == "Ruby"
}

// CorrelateRuby returns leads for the detected Ruby version. The optional
// facts argument supplies observed evidence for resolving prerequisites;
// omitting it leaves prerequisites "unknown".
func (c *Catalog) CorrelateRuby(variant, version string, facts ...ObservedFacts) []Vulnerability {
	if version == "" || !cRuby(variant) {
		return nil
	}
	if _, _, _, ok := parseVersion(version); !ok {
		return nil
	}
	return matchEntries(c.ruby, version, "version-correlation", optFacts(facts))
}

// CorrelateRubyBranch returns leads that hold for an entire release branch
// (e.g. "3.2"), used when only the branch — not the patch release — could be
// learned. An entry matches only when both the first and a notional last
// release of the branch fall inside an affected range.
func (c *Catalog) CorrelateRubyBranch(variant, branch string, facts ...ObservedFacts) []Vulnerability {
	if branch == "" || !cRuby(variant) {
		return nil
	}
	if _, _, ok := parseBranch(branch); !ok {
		return nil
	}
	var whole []FeedEntry
	for _, e := range c.ruby {
		if e.matches(branch+".0") && e.matches(branch+".9999") {
			whole = append(whole, e)
		}
	}
	return matchEntries(whole, branch+".0", "branch-correlation (every "+branch+".x release is affected; patch level unknown)", optFacts(facts))
}

// UnknownVersionLeads returns informational leads for entries flagged
// AlertUnknownVersion, used when Ruby is detected but discloses no version:
// the exposure can be neither confirmed nor ruled out remotely.
func (c *Catalog) UnknownVersionLeads(variant string, facts ...ObservedFacts) []Vulnerability {
	if !cRuby(variant) {
		return nil
	}
	var out []Vulnerability
	for _, e := range c.ruby {
		if !e.AlertUnknownVersion {
			continue
		}
		v := Vulnerability{
			ID:               e.ID,
			Severity:         "info",
			Title:            e.Title + " — Ruby version not disclosed, exposure cannot be ruled out",
			AffectedVersions: affectedSummary(e.Affected),
			Description: e.Description + " The Ruby version could not be determined remotely; " +
				"check `ruby -v` on the host against the affected versions.",
			Reference:  e.Reference,
			MatchBasis: "Ruby detected, version unknown (not a version match)",
		}
		v.Prerequisites, v.Applicability = resolvePrereqs(e.Prereqs, optFacts(facts))
		if v.Applicability != "contradicted" {
			v.Applicability = "unverified"
		}
		out = append(out, v)
	}
	return out
}

// componentKey normalises a framework / component / gem name to a catalogue
// key, folding Rails' component gems and common aliases together.
func componentKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "ruby on rails", "railties":
		return "rails"
	case "phusion passenger":
		return "passenger"
	case "ghes", "github enterprise":
		return "github enterprise server"
	}
	return n
}

func (c *Catalog) componentEntries(name string) []FeedEntry {
	key := componentKey(name)
	var out []FeedEntry
	out = append(out, c.cms[key]...)
	out = append(out, c.pkg[key]...)
	return out
}

// CorrelatePackage returns leads for a gem at a concrete version.
func (c *Catalog) CorrelatePackage(name, version string, facts ...ObservedFacts) []Vulnerability {
	if name == "" || version == "" {
		return nil
	}
	entries := c.componentEntries(name)
	if len(entries) == 0 {
		return nil
	}
	if _, _, _, ok := parseVersion(version); !ok {
		return nil
	}
	return matchEntries(entries, version, name+" gem-correlation", optFacts(facts))
}

// CorrelateCMS returns leads for a detected framework, application or stack
// component version.
func (c *Catalog) CorrelateCMS(framework, version string, facts ...ObservedFacts) []Vulnerability {
	if framework == "" || version == "" {
		return nil
	}
	entries := c.componentEntries(framework)
	if len(entries) == 0 {
		return nil
	}
	if _, _, _, ok := parseVersion(version); !ok {
		return nil
	}
	return matchEntries(entries, version, framework+" version-correlation", optFacts(facts))
}

func optFacts(facts []ObservedFacts) ObservedFacts {
	if len(facts) > 0 {
		return facts[0]
	}
	return ObservedFacts{}
}

func matchEntries(entries []FeedEntry, version, basisKind string, facts ObservedFacts) []Vulnerability {
	var out []Vulnerability
	for _, e := range entries {
		if !e.matches(version) {
			continue
		}
		basis := basisKind
		if e.Note != "" {
			basis += "; applies to: " + e.Note
		}
		v := Vulnerability{
			ID:               e.ID,
			Severity:         e.Severity,
			Title:            e.Title,
			AffectedVersions: affectedSummary(e.Affected),
			Description:      e.Description,
			Reference:        e.Reference,
			MatchBasis:       basis,
		}
		v.Prerequisites, v.Applicability = resolvePrereqs(e.Prereqs, facts)
		out = append(out, v)
	}
	return out
}

// resolvePrereqs resolves each prerequisite against the observed facts and
// summarises applicability: any contradicted ⇒ "contradicted"; else any
// observed ⇒ "observed"; else "" (plain lead).
func resolvePrereqs(prereqs []Prereq, facts ObservedFacts) ([]PrereqResult, string) {
	if len(prereqs) == 0 {
		return nil, ""
	}
	results := make([]PrereqResult, 0, len(prereqs))
	anyContradicted, anyObserved := false, false
	for _, p := range prereqs {
		state := resolvePrereq(p, facts)
		switch state {
		case "contradicted":
			anyContradicted = true
		case "observed":
			anyObserved = true
		}
		results = append(results, PrereqResult{Detail: prereqDetail(p), State: state})
	}
	switch {
	case anyContradicted:
		return results, "contradicted"
	case anyObserved:
		return results, "observed"
	default:
		return results, ""
	}
}

func prereqDetail(p Prereq) string {
	if p.Detail != "" {
		return p.Detail
	}
	switch p.Kind {
	case "framework":
		return "requires " + strings.ReplaceAll(p.Want, "|", " or ")
	case "app-server":
		return "requires the " + p.Want + " app server"
	case "os":
		return "requires " + p.Want
	case "gem":
		return "requires the " + p.Want + " gem"
	case "env":
		return "requires the " + p.Want + " environment"
	default:
		return p.Kind + " " + p.Want
	}
}

func resolvePrereq(p Prereq, facts ObservedFacts) string {
	switch p.Kind {
	case "framework":
		// Absence is not proof (a framework can hide), so never contradicted.
		for _, w := range strings.Split(strings.ToLower(p.Want), "|") {
			if facts.Frameworks[strings.TrimSpace(w)] {
				return "observed"
			}
		}
		return "unknown"
	case "app-server":
		fam := appServerFamily(facts.AppServer)
		if fam == "" {
			return "unknown"
		}
		if fam == strings.ToLower(p.Want) {
			return "observed"
		}
		return "contradicted"
	case "os":
		os := osFamily(facts.System)
		if os == "" {
			return "unknown"
		}
		if os == strings.ToLower(p.Want) {
			return "observed"
		}
		return "contradicted"
	case "gem":
		if facts.Gems[strings.ToLower(p.Want)] {
			return "observed"
		}
		return "unknown"
	case "env":
		if facts.Env == "" {
			return "unknown"
		}
		if strings.EqualFold(facts.Env, p.Want) {
			return "observed"
		}
		return "contradicted"
	default:
		return "unknown"
	}
}

// appServerFamily maps an observed app-server string to a single family
// token, or "" when it is unknown.
func appServerFamily(s string) string {
	l := strings.ToLower(s)
	for _, fam := range []string{"passenger", "webrick", "puma", "unicorn", "thin", "falcon", "mongrel", "torquebox", "pitchfork"} {
		if strings.Contains(l, fam) {
			return fam
		}
	}
	return ""
}

func osFamily(system string) string {
	l := strings.ToLower(system)
	switch {
	case l == "":
		return ""
	case strings.Contains(l, "mingw") || strings.Contains(l, "mswin") || strings.Contains(l, "windows"):
		return "windows"
	case strings.Contains(l, "darwin"):
		return "darwin"
	case strings.Contains(l, "linux"):
		return "linux"
	case strings.Contains(l, "bsd"):
		return "bsd"
	default:
		return ""
	}
}

// EOL reports whether the version's release branch has reached end of security
// support, relative to the current date. JRuby and TruffleRuby follow their own
// release lines and are not evaluated.
func (c *Catalog) EOL(variant, version string) (bool, string) {
	if !cRuby(variant) {
		return false, ""
	}
	maj, min, _, ok := parseVersion(version)
	if !ok {
		return false, ""
	}
	branch := fmt.Sprintf("%d.%d", maj, min)
	if maj < 2 {
		return true, fmt.Sprintf("Ruby %s is long past end of life", branch)
	}
	date, known := c.eol[branch]
	if !known {
		return false, ""
	}
	end, err := time.Parse("2006-01-02", date)
	if err != nil {
		return false, ""
	}
	if time.Now().After(end) {
		return true, fmt.Sprintf("Ruby %s reached end of security support on %s", branch, date)
	}
	return false, fmt.Sprintf("Ruby %s receives security support until %s", branch, date)
}

func affectedSummary(ranges []RangeSpec) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		switch {
		case r.Equals != "":
			parts = append(parts, "= "+r.Equals)
		case r.Branch != "" && r.LessThan != "":
			parts = append(parts, r.Branch+".x < "+r.LessThan)
		case r.Branch != "" && r.Fixed != "":
			parts = append(parts, r.Branch+".x < "+r.Fixed)
		case r.Introduced != "" && r.Fixed != "":
			parts = append(parts, r.Introduced+" – "+r.Fixed)
		case r.LessThan != "":
			parts = append(parts, "< "+r.LessThan)
		case r.Fixed != "":
			parts = append(parts, "< "+r.Fixed)
		case r.Branch != "":
			parts = append(parts, r.Branch+".x")
		}
	}
	return strings.Join(parts, ", ")
}

// ParseFeed decodes feed JSON, auto-detecting the native qrubyscanner schema,
// the OSV format (single record or array) and CSAF 2.0 advisories.
func ParseFeed(data []byte) (*VulnFeed, error) {
	switch detectFeedFormat(data) {
	case feedOSV:
		return convertOSV(data)
	case feedCSAF:
		return convertCSAF(data)
	default:
		var f VulnFeed
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse vuln feed: %w", err)
		}
		if f.Schema != "" && f.Schema != FeedSchema {
			return nil, fmt.Errorf("unsupported vuln feed schema %q (want %q, or an OSV/CSAF document)", f.Schema, FeedSchema)
		}
		return &f, nil
	}
}

// LoadFeed reads a feed from a local file path or an http(s) URL.
func LoadFeed(ctx context.Context, src string, client *http.Client) (*VulnFeed, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch vuln feed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch vuln feed: HTTP %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return nil, err
		}
		return ParseFeed(data)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("read vuln feed: %w", err)
	}
	return ParseFeed(data)
}

// SeverityRank maps a severity string to a comparable rank (higher = worse).
func SeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func parseBranch(b string) (maj, min int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(b), ".", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	m, n, _, vok := parseVersion(b + ".0")
	return m, n, vok
}
