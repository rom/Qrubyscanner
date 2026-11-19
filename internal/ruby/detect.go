package ruby

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/rom/qrubyscanner/internal/probe"
)

// Input bundles everything Analyze needs about one HTTP(S) service.
type Input struct {
	// TargetURL is the primary scheme://host:port/path that was requested.
	TargetURL string
	// Deep enables version/gem/app-server fingerprinting and vulnerability
	// correlation. When false, Analyze stops at the Ruby yes/no verdict.
	Deep bool
	// Root is the response to the primary request. Required.
	Root *probe.Response
	// Extra holds deep-mode probe responses keyed by requested URL.
	Extra map[string]*probe.Response
	// Favicon is the /favicon.ico response (deep mode), used for a Shodan-style
	// mmh3 fingerprint hash.
	Favicon *probe.Response
	// ParamProbe is the response to ParamTypeProbe (deep mode): a 400 where
	// the plain request succeeded is Rack's query-parser behaviour.
	ParamProbe *probe.Response
	// Control is the response to a guaranteed-nonexistent URL (deep mode). It
	// serves two purposes: its body is analysed like any other (framework 404
	// pages are highly characteristic), and it is the soft-404 baseline — a
	// server that returns a normal page for a path that cannot exist is a
	// catch-all, so behavioural signals are suppressed when a probed response
	// is indistinguishable from this baseline.
	Control *probe.Response
	// Catalog supplies vulnerability/EOL data. When nil, the built-in default
	// catalogue is used.
	Catalog *Catalog
	// BundlerFiles are operator-supplied Bundler file contents (Gemfile /
	// Gemfile.lock, sniffed by content) for projects whose files are not
	// web-exposed. They augment or override any fetched ones.
	BundlerFiles [][]byte
}

const (
	maxDataLen      = 200
	maxObservedGems = 80
)

// Version-observation ranks: what the running process reported beats what a
// project file declares, which beats a hint.
const (
	rankRunning  = 3 // banner, /rails/info/properties, `ruby -v` string
	rankDeclared = 2 // .ruby-version, Gemfile(.lock), install path
)

var (
	reCookieMarshal   = regexp.MustCompile(`^BAh[A-Za-z0-9+/=]*--[0-9a-f]{40,64}$`)
	reCookieSigned    = regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}--[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
	reCookieEncrypted = regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}--[A-Za-z0-9+/=]{16}--[A-Za-z0-9+/=]{22,24}$`)

	reRailsLog       = regexp.MustCompile(`Started (?:GET|POST|PUT|PATCH|DELETE|HEAD) "[^"]*" for [0-9a-fA-F.:]+ at \d{4}-\d{2}-\d{2}|Processing by \w+(?:::\w+)*#\w+ as `)
	reConfigRu       = regexp.MustCompile(`(?m)^\s*run\s+[A-Z(:]|^\s*require(?:_relative)?\s+['"]`)
	reRakefile       = regexp.MustCompile(`Rails\.application\.load_tasks|require(?:_relative)?\s+['"](?:rake|\.?/?config/application)['"]|(?m)^\s*task\s+:?\w+`)
	reDatabaseYml    = regexp.MustCompile(`(?m)^\s*adapter:\s*([\w-]+)`)
	reMasterKey      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reSidekiqVersion = regexp.MustCompile(`Sidekiq v?(\d+\.\d+\.\d+)`)
	reJSONVersion    = regexp.MustCompile(`"version"\s*:\s*"([^"]{1,60})"`)
	reGHESVersion    = regexp.MustCompile(`"installed_version"\s*:\s*"(\d+\.\d+\.\d+)"`)
	reGitLabHelp     = regexp.MustCompile(`GitLab\s+(?:Community|Enterprise) Edition\s+(?:<[^>]+>\s*)*v?(\d+\.\d+\.\d+)`)
	reDiscourseGen   = regexp.MustCompile(`(?i)Discourse (\d+(?:\.\d+){1,2}(?:\.beta\d+)?)`)
	reLeadingVersion = regexp.MustCompile(`^(\d+(?:\.\d+){1,3})`)
)

// railsGems are the component gems whose version equals the Rails version.
var railsGems = map[string]bool{
	"rails": true, "railties": true, "actionpack": true, "activerecord": true, "activesupport": true,
	"actionview": true, "activemodel": true, "activejob": true, "actionmailer": true, "actioncable": true,
	"activestorage": true, "actiontext": true, "actionmailbox": true,
}

// promotedGems are gems whose version is reported as a top-level component
// (and correlated there) rather than only in the gem inventory.
var promotedGems = map[string]string{
	"rack": "Rack", "sinatra": "Sinatra", "puma": "Puma", "passenger": "Phusion Passenger",
	"webrick": "WEBrick", "thin": "Thin", "unicorn": "Unicorn", "sidekiq": "Sidekiq",
	"hanami": "Hanami", "padrino": "Padrino", "roda": "Roda", "grape": "Grape", "falcon": "Falcon",
}

// analysis carries the mutable state shared by the detection stages.
type analysis struct {
	d           *Detection
	seen        map[string]bool
	fwSet       map[string]bool
	gemSet      map[string]bool
	modSet      map[string]bool
	obsSeen     map[string]bool
	versionRank int
	comp        map[string]compVersion // component name -> best version
	observed    map[string]string      // gem name -> version, from backtrace paths
	env         string
}

type compVersion struct{ ver, src string }

func newAnalysis() *analysis {
	return &analysis{
		d: &Detection{}, seen: map[string]bool{}, fwSet: map[string]bool{}, gemSet: map[string]bool{},
		modSet: map[string]bool{}, obsSeen: map[string]bool{}, comp: map[string]compVersion{}, observed: map[string]string{},
	}
}

func (a *analysis) addEv(ev Evidence) {
	// De-duplicate by signal: the same signal seen on several deep-mode
	// probe URLs should count and display only once.
	if a.seen[ev.Signal] {
		return
	}
	a.seen[ev.Signal] = true
	if len(ev.Data) > maxDataLen {
		ev.Data = ev.Data[:maxDataLen] + "…"
	}
	if ev.Confidence == "" {
		ev.Confidence = confidenceTier(ev.Weight)
	}
	if ev.Probe == "" {
		ev.Probe = ev.Source
	}
	if ev.Where == "" || ev.How == "" {
		w, h := provenanceDefaults(ev.Signal)
		if ev.Where == "" {
			ev.Where = w
		}
		if ev.How == "" {
			ev.How = h
		}
	}
	if ev.Snippet == "" && ev.Data != "" {
		ev.Snippet = ev.Data
	}
	a.d.Evidence = append(a.d.Evidence, ev)
	a.d.Confidence += ev.Weight
}

func (a *analysis) addFw(f string) {
	if f == "" || a.fwSet[f] {
		return
	}
	a.fwSet[f] = true
	a.d.Frameworks = append(a.d.Frameworks, f)
}

func (a *analysis) addGem(g string) {
	key := strings.ToLower(g)
	if g == "" || a.gemSet[key] {
		return
	}
	a.gemSet[key] = true
	a.d.Gems = append(a.d.Gems, g)
}

func (a *analysis) addMod(m string) {
	if m == "" || a.modSet[m] {
		return
	}
	a.modSet[m] = true
	a.d.Modules = append(a.d.Modules, m)
}

// setVersion records a Ruby version observation; the highest-ranked one
// becomes the headline Version.
func (a *analysis) setVersion(v, source string, rank int) {
	if v == "" {
		return
	}
	if key := v + "\x00" + source; !a.obsSeen[key] {
		a.obsSeen[key] = true
		a.d.VersionObservations = append(a.d.VersionObservations, VersionObservation{Version: v, Source: source, Rank: rank})
	}
	if rank > a.versionRank {
		a.d.Version = v
		a.d.VersionSource = source
		a.versionRank = rank
	}
}

func (a *analysis) setVariant(v string) {
	if v == "" {
		return
	}
	// A specific alternative implementation overrides the generic "Ruby".
	if a.d.Variant == "" || (a.d.Variant == "Ruby" && v != "Ruby") {
		a.d.Variant = v
	}
}

func (a *analysis) setBranch(b string) {
	if b != "" && a.d.Branch == "" {
		a.d.Branch = b
	}
}

// setComp records a framework / component version, preferring the most
// specific (most dotted) value seen.
func (a *analysis) setComp(name, ver, src string) {
	ver = strings.TrimSpace(ver)
	if name == "" || ver == "" {
		return
	}
	if _, _, _, ok := parseVersion(ver); !ok {
		return
	}
	if cur, ok := a.comp[name]; ok && strings.Count(cur.ver, ".") >= strings.Count(ver, ".") {
		return
	}
	a.comp[name] = compVersion{ver, src}
}

func (a *analysis) setEnv(env string) {
	if env != "" && a.env == "" {
		a.env = env
	}
}

// Analyze turns collected responses into a Ruby Detection.
func Analyze(in Input) *Detection {
	if in.Root == nil {
		return nil
	}
	a := newAnalysis()
	d := a.d

	// Soft-404 / catch-all baseline.
	ctrl := controlSignature(in.Control)

	// --- Primary response ---------------------------------------------------
	a.analyzeResponse(in.Root, in.TargetURL)

	// --- URL extension hint -------------------------------------------------
	if u := strings.ToLower(in.TargetURL); hasRubyExtension(u) {
		a.addEv(Evidence{
			Signal: "url.ruby-extension", Source: in.TargetURL, Weight: 40,
			Detail: "Requested path uses a Ruby file extension",
			Where:  "request URL", How: "URL suffix match",
			Pattern: ".rb/.erb/.rhtml/.rbx", Snippet: in.TargetURL, Status: in.Root.Status,
		})
	}

	// --- Not-found page -----------------------------------------------------
	// Framework 404 pages (Rails' static page or routing error, Sinatra's
	// "doesn't know this ditty", WEBrick's signature footer) are among the best
	// passive Ruby indicators, so the control response is analysed too.
	if c := in.Control; c != nil && c.Err == "" {
		a.analyzeResponse(c, c.RequestURL)
	}

	// --- Deep probes --------------------------------------------------------
	var gemfile, lock string
	urls := make([]string, 0, len(in.Extra))
	for u := range in.Extra {
		urls = append(urls, u)
	}
	sort.Strings(urls) // deterministic evidence attribution
	for _, u := range urls {
		resp := in.Extra[u]
		if resp == nil || resp.Err != "" {
			continue
		}
		a.analyzeResponse(resp, u)
		body := resp.BodyString()
		a.detectAppEndpoints(u, resp, body)
		if resp.Status != 200 {
			continue
		}
		if isRailsInfo(body) {
			a.absorbRailsInfo(u, resp, body)
		}
		switch {
		case isGemfileLock(body):
			lock = body
			a.addEv(Evidence{Signal: "diag.gemfile-lock", Source: u, Weight: 75, Status: resp.Status,
				Detail: "Gemfile.lock is publicly readable (Bundler lockfile — full dependency list)"})
		case strings.HasSuffix(strings.ToLower(pathOf(u)), "/gemfile") && isGemfile(body):
			gemfile = body
			a.addEv(Evidence{Signal: "diag.gemfile", Source: u, Weight: 70, Status: resp.Status,
				Detail: "Gemfile is publicly readable (Ruby project manifest)"})
		}
		a.detectExposures(u, resp, body)
	}

	// --- Rack parameter-type behavioural probe ------------------------------
	if p := in.ParamProbe; p != nil && p.Err == "" {
		a.analyzeResponse(p, p.RequestURL)
		if p.Status == 400 && in.Root.Status > 0 && in.Root.Status < 400 && !ctrl.matches(p) {
			a.addEv(Evidence{
				Signal: "behavior.rack-param-type", Source: p.RequestURL, Weight: 30,
				Detail:  "A query declaring one parameter as both array and hash is rejected with 400 while the plain request succeeds (Rack query-parser behaviour)",
				Pattern: ParamTypeProbe, Status: p.Status,
			})
		}
	}

	// --- Favicon fingerprint (deep mode) ------------------------------------
	if in.Favicon != nil && in.Favicon.Err == "" && in.Favicon.Status == 200 && len(in.Favicon.Body) > 0 {
		d.FaviconHash = faviconHash(in.Favicon.Body)
		if entry, ok := faviconLookup(d.FaviconHash); ok {
			w := 40
			if !entry.Ruby {
				w = 0
			}
			detail := "favicon hash matches " + entry.Product
			if entry.Note != "" {
				detail += " (" + entry.Note + ")"
			}
			a.addEv(Evidence{
				Signal: "favicon.catalog", Source: in.Favicon.FinalURL, Weight: w,
				Detail: detail, Data: d.FaviconHash + " → " + entry.Product,
				Where: "site favicon", How: "mmh3 favicon-hash catalogue match",
				Pattern: d.FaviconHash, Snippet: entry.Product, Status: in.Favicon.Status,
			})
			a.addFw(entry.Framework)
		}
	}

	// --- Bundler dependency inventory ---------------------------------------
	// Operator-supplied files augment or override the web-fetched ones.
	for _, raw := range in.BundlerFiles {
		switch classifyBundler(string(raw)) {
		case "lock":
			lock = string(raw)
		case "gemfile":
			gemfile = string(raw)
		}
	}
	inv := buildBundlerInventory(gemfile, lock)
	a.absorbInventory(inv)

	// Gems leaked in backtrace paths join the inventory as "observed".
	if len(a.observed) > 0 {
		if inv == nil {
			inv = &BundlerInventory{}
		}
		inv.mergeObserved(a.observed)
	}

	// --- Component versions --------------------------------------------------
	if len(a.comp) > 0 {
		d.FrameworkVersions = make(map[string]string, len(a.comp))
		names := make([]string, 0, len(a.comp))
		for n := range a.comp {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			c := a.comp[n]
			d.FrameworkVersions[n] = c.ver
			if !isStackComponent(n) {
				a.addFw(n)
			}
			// A version for a Ruby-only component is itself mild evidence of
			// Ruby; Passenger also hosts Python and Node.js, so it is not.
			w := 15
			if n == "Phusion Passenger" {
				w = 0
			}
			a.addEv(Evidence{
				Signal: "component.version." + strings.ToLower(strings.ReplaceAll(n, " ", "-")), Source: c.src, Weight: w,
				Detail: n + " version " + c.ver, Data: c.ver,
			})
		}
	}

	// --- Finalise -----------------------------------------------------------
	if d.Confidence > 100 {
		d.Confidence = 100
	}
	d.Verdict = scoreToVerdict(d.Confidence)
	d.IsRuby = d.Confidence >= 50
	if d.IsRuby && d.Variant == "" {
		d.Variant = "Ruby"
	}
	if b := branchOf(d.Version); b != "" {
		d.Branch = b
	}

	d.Frameworks, d.Addons = partitionAddons(d.Frameworks)
	sort.Strings(d.Frameworks)
	sort.Strings(d.Addons)
	sort.Strings(d.Gems)
	sort.Strings(d.Modules)
	sortEvidence(d.Evidence)

	d.VersionConflict = versionsConflict(d.VersionObservations)
	d.RailsEnv = a.inferEnv()
	if d.IsRuby {
		d.AppServer = a.inferAppServer(inv)
	}

	hasInventory := inv != nil && (len(inv.Gems) > 0 || inv.RubyRequire != "" || inv.RubyLocked != "")
	if hasInventory {
		d.Bundler = inv
	}
	facts := observedFacts(d)
	if in.Deep && d.IsRuby {
		cat := in.Catalog
		if cat == nil {
			cat = DefaultCatalog()
		}
		var core, comp []Vulnerability
		switch {
		case d.Version != "":
			d.EndOfLife, d.EOLDetail = cat.EOL(d.Variant, d.Version)
			core = cat.CorrelateRuby(d.Variant, d.Version, facts)
		case d.Branch != "":
			d.EndOfLife, d.EOLDetail = cat.EOL(d.Variant, d.Branch+".0")
			core = cat.CorrelateRubyBranch(d.Variant, d.Branch, facts)
		}
		for _, name := range sortedKeys(d.FrameworkVersions) {
			comp = append(comp, cat.CorrelateCMS(name, d.FrameworkVersions[name], facts)...)
		}
		// A Ruby version that was actually observed supersedes inferences made
		// from a product's bundled interpreter.
		if d.Version != "" {
			comp = dropID(comp, ruby2ID)
		}
		d.Vulnerabilities = append(core, comp...)
		// Nothing told us the Ruby version: say so rather than stay silent
		// about issues that could not be ruled out.
		if d.Version == "" && d.Branch == "" && !hasID(d.Vulnerabilities, ruby2ID) {
			d.Vulnerabilities = append(d.Vulnerabilities, cat.UnknownVersionLeads(d.Variant, facts)...)
		}
		sortVulns(d.Vulnerabilities)
	}

	if hasInventory {
		if in.Deep {
			cat := in.Catalog
			if cat == nil {
				cat = DefaultCatalog()
			}
			skip := map[string]bool{}
			for name := range d.FrameworkVersions {
				skip[componentKey(name)] = true
			}
			if skip["rails"] {
				for g := range railsGems {
					skip[g] = true
				}
			}
			correlateBundler(cat, inv, facts, skip)
		}
	}

	return d
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func hasID(vs []Vulnerability, id string) bool {
	for _, v := range vs {
		if v.ID == id {
			return true
		}
	}
	return false
}

func dropID(vs []Vulnerability, id string) []Vulnerability {
	out := vs[:0]
	for _, v := range vs {
		if v.ID != id {
			out = append(out, v)
		}
	}
	return out
}

// isStackComponent reports names that are versioned parts of the stack rather
// than frameworks/applications (they are shown under app server / modules).
func isStackComponent(name string) bool {
	switch name {
	case "Phusion Passenger", "WEBrick", "Thin", "Puma", "Unicorn", "Falcon", "Mongrel", "JRuby", "Sidekiq":
		return true
	}
	return false
}

// absorbRailsInfo records an exposed /rails/info/properties page.
func (a *analysis) absorbRailsInfo(u string, resp *probe.Response, body string) {
	d := a.d
	d.RailsInfoExposed = true
	d.RailsInfoURL = u
	a.addFw("Rails")
	a.addEv(Evidence{
		Signal: "diag.rails-info", Source: u, Weight: 90, Status: resp.Status,
		Detail: "/rails/info/properties is publicly exposed (development-mode diagnostics: exact Ruby, Rails and Rack versions)",
	})
	facts := parseRailsInfo(body)
	if facts == nil {
		return
	}
	d.RailsInfo = facts
	if strings.Contains(strings.ToLower(facts.RubyDescription), "jruby") || strings.Contains(strings.ToLower(facts.RubyDescription), "java") {
		a.setVariant("JRuby")
	} else if strings.Contains(strings.ToLower(facts.RubyDescription), "truffleruby") {
		a.setVariant("TruffleRuby")
	}
	a.setVersion(facts.RubyVersion, "/rails/info/properties", rankRunning+1)
	a.setComp("Rails", facts.RailsVersion, u)
	a.setComp("Rack", facts.RackVersion, u)
	a.setEnv(facts.Environment)
	for _, mw := range facts.Middleware {
		for prefix, gem := range middlewareGems {
			if gem != "" && strings.HasPrefix(mw, prefix) {
				a.addGem(gem)
			}
		}
	}
	if facts.DatabaseAdapter != "" {
		a.addGem("database adapter: " + facts.DatabaseAdapter)
	}
}

// absorbInventory feeds a Bundler inventory back into the detection: the
// locked Ruby version and the framework / server versions it pins.
func (a *analysis) absorbInventory(inv *BundlerInventory) {
	if inv == nil {
		return
	}
	if inv.RubyLocked != "" {
		v, variant := lockedRubyVersion(inv.RubyLocked)
		a.setVariant(variant)
		a.setVersion(v, "Gemfile.lock RUBY VERSION (interpreter at lock time)", rankDeclared)
	}
	if r := strings.TrimSpace(inv.RubyRequire); reExactVersion.MatchString(r) {
		a.setVersion(r, "Gemfile ruby directive", rankDeclared)
	}
	railsVer := inv.gemVersion("rails")
	if railsVer == "" {
		railsVer = inv.gemVersion("railties")
	}
	if railsVer != "" {
		a.setComp("Rails", railsVer, "Gemfile.lock")
	}
	for gem, label := range promotedGems {
		if v := inv.gemVersion(gem); v != "" {
			a.setComp(label, v, "Gemfile.lock")
		}
	}
}

// mergeObserved adds gems seen in backtrace paths, which reflect the running
// application and therefore outrank lockfile entries.
func (inv *BundlerInventory) mergeObserved(observed map[string]string) {
	idx := map[string]int{}
	for i, g := range inv.Gems {
		idx[g.Name] = i
	}
	names := make([]string, 0, len(observed))
	for n := range observed {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		g := BundlerGem{Name: n, Version: observed[n], Class: "observed"}
		if i, ok := idx[n]; ok {
			inv.Gems[i] = g
		} else if len(inv.Gems) < maxBundlerGems {
			inv.Gems = append(inv.Gems, g)
		}
	}
	sort.Slice(inv.Gems, func(i, j int) bool { return inv.Gems[i].Name < inv.Gems[j].Name })
}

// versionsConflict reports whether observations disagree at major.minor level.
func versionsConflict(obs []VersionObservation) bool {
	seen := map[string]bool{}
	for _, o := range obs {
		if maj, min, _, ok := parseVersion(o.Version); ok {
			seen[fmt.Sprintf("%d.%d", maj, min)] = true
		}
	}
	return len(seen) > 1
}

// observedFacts gathers the evidence used to resolve vulnerability
// prerequisites.
func observedFacts(d *Detection) ObservedFacts {
	f := ObservedFacts{AppServer: d.AppServer, Env: d.RailsEnv, Frameworks: map[string]bool{}, Gems: map[string]bool{}}
	for _, list := range [][]string{d.Frameworks, d.Addons} {
		for _, fw := range list {
			f.Frameworks[strings.ToLower(fw)] = true
		}
	}
	for name := range d.FrameworkVersions {
		f.Frameworks[strings.ToLower(name)] = true
	}
	for _, g := range d.Gems {
		f.Gems[strings.ToLower(g)] = true
	}
	if d.Bundler != nil {
		for _, g := range d.Bundler.Gems {
			f.Gems[strings.ToLower(g.Name)] = true
		}
	}
	if d.RailsInfo != nil {
		f.System = d.RailsInfo.System
	}
	// Applications built on Rails imply Rails.
	for app := range railsApps {
		if f.Frameworks[strings.ToLower(app)] {
			f.Frameworks["rails"] = true
		}
	}
	return f
}

// railsApps are applications known to be built on Rails; detecting one
// satisfies a "rails" prerequisite.
var railsApps = map[string]bool{
	"GitLab": true, "Discourse": true, "Mastodon": true, "Redmine": true, "OpenProject": true,
	"Chatwoot": true, "diaspora*": true, "Huginn": true, "Zammad": true, "Canvas LMS": true,
	"Decidim": true, "Dradis": true, "Errbit": true, "Spree": true, "Solidus": true,
	"GitHub": true, "GitHub Enterprise Server": true, "Foreman": true, "Forem": true,
	"Refinery CMS": true, "Alchemy CMS": true, "Camaleon CMS": true, "Publify": true,
	"Fat Free CRM": true, "Loomio": true, "Metasploit Pro": true, "Shopify": true,
}

// analyzeResponse extracts header, cookie and body evidence from one response.
func (a *analysis) analyzeResponse(resp *probe.Response, source string) {
	if resp == nil || resp.Err != "" {
		return
	}

	// Tag every signal from this response with its HTTP status code.
	addEv := func(ev Evidence) {
		if ev.Status == 0 {
			ev.Status = resp.Status
		}
		a.addEv(ev)
	}

	// Header-based signatures.
	for _, sig := range headerSigs {
		for _, val := range resp.HeaderValues(sig.header) {
			var matched bool
			how, pattern := "header present", sig.contains
			switch {
			case sig.re != nil:
				matched = sig.re.MatchString(strings.TrimSpace(val))
				how, pattern = "header regular expression", sig.re.String()
			case sig.contains == "":
				matched = true
			default:
				matched = containsFold(val, sig.contains)
				how = "header substring match"
			}
			if !matched {
				continue
			}
			signal := "header." + strings.ToLower(sig.header)
			if containsFold(val, "passenger") {
				// Server and X-Powered-By both advertise Passenger; count once.
				signal = "stack.passenger"
			}
			addEv(Evidence{
				Signal: signal,
				Source: source, Weight: rubyWeight(sig.weight, sig.rubyImplied, sig.variant), Detail: sig.detail, Data: val,
				Where: "response header '" + sig.header + "'", How: how,
				Pattern: pattern, Snippet: sig.header + ": " + val, Probe: source,
			})
			a.addFw(sig.framework)
			a.setVariant(sig.variant)
			break
		}
	}
	a.headerHeuristics(resp, source, addEv)

	// Sinatra's production not-found reply: the router falls through
	// (X-Cascade: pass) and the body is exactly "<h1>Not Found</h1>".
	if resp.Status == 404 && strings.EqualFold(resp.HeaderGet("X-Cascade"), "pass") &&
		strings.TrimSpace(resp.BodyString()) == "<h1>Not Found</h1>" {
		addEv(Evidence{
			Signal: "behavior.sinatra-not-found", Source: source, Weight: 45,
			Detail:  "Sinatra default 404 (X-Cascade: pass with the bare \"<h1>Not Found</h1>\" body)",
			Snippet: "<h1>Not Found</h1>", Probe: source,
		})
		a.addFw("Sinatra")
	}

	// Server header modules (mod_ssl, OpenSSL/..., Phusion_Passenger/...).
	for _, val := range resp.HeaderValues("Server") {
		for _, tok := range strings.Fields(val) {
			if strings.HasPrefix(tok, "mod_") || strings.Contains(tok, "/") {
				tok = strings.Trim(tok, "()")
				if tok != "" {
					a.addMod(tok)
				}
			}
		}
	}

	// Cookie-based signatures.
	for _, c := range resp.Cookies {
		for _, sig := range cookieSigs {
			if !cookieMatch(c.Name, sig) {
				continue
			}
			how := "cookie-name match"
			switch sig.kind {
			case matchPrefix:
				how = "cookie-name prefix match"
			case matchSuffix:
				how = "cookie-name suffix match"
			}
			signal := "cookie." + strings.ToLower(strings.Trim(sig.name, "_-"))
			if sig.kind == matchSuffix {
				signal = "cookie.rails-session-name"
			}
			addEv(Evidence{
				Signal: signal,
				Source: source, Weight: sig.weight, Detail: sig.detail, Data: c.Name,
				Where: "Set-Cookie header", How: how, Pattern: sig.name,
				Snippet: "Set-Cookie: " + c.Name + "=…", Probe: source,
			})
			a.addFw(sig.framework)
			if strings.Contains(sig.detail, "Devise") {
				a.addGem("devise")
			}
			break // the first (most specific) matching signature wins
		}
		a.cookieValueHeuristics(c.Name, c.Value, source, addEv)
	}

	// Body-based signatures.
	body := resp.BodyString()
	if body == "" {
		return
	}
	// Secret-bearing files (keys, credentials, logs) are still matched, but
	// their content is never quoted into evidence.
	withhold := resp.Status == 200 && sensitivePath(source)
	for _, sig := range bodySigs {
		if loc := sig.re.FindStringIndex(body); loc != nil {
			snippet, line := bodyContext(body, loc[0], loc[1])
			if withhold {
				addEv(Evidence{
					Signal: sig.id, Source: source, Weight: rubyWeight(sig.weight, sig.rubyImplied, ""),
					Detail: sig.detail, Where: "response body", How: "regular expression",
					Pattern: sig.re.String(), Snippet: "(content withheld)", Line: line, Probe: source,
				})
				a.addFw(sig.framework)
				continue
			}
			addEv(Evidence{
				Signal: sig.id, Source: source, Weight: rubyWeight(sig.weight, sig.rubyImplied, ""),
				Detail: sig.detail, Data: collapseWS(body[loc[0]:loc[1]]),
				Where: "response body", How: "regular expression",
				Pattern: sig.re.String(), Snippet: snippet, Line: line, Probe: source,
			})
			a.addFw(sig.framework)
		}
	}
	for _, gt := range gemTokens {
		if strings.Contains(body, gt.token) {
			a.addGem(gt.gem)
		}
	}
	a.bodyVersions(body, source)

	if m := rePoweredBy.FindStringSubmatch(body); m != nil {
		a.addFw(canonicalApp(m[1]))
	}
	if m := reGenerator.FindStringSubmatch(body); m != nil {
		gen := m[1]
		fw := frameworkFromGenerator(gen)
		w := 0
		if fw != "" {
			w = 20
		}
		idx := strings.Index(body, m[0])
		_, line := bodyContext(body, idx, idx+len(m[0]))
		addEv(Evidence{
			Signal: "body.generator", Source: source, Weight: w,
			Detail: "HTML generator meta tag", Data: gen,
			Where: "response body", How: "regular expression", Pattern: reGenerator.String(),
			Snippet: collapseWS(m[0]), Line: line, Probe: source,
		})
		a.addFw(fw)
		if dm := reDiscourseGen.FindStringSubmatch(gen); dm != nil {
			a.setComp("Discourse", dm[1], source)
		}
	}
}

// headerHeuristics covers header evidence that needs more than a single
// substring: banner version extraction and multi-header Rails defaults.
func (a *analysis) headerHeuristics(resp *probe.Response, source string, addEv func(Evidence)) {
	for _, h := range []string{"Server", "X-Powered-By"} {
		for _, val := range resp.HeaderValues(h) {
			if m := reWEBrick.FindStringSubmatch(val); m != nil {
				a.setComp("WEBrick", m[1], h+" header")
				a.setVersion(m[2], h+" header (WEBrick banner)", rankRunning)
				a.setVariant("Ruby")
			} else if m := reRubyBanner.FindStringSubmatch(val); m != nil {
				a.setVersion(m[1], h+" header", rankRunning)
				a.setVariant("Ruby")
			}
			if m := reJRubyBanner.FindStringSubmatch(val); m != nil {
				a.setVariant("JRuby")
				a.setComp("JRuby", m[1], h+" header")
			}
			if m := rePassenger.FindStringSubmatch(val); m != nil {
				a.addMod("Phusion Passenger")
				a.setComp("Phusion Passenger", m[1], h+" header")
			}
			v := strings.TrimSpace(val)
			for _, s := range []struct {
				re   *regexp.Regexp
				name string
			}{{reThin, "Thin"}, {rePumaSrv, "Puma"}, {reUnicorn, "Unicorn"}, {reFalcon, "Falcon"}, {reMongrel, "Mongrel"}} {
				if m := s.re.FindStringSubmatch(v); m != nil && h == "Server" {
					a.setComp(s.name, m[1], "Server header")
				}
			}
		}
	}
	if v := resp.HeaderGet("X-GitHub-Enterprise-Version"); v != "" {
		a.setComp("GitHub Enterprise Server", v, "X-GitHub-Enterprise-Version header")
	}
	if v := resp.HeaderGet("Foreman_version"); v != "" {
		a.setComp("Foreman", v, "Foreman_version header")
	}

	// Rack::ETag weak validator together with Rails' default Cache-Control.
	if reRackETag.MatchString(strings.TrimSpace(resp.HeaderGet("ETag"))) &&
		strings.EqualFold(strings.TrimSpace(resp.HeaderGet("Cache-Control")), "max-age=0, private, must-revalidate") {
		addEv(Evidence{
			Signal: "header.rails-cache-defaults", Source: source, Weight: 35,
			Detail: "Rack::ETag weak ETag with Rails' default Cache-Control (max-age=0, private, must-revalidate)",
			Where:  "response headers 'ETag' + 'Cache-Control'", How: "header combination",
			Snippet: "ETag: " + resp.HeaderGet("ETag") + " / Cache-Control: " + resp.HeaderGet("Cache-Control"), Probe: source,
		})
		a.addFw("Rails")
	}

	// Rails' default security header set. Express' helmet emits the same two
	// distinctive headers but always adds X-DNS-Prefetch-Control, which Rails
	// never sends — so its presence disqualifies the match.
	// Rails 7.1 dropped X-Download-Options, so either it or Rails' default
	// Referrer-Policy must accompany X-Permitted-Cross-Domain-Policies.
	download := strings.EqualFold(resp.HeaderGet("X-Download-Options"), "noopen")
	referrer := strings.EqualFold(resp.HeaderGet("Referrer-Policy"), "strict-origin-when-cross-origin")
	if strings.EqualFold(resp.HeaderGet("X-Permitted-Cross-Domain-Policies"), "none") &&
		(download || referrer) && resp.HeaderGet("X-DNS-Prefetch-Control") == "" {
		detail := "Rails default security headers (X-Permitted-Cross-Domain-Policies: none with X-Download-Options / Referrer-Policy defaults)"
		xss := strings.TrimSpace(resp.HeaderGet("X-XSS-Protection"))
		switch {
		case strings.HasPrefix(xss, "1"):
			detail += "; X-XSS-Protection: 1 suggests Rails 6.1 or earlier"
		case xss == "0" && download:
			detail += "; header set matches Rails 7.0"
		case xss == "0":
			detail += "; header set matches Rails 7.1 or later"
		}
		addEv(Evidence{
			Signal: "header.rails-security-defaults", Source: source, Weight: 25, Detail: detail,
			Where: "response headers", How: "header combination",
			Snippet: "X-Permitted-Cross-Domain-Policies: none / Referrer-Policy: " + resp.HeaderGet("Referrer-Policy"), Probe: source,
		})
		a.addFw("Rails")
	}
}

// cookieValueHeuristics recognises the wire formats of Rails / Rack session
// cookies. Only the format is recorded — never the cookie value.
func (a *analysis) cookieValueHeuristics(name, value, source string, addEv func(Evidence)) {
	if value == "" {
		return
	}
	if dec, err := url.QueryUnescape(value); err == nil {
		value = dec
	}
	ev := Evidence{Source: source, Where: "Set-Cookie header", How: "cookie-value format match", Probe: source, Data: name}
	switch {
	case reCookieMarshal.MatchString(value):
		ev.Signal, ev.Weight = "cookie.ruby-marshal", 80
		ev.Detail = "Session cookie carries a Ruby Marshal payload with an HMAC (Rack::Session::Cookie / Rails ≤ 4.0 format). If the signing secret leaks, a forged cookie is deserialised — code execution"
		ev.Pattern = reCookieMarshal.String()
		ev.Snippet = "Set-Cookie: " + name + "=BAh…--<hmac>"
	case reCookieEncrypted.MatchString(value):
		ev.Signal, ev.Weight = "cookie.rails-encrypted", 60
		ev.Detail = "Rails AES-256-GCM encrypted cookie (data--iv--auth_tag, Rails 5.2 or later)"
		ev.Pattern = reCookieEncrypted.String()
		ev.Snippet = "Set-Cookie: " + name + "=<data>--<iv>--<tag>"
		a.addFw("Rails")
	case reCookieSigned.MatchString(value):
		ev.Signal, ev.Weight = "cookie.rails-signed", 55
		ev.Detail = "payload--HMAC signed cookie (Rails MessageVerifier / Rack::Session::Cookie format)"
		ev.Pattern = reCookieSigned.String()
		ev.Snippet = "Set-Cookie: " + name + "=<payload>--<hmac>"
	default:
		return
	}
	addEv(ev)
}

// bodyVersions extracts Ruby, framework and gem versions leaked in a body.
func (a *analysis) bodyVersions(body, source string) {
	if m := reWEBrick.FindStringSubmatch(body); m != nil {
		a.setComp("WEBrick", m[1], source+" (WEBrick signature)")
		a.setVersion(m[2], "WEBrick error-page signature", rankRunning)
		a.setVariant("Ruby")
	}
	if m := reRubyVersionString.FindStringSubmatch(body); m != nil {
		v := m[1]
		if m[2] != "" {
			v += "p" + m[2]
		}
		a.setVersion(v, "ruby version string in response body", rankRunning)
	} else if strings.Contains(body, "Rails version") {
		if m := reWelcomeRuby.FindStringSubmatch(body); m != nil {
			a.setVersion(strings.Replace(m[1], "-p", "p", 1), "Rails welcome/info page", rankRunning)
		}
	}
	if strings.Contains(body, "Ruby version") {
		if m := reWelcomeRails.FindStringSubmatch(body); m != nil {
			a.setComp("Rails", m[1], source)
		}
	}
	if strings.Contains(strings.ToLower(body), "jruby") && reJRubyBanner.MatchString(body) {
		a.setVariant("JRuby")
	}
	if m := reRubyInstallPath.FindStringSubmatch(body); m != nil {
		a.setVersion(strings.Replace(m[1], "-p", "p", 1), "Ruby install path in response body", rankDeclared)
	}
	if m := reRubyABIPath.FindStringSubmatch(body); m != nil {
		a.setBranch(m[1])
		a.addEv(Evidence{
			Signal: "body.ruby-abi-path", Source: source, Weight: 0,
			Detail: "RubyGems ABI directory reveals the Ruby branch " + m[1] + ".x (patch level unknown)", Data: m[0],
		})
	}
	for _, m := range reGemPath.FindAllStringSubmatch(body, 400) {
		name, ver := m[1], m[2]
		switch {
		case railsGems[name]:
			a.setComp("Rails", ver, source+" (gem path)")
		case promotedGems[name] != "":
			a.setComp(promotedGems[name], ver, source+" (gem path)")
		}
		if len(a.observed) < maxObservedGems || a.observed[name] != "" {
			a.observed[name] = ver
		}
		a.addGem(name)
	}
}

// detectAppEndpoints reads application-specific endpoints that disclose a
// product and its version. It runs for any status, since some are informative
// even when they refuse the request.
func (a *analysis) detectAppEndpoints(u string, resp *probe.Response, body string) {
	lu := strings.ToLower(pathOf(u))
	st := resp.Status
	switch {
	case strings.HasPrefix(lu, "/api/v1/instance") || strings.HasPrefix(lu, "/api/v2/instance"):
		m := reJSONVersion.FindStringSubmatch(body)
		if st != 200 || m == nil {
			return
		}
		if containsFold(m[1], "compatible;") || containsFold(body, "pleroma") || containsFold(body, "akkoma") || containsFold(body, "misskey") {
			// Pleroma/Akkoma (Elixir), Misskey (Node.js) and friends emulate the
			// Mastodon API; they are not Ruby.
			a.addEv(Evidence{Signal: "diag.mastodon-compatible-api", Source: u, Weight: 0, Status: st,
				Detail: "Mastodon-compatible API served by a non-Mastodon implementation (not evidence of Ruby)", Data: m[1]})
			return
		}
		a.addFw("Mastodon")
		a.addEv(Evidence{Signal: "diag.mastodon-instance", Source: u, Weight: 55, Status: st,
			Detail: "Mastodon instance API discloses the server version", Data: m[1]})
		if v := reLeadingVersion.FindString(m[1]); v != "" {
			a.setComp("Mastodon", v, u)
		}
	case lu == "/api":
		if st == 200 && strings.Contains(body, `"queue_services"`) {
			a.addFw("Chatwoot")
			a.addEv(Evidence{Signal: "diag.chatwoot-api", Source: u, Weight: 55, Status: st, Detail: "Chatwoot API status endpoint discloses the version"})
			if m := reJSONVersion.FindStringSubmatch(body); m != nil {
				a.setComp("Chatwoot", reLeadingVersion.FindString(m[1]), u)
			}
		}
	case lu == "/api/v3/meta":
		if m := reGHESVersion.FindStringSubmatch(body); m != nil {
			a.addFw("GitHub Enterprise Server")
			a.setComp("GitHub Enterprise Server", m[1], u)
			a.addEv(Evidence{Signal: "diag.ghes-meta", Source: u, Weight: 55, Status: st, Detail: "GitHub Enterprise Server meta API discloses the installed version", Data: m[1]})
		}
	case lu == "/api/v4/version":
		if (st == 401 || st == 403) && strings.Contains(body, `"message"`) && containsFold(body, "401 Unauthorized") {
			a.addFw("GitLab")
			a.addEv(Evidence{Signal: "diag.gitlab-api", Source: u, Weight: 45, Status: st, Detail: "GitLab REST API answers at /api/v4 (version requires authentication)"})
		} else if st == 200 {
			if m := reJSONVersion.FindStringSubmatch(body); m != nil && strings.Contains(body, `"revision"`) {
				a.addFw("GitLab")
				a.setComp("GitLab", reLeadingVersion.FindString(m[1]), u)
			}
		}
	case lu == "/help":
		if m := reGitLabHelp.FindStringSubmatch(body); m != nil {
			a.addFw("GitLab")
			a.setComp("GitLab", m[1], u)
		}
	case lu == "/api/status":
		if st == 200 && strings.Contains(body, `"api_version"`) {
			if m := reJSONVersion.FindStringSubmatch(body); m != nil {
				a.addFw("Foreman")
				a.setComp("Foreman", reLeadingVersion.FindString(m[1]), u)
			}
		}
	}
}

// detectExposures recognises exposed diagnostics, project files and secrets on
// a 200 response. Secret values are never copied into evidence.
func (a *analysis) detectExposures(u string, resp *probe.Response, body string) {
	lu := strings.ToLower(pathOf(u))
	st := resp.Status
	html := strings.Contains(body, "<html") || strings.Contains(body, "<!DOCTYPE") || strings.Contains(body, "<!doctype")
	ev := func(signal string, weight int, detail, data string) {
		e := Evidence{Signal: signal, Source: u, Weight: weight, Detail: detail, Status: st, Data: data}
		if data == "" {
			// Keep secret-bearing bodies out of the record entirely.
			e.Snippet = "(content withheld)"
		}
		a.addEv(e)
	}

	switch {
	case strings.HasSuffix(lu, "/rails/info/routes"):
		if strings.Contains(body, "route_table") || (strings.Contains(body, "Controller#Action") && strings.Contains(body, "Path")) {
			a.addFw("Rails")
			a.setEnv("development")
			ev("diag.rails-routes", 85, "/rails/info/routes is publicly exposed (development-mode route listing)", "route table")
		}
	case lu == "/up":
		if len(body) < 400 && strings.Contains(body, "background-color: green") {
			a.addFw("Rails")
			ev("diag.rails-health", 55, "Rails health-check endpoint /up (Rails::HealthController — Rails 7.1 or later)", "background-color: green")
		}
	case strings.HasSuffix(lu, "/rails/mailers"):
		if strings.Contains(body, "Mailer Previews") {
			a.addFw("Rails")
			a.setEnv("development")
			ev("diag.rails-mailers", 75, "Action Mailer previews are publicly exposed (development mode)", "Mailer Previews")
		}
	case strings.Contains(lu, "/rails/conductor/"):
		if strings.Contains(body, "Rails Conductor") || strings.Contains(body, "inbound_emails") {
			a.addFw("Rails")
			a.setEnv("development")
			ev("diag.rails-conductor", 80, "Rails Conductor (Action Mailbox development UI) is publicly exposed", "Rails Conductor")
		}
	case strings.HasSuffix(lu, "/.ruby-version"):
		t := strings.TrimSpace(body)
		if len(t) > 40 || html {
			return
		}
		if m := reRubyVersionFl.FindStringSubmatch(t); m != nil {
			a.setVersion(strings.Replace(m[1], "-p", "p", 1), "/.ruby-version file", rankDeclared)
			ev("diag.ruby-version-file", 60, ".ruby-version is publicly readable (declares the project's Ruby version)", t)
		} else if strings.HasPrefix(t, "jruby-") || strings.HasPrefix(t, "truffleruby-") {
			if strings.HasPrefix(t, "jruby-") {
				a.setVariant("JRuby")
			} else {
				a.setVariant("TruffleRuby")
			}
			ev("diag.ruby-version-file", 60, ".ruby-version is publicly readable (alternative Ruby implementation)", t)
		}
	case strings.HasSuffix(lu, "/.tool-versions"):
		if m := reToolVersions.FindStringSubmatch(body); m != nil && !html {
			a.setVersion(strings.Replace(m[1], "-p", "p", 1), "/.tool-versions file", rankDeclared)
			ev("diag.tool-versions", 55, ".tool-versions is publicly readable (asdf/mise Ruby version)", "ruby "+m[1])
		}
	case strings.HasSuffix(lu, "/config.ru"):
		if !html && reConfigRu.MatchString(body) && (strings.Contains(body, "run ") || strings.Contains(body, "require")) {
			if strings.Contains(body, "Rails.application") || strings.Contains(body, "config/environment") {
				a.addFw("Rails")
			}
			if strings.Contains(body, "Sinatra") {
				a.addFw("Sinatra")
			}
			ev("diag.config-ru", 70, "config.ru (Rack application entry point) is served as a file", "config.ru")
		}
	case strings.HasSuffix(lu, "/rakefile"):
		if !html && reRakefile.MatchString(body) {
			ev("diag.rakefile", 65, "Rakefile is publicly readable (Ruby project)", "Rakefile")
		}
	case strings.HasSuffix(lu, "/config/database.yml"):
		if m := reDatabaseYml.FindStringSubmatch(body); m != nil && !html {
			a.addFw("Rails")
			ev("diag.database-yml", 60, "config/database.yml is publicly readable (database credentials may be exposed)", "adapter: "+m[1])
		}
	case strings.HasSuffix(lu, "/config/secrets.yml"):
		if !html && strings.Contains(body, "secret_key_base") {
			a.addFw("Rails")
			ev("diag.secrets-yml", 65, "config/secrets.yml is publicly readable — secret_key_base exposed (session forgery, possible code execution)", "")
		}
	case strings.HasSuffix(lu, "/config/master.key"):
		if reMasterKey.MatchString(strings.TrimSpace(body)) {
			a.addFw("Rails")
			ev("diag.master-key", 65, "config/master.key is publicly readable — decrypts credentials.yml.enc (secret_key_base and other secrets)", "")
		}
	case strings.HasSuffix(lu, "/.env"):
		if html {
			return
		}
		rubyish := false
		for _, k := range []string{"SECRET_KEY_BASE=", "RAILS_ENV=", "RACK_ENV=", "RAILS_MASTER_KEY=", "BUNDLE_", "RAILS_", "PUMA_", "SIDEKIQ_"} {
			if strings.Contains(body, k) {
				rubyish = true
				break
			}
		}
		switch {
		case rubyish:
			ev("diag.dotenv", 55, "Exposed .env file with Ruby/Rails settings (secrets may be readable)", "")
		case strings.Contains(body, "DATABASE_URL=") || strings.Contains(body, "DB_PASSWORD=") || strings.Contains(body, "SECRET"):
			ev("diag.dotenv-generic", 0, "Exposed .env file (secrets may be readable; not Ruby-specific)", "")
		}
	case strings.HasSuffix(lu, ".log"):
		if reRailsLog.MatchString(body) {
			a.addFw("Rails")
			if strings.Contains(lu, "development") {
				a.setEnv("development")
			}
			ev("diag.rails-log", 75, "Rails log file is publicly readable (request parameters, SQL and possibly credentials)", "")
		}
	case strings.HasSuffix(lu, "/packs/manifest.json"):
		if strings.Contains(body, `"entrypoints"`) || strings.Contains(body, `"/packs/`) {
			a.addFw("Rails")
			a.addGem("webpacker/shakapacker")
			ev("diag.webpacker-manifest", 45, "Webpacker/Shakapacker manifest is served (Rails asset bundling)", "manifest.json")
		}
	case strings.HasSuffix(lu, "/sidekiq"):
		if m := reSidekiqVersion.FindStringSubmatch(body); m != nil {
			a.setComp("Sidekiq", m[1], u)
		}
	}
}

// inferEnv reports the Rails/Rack environment when it was observed, or
// "development" when development-only pages were seen.
func (a *analysis) inferEnv() string {
	if a.env != "" {
		return a.env
	}
	for _, s := range []string{"body.rails-exception-page", "body.rails-web-console", "body.better-errors", "diag.rails-info"} {
		if a.seen[s] {
			return "development"
		}
	}
	return ""
}

// inferAppServer makes a best-effort guess at the Ruby application server from
// the collected evidence, falling back to the gem inventory.
func (a *analysis) inferAppServer(inv *BundlerInventory) string {
	withVer := func(name string) string {
		if c, ok := a.comp[name]; ok {
			return name + " " + c.ver
		}
		return name
	}
	for _, name := range []string{"WEBrick", "Puma", "Thin", "Unicorn", "Falcon", "Mongrel"} {
		if _, ok := a.comp[name]; ok && a.comp[name].src != "Gemfile.lock" {
			return withVer(name)
		}
	}
	switch {
	case a.seen["body.webrick-error"]:
		return withVer("WEBrick")
	case a.seen["body.puma-error"]:
		return withVer("Puma")
	case a.seen["stack.passenger"] || a.seen["body.passenger-error"] || a.modSet["Phusion Passenger"]:
		return withVer("Phusion Passenger")
	case a.seen["body.unicorn-error"]:
		return "Unicorn"
	}
	for _, ev := range a.d.Evidence {
		if ev.Signal != "header.server" {
			continue
		}
		l := strings.ToLower(ev.Data)
		for _, s := range []string{"WEBrick", "Puma", "Thin", "Unicorn", "Falcon", "Mongrel", "Rainbows", "Pitchfork", "Goliath", "TorqueBox", "Trinidad"} {
			if strings.Contains(l, strings.ToLower(s)) {
				return withVer(s)
			}
		}
	}
	if inv != nil {
		for _, gem := range []string{"puma", "passenger", "unicorn", "falcon", "thin", "pitchfork"} {
			if v := inv.gemVersion(gem); v != "" {
				return promotedOr(gem) + " " + v + " (from Gemfile.lock)"
			}
		}
	}
	return ""
}

func promotedOr(gem string) string {
	if l := promotedGems[gem]; l != "" {
		return l
	}
	return gem
}

func cookieMatch(name string, sig cookieSig) bool {
	n, s := strings.ToLower(name), strings.ToLower(sig.name)
	switch sig.kind {
	case matchPrefix:
		return strings.HasPrefix(n, s)
	case matchSuffix:
		// The Rails convention is `_<app>_session`: leading underscore required.
		return strings.HasPrefix(n, "_") && strings.HasSuffix(n, s) && len(n) > len(s)+1
	default:
		return n == s
	}
}

func frameworkFromGenerator(gen string) string {
	g := strings.ToLower(gen)
	switch {
	case strings.Contains(g, "discourse"):
		return "Discourse"
	case strings.Contains(g, "diaspora"):
		return "diaspora*"
	case strings.Contains(g, "decidim"):
		return "Decidim"
	case strings.Contains(g, "publify"):
		return "Publify"
	case strings.Contains(g, "refinery"):
		return "Refinery CMS"
	case strings.Contains(g, "alchemy"):
		return "Alchemy CMS"
	case strings.Contains(g, "camaleon"):
		return "Camaleon CMS"
	case strings.Contains(g, "redmine"):
		return "Redmine"
	default:
		return ""
	}
}

// canonicalApp normalises a "Powered by" app name to a stable label.
func canonicalApp(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ruby on rails":
		return "Rails"
	case "spree commerce":
		return "Spree"
	case "diaspora", "diaspora*":
		return "diaspora*"
	case "phusion passenger":
		return "" // an app server, reported under modules
	default:
		return strings.TrimSpace(name)
	}
}

// addonNames are technologies reported under Addons rather than Frameworks:
// Ruby tools, dev aids and dashboards.
var addonNames = map[string]bool{
	"Rails Web Console":    true,
	"Better Errors":        true,
	"Sidekiq Web":          true,
	"ActiveAdmin":          true,
	"RailsAdmin":           true,
	"Administrate":         true,
	"rack-mini-profiler":   true,
	"Letter Opener":        true,
	"Flipper UI":           true,
	"PgHero":               true,
	"Resque Web":           true,
	"GoodJob Dashboard":    true,
	"Mission Control Jobs": true,
}

// partitionAddons moves addon technologies out of frameworks into addons.
func partitionAddons(frameworks []string) (fw, addons []string) {
	for _, f := range frameworks {
		if addonNames[f] {
			addons = append(addons, f)
		} else {
			fw = append(fw, f)
		}
	}
	return fw, addons
}

// ctrlSig is a fingerprint of the soft-404 / catch-all baseline response (the
// reply to a guaranteed-nonexistent URL), used to tell a genuinely distinct
// page apart from a server that returns the same thing for every path.
type ctrlSig struct {
	present bool
	status  int
	bodyLen int
	ctype   string
}

func controlSignature(r *probe.Response) ctrlSig {
	if r == nil || r.Err != "" || r.Status == 0 {
		return ctrlSig{}
	}
	return ctrlSig{
		present: true,
		status:  r.Status,
		bodyLen: len(r.Body),
		ctype:   mediaType(r.HeaderGet("Content-Type")),
	}
}

// matches reports whether a probe response is indistinguishable from the
// baseline: same status, same media type, and a body within 15% of the
// baseline's size. When no baseline was captured it always returns false, so
// detection falls back to its ungated behaviour.
func (c ctrlSig) matches(r *probe.Response) bool {
	if !c.present || r == nil || r.Err != "" || r.Status == 0 {
		return false
	}
	if r.Status != c.status {
		return false
	}
	if ct := mediaType(r.HeaderGet("Content-Type")); c.ctype != "" && ct != "" && ct != c.ctype {
		return false
	}
	a, b := len(r.Body), c.bodyLen
	hi, lo := a, b
	if hi < lo {
		hi, lo = lo, hi
	}
	if hi == 0 {
		return true // both empty with the same status
	}
	return float64(hi-lo)/float64(hi) <= 0.15
}

// mediaType returns the lowercased type/subtype of a Content-Type header,
// dropping any parameters (e.g. "; charset=utf-8").
func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// pathOf returns the path component of a URL (without query), or the input
// unchanged when it does not parse.
func pathOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// sensitivePath reports probe URLs whose bodies may hold secrets.
func sensitivePath(raw string) bool {
	p := strings.ToLower(pathOf(raw))
	for _, suffix := range []string{"/.env", "/master.key", "/secrets.yml", "/database.yml", "/credentials.yml.enc", ".log", ".key", ".pem"} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

func hasRubyExtension(u string) bool {
	u = pathOf(u)
	for _, ext := range []string{".rb", ".erb", ".rhtml", ".rbx", ".rjs"} {
		if strings.HasSuffix(u, ext) {
			return true
		}
	}
	return false
}

// bodyContext returns a collapsed context window around a body match and the
// 1-based line number where the match begins.
func bodyContext(body string, start, end int) (string, int) {
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	line := 1 + strings.Count(body[:start], "\n")
	lo := start - 60
	if lo < 0 {
		lo = 0
	}
	hi := end + 60
	if hi > len(body) {
		hi = len(body)
	}
	seg := collapseWS(strings.ToValidUTF8(body[lo:hi], ""))
	if len(seg) > 220 {
		seg = seg[:220] + "…"
	}
	return seg, line
}

func collapseWS(s string) string { return strings.Join(strings.Fields(s), " ") }

// provenanceDefaults supplies a baseline where/how for a signal by prefix.
func provenanceDefaults(signal string) (where, how string) {
	switch {
	case strings.HasPrefix(signal, "header."), strings.HasPrefix(signal, "stack."):
		return "response header", "header match"
	case strings.HasPrefix(signal, "cookie."):
		return "Set-Cookie header", "cookie-name match"
	case strings.HasPrefix(signal, "diag."):
		return "deep-probe response", "exposed diagnostic/project file"
	case strings.HasPrefix(signal, "behavior."):
		return "server behaviour", "behavioural probe"
	case strings.HasPrefix(signal, "component.version."):
		return "response header / body / project file", "component version extraction"
	case strings.HasPrefix(signal, "url."):
		return "request URL", "URL inspection"
	case strings.HasPrefix(signal, "favicon."):
		return "site favicon", "mmh3 favicon-hash catalogue match"
	case strings.HasPrefix(signal, "body."):
		return "response body", "content match"
	default:
		return "response", "heuristic"
	}
}

// rubyWeight gates a signature's confidence contribution: a signature that
// does not imply a Ruby runtime (e.g. a statically generated Jekyll site)
// still records its framework and evidence, but adds 0 to the Ruby score.
func rubyWeight(weight int, rubyImplied bool, variant string) int {
	if rubyImplied || variant != "" {
		return weight
	}
	return 0
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func sortEvidence(ev []Evidence) {
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].Weight != ev[j].Weight {
			return ev[i].Weight > ev[j].Weight
		}
		return ev[i].Signal < ev[j].Signal
	})
}

func sortVulns(vs []Vulnerability) {
	sort.SliceStable(vs, func(i, j int) bool {
		ri, rj := SeverityRank(vs[i].Severity), SeverityRank(vs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return vs[i].ID > vs[j].ID
	})
}
