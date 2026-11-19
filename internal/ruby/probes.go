package ruby

import "strings"

// Deep-mode probe definitions. The scanner fetches these and hands the
// responses back to Analyze. Keeping the catalogue here lets the detection
// logic and the scanner agree on what is collected. Every probe is a plain,
// read-only GET; none submit data or attempt exploitation.

// ParamTypeProbe is a behavioural probe for Rack's query parser. The query
// string declares the same parameter both as an array and as a hash, which
// Rack rejects ("expected Hash (got Array) for param"); Rails and Sinatra turn
// that into a 400 Bad Request. PHP, Node.js, Python, Java, Go and .NET stacks
// accept such a query without complaint, so a 400 here — when the plain
// request succeeded — is characteristic of Rack. The request is harmless: it
// carries no payload and only exercises ordinary parameter parsing.
const ParamTypeProbe = "/?qrubyscanner[]=1&qrubyscanner[k]=1"

// RequestIDProbeValue is sent as X-Request-Id on the parameter probe.
// ActionDispatch::RequestId echoes a client-supplied request id back after
// stripping everything except word characters, "-" and "@" — so a Rails
// application answers with exactly RequestIDProbeEcho. A server that echoes
// the value untouched, or not at all, is not showing that behaviour.
const (
	RequestIDProbeValue = "qruby.scan!1-@probe_x"
	RequestIDProbeEcho  = "qrubyscan1-@probe_x"
)

// UnknownMethodProbe is a syntactically valid but non-existent HTTP method.
// Puma answers methods it does not know with a bare "501 Not Implemented" and
// an empty body before the application is consulted; Rails itself (behind
// other servers) answers 405 via ActionController::UnknownHttpMethod. The
// request has no body and no side effects.
const UnknownMethodProbe = "QRUBYSCAN"

// GenericDeepProbePaths are generic Ruby diagnostic/project discovery probes,
// issued when a service plausibly runs Ruby.
func GenericDeepProbePaths() []string {
	return []string{
		// Rails development/diagnostic endpoints. /rails/info/properties leaks
		// the exact Ruby, Rails and Rack versions when reachable.
		"/rails/info/properties",
		"/rails/info/routes",
		// Rails >= 7.1 health check (Rails::HealthController).
		"/up",
		// Static error pages every generated Rails app ships in public/.
		"/404.html",
		"/422.html",
		"/500.html",
		// Sign-in pages: the front page of many deployments is static or
		// cached, while these are always rendered by the application (Devise's
		// default route, and the Rails 8 authentication generator's).
		"/users/sign_in",
		"/session/new",
		// Rails >= 7.2 generator defaults.
		"/406-unsupported-browser.html",
		"/icon.svg",
		"/robots.txt",
		// Project files that are sometimes left inside the document root. A
		// readable Gemfile.lock / .ruby-version discloses the Ruby version.
		"/Gemfile",
		"/Gemfile.lock",
		"/.ruby-version",
		"/.tool-versions",
		"/config.ru",
		"/Rakefile",
		// Exposed secrets / configuration (read-only GETs; values are never
		// stored in evidence).
		"/config/database.yml",
		"/config/secrets.yml",
		"/config/master.key",
		"/.env",
		"/log/development.log",
	}
}

// ProbeGroup is an application-specific set of probe paths gated by a trigger
// over the evidence seen so far, so an app's endpoints are only requested once
// something already hints at that app (adaptive discovery).
type ProbeGroup struct {
	Name    string
	Trigger func(*Detection) bool
	Paths   []string
}

// hasFramework reports whether a detection already names a framework (case-
// insensitive substring), used as a probe-group trigger.
func hasFramework(d *Detection, name string) bool {
	if d == nil {
		return false
	}
	name = strings.ToLower(name)
	for _, list := range [][]string{d.Frameworks, d.Addons} {
		for _, f := range list {
			if strings.Contains(strings.ToLower(f), name) {
				return true
			}
		}
	}
	return false
}

// ConditionalProbeGroups are framework-specific probe sets issued only after
// the base/core responses show evidence of that framework.
func ConditionalProbeGroups() []ProbeGroup {
	return []ProbeGroup{
		{Name: "rails", Trigger: func(d *Detection) bool { return hasFramework(d, "Rails") },
			Paths: []string{"/sidekiq", "/admin", "/letter_opener", "/flipper", "/pghero",
				"/rails/mailers", "/rails/conductor/action_mailbox/inbound_emails", "/packs/manifest.json"}},
		{Name: "gitlab", Trigger: func(d *Detection) bool { return hasFramework(d, "GitLab") },
			Paths: []string{"/users/sign_in", "/help", "/api/v4/version"}},
		{Name: "mastodon", Trigger: func(d *Detection) bool { return hasFramework(d, "Mastodon") },
			Paths: []string{"/api/v1/instance", "/api/v2/instance"}},
		{Name: "discourse", Trigger: func(d *Detection) bool { return hasFramework(d, "Discourse") },
			Paths: []string{"/srv/status", "/about.json"}},
		{Name: "chatwoot", Trigger: func(d *Detection) bool { return hasFramework(d, "Chatwoot") },
			Paths: []string{"/api"}},
		{Name: "github", Trigger: func(d *Detection) bool { return hasFramework(d, "GitHub") },
			Paths: []string{"/api/v3/meta"}},
		{Name: "foreman", Trigger: func(d *Detection) bool { return hasFramework(d, "Foreman") },
			Paths: []string{"/api/status"}},
	}
}

// DeepProbePaths is the full union of generic and all conditional probe paths
// (the non-adaptive set). Retained for callers that want everything.
func DeepProbePaths() []string {
	paths := append([]string{}, GenericDeepProbePaths()...)
	for _, g := range ConditionalProbeGroups() {
		paths = append(paths, g.Paths...)
	}
	return paths
}

// FaviconPath is fetched in deep mode for the favicon fingerprint.
const FaviconPath = "/favicon.ico"
