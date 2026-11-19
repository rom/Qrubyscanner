package ruby

import "regexp"

var (
	// reWEBrick matches the WEBrick banner, which embeds the running Ruby
	// version and release date: "WEBrick/1.8.1 (Ruby/3.2.2/2023-03-30)".
	reWEBrick = regexp.MustCompile(`(?i)WEBrick/(\d+\.\d+(?:\.\d+)?)\s*\(Ruby/(\d+\.\d+\.\d+)(?:/(\d{4}-\d{2}-\d{2}))?\)`)
	// reRubyBanner matches a bare "Ruby/3.2.2" product token in a banner.
	reRubyBanner = regexp.MustCompile(`(?i)\bRuby/(\d+\.\d+\.\d+(?:-?p\d+)?)`)
	// reJRubyBanner matches "JRuby/9.4.5.0" or "jruby 9.4.5.0".
	reJRubyBanner = regexp.MustCompile(`(?i)\bjruby[/ ](\d+\.\d+\.\d+(?:\.\d+)?)`)
	// rePassenger matches Phusion Passenger banners in Server / X-Powered-By:
	// "Phusion Passenger(R) 6.0.18", "Phusion Passenger 5.0.30",
	// "Phusion Passenger (mod_rails/mod_rack) 3.0.11".
	rePassenger = regexp.MustCompile(`(?i)Phusion[ _]Passenger(?:\(R\)|®)?(?: Enterprise)?(?: \(mod_rails/mod_rack\))?[ /]*v?(\d+\.\d+\.\d+)?`)
	reThin      = regexp.MustCompile(`(?i)^thin(?:[ /](\d+\.\d+\.\d+))?(?: codename|$)`)
	rePumaSrv   = regexp.MustCompile(`(?i)^puma(?:[ /](\d+\.\d+(?:\.\d+)?))?`)
	reMongrel   = regexp.MustCompile(`(?i)^mongrel(?:[ /](\d+\.\d+(?:\.\d+)?))?`)
	reFalcon    = regexp.MustCompile(`(?i)^falcon/(\d+\.\d+(?:\.\d+)?)`)
	reUnicorn   = regexp.MustCompile(`(?i)^unicorn(?:[ /](\d+\.\d+(?:\.\d+)?))?`)

	// reXRuntime is the exact shape Rack::Runtime emits: seconds with six
	// decimals ("0.012345").
	reXRuntime = regexp.MustCompile(`^\d+\.\d{6}$`)
	// reRackETag is the weak ETag Rack::ETag generates (MD5 / SHA-256 prefix).
	reRackETag = regexp.MustCompile(`^W/"[0-9a-f]{32}"$`)
	// rePreloadLink matches the Link preload header Rails emits for
	// fingerprinted pipeline assets.
	rePreloadLink = regexp.MustCompile(`(?i)</(?:assets|packs|vite)/[^>]+-[0-9a-f]{8,64}\.(?:css|js)>;\s*rel=preload`)

	reGenerator = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

	// Version leaks inside bodies.
	// reWelcomeRuby matches the Rails welcome page ("Ruby version: ruby 3.3.0
	// (2023-12-25 revision …) [x86_64-linux]").
	reWelcomeRuby  = regexp.MustCompile(`(?is)Ruby version:?\s*(?:</(?:strong|b|dt|th|td)>\s*(?:<(?:dd|td)[^>]*>)?)?\s*(?:ruby |jruby )?(\d+\.\d+\.\d+(?:-?p\d+)?)`)
	reWelcomeRails = regexp.MustCompile(`(?is)Rails version:?\s*(?:</(?:strong|b|dt|th|td)>\s*(?:<(?:dd|td)[^>]*>)?)?\s*(\d+\.\d+\.\d+(?:\.\w+)?)`)
	// reRubyVersionString matches `ruby -v` style output anywhere in a body.
	reRubyVersionString = regexp.MustCompile(`\bruby (\d+\.\d+\.\d+)(?:p(\d+))? \((?:\d{4}-\d{2}-\d{2})`)
	// reRubyInstallPath matches version-manager / source install paths that
	// carry the full interpreter version (rbenv, RVM, asdf, chruby, ruby-build).
	reRubyInstallPath = regexp.MustCompile(`/(?:\.rbenv/versions|\.rvm/(?:gems|rubies)|\.asdf/installs/ruby|\.rubies|opt/rubies|rubies|opt/ruby)/(?:ruby-)?(\d+\.\d+\.\d+(?:-?p\d+)?)\b`)
	// reRubyABIPath matches a RubyGems ABI directory, which names only the
	// branch ("…/ruby/3.2.0/gems/…" serves every 3.2.x).
	reRubyABIPath = regexp.MustCompile(`/(?:lib/ruby(?:/gems)?|bundle/ruby|gems/ruby|vendor/bundle/ruby|ruby/gems)/(\d+\.\d+)\.0\b`)
	// reGemPath matches an installed gem directory in a backtrace:
	// ".../gems/actionpack-7.0.4.3/lib/…".
	reGemPath = regexp.MustCompile(`/gems/([a-z][a-z0-9_]*(?:-[a-z][a-z0-9_]*)*)-(\d+\.\d+(?:\.\d+){0,2}(?:\.(?:rc|beta|pre)\d*)?)/`)

	// rePoweredBy matches "Powered by <Ruby app>" footers.
	rePoweredBy = regexp.MustCompile(`(?i)Powered by\s+(?:<a[^>]*>\s*)?(Redmine|Discourse|Mastodon|GitLab|OpenProject|Chatwoot|Spree(?: Commerce)?|Solidus|diaspora\*?|Huginn|Zammad|Foreman|Publify|Refinery CMS|Alchemy CMS|Camaleon CMS|Fat Free CRM|Errbit|Decidim|Forem|Sinatra|Ruby on Rails|Hanami|Padrino|Gollum|Phusion Passenger)`)
)

type matchKind int

const (
	matchExact matchKind = iota
	matchPrefix
	matchSuffix
)

// cookieSig maps a cookie name to the technology it implies.
type cookieSig struct {
	name      string
	kind      matchKind
	framework string // "" means it only implies Ruby generally
	weight    int
	detail    string
}

var cookieSigs = []cookieSig{
	{"rack.session", matchExact, "Rack", 75, "default Rack::Session cookie"},
	{"_session_id", matchExact, "", 45, "classic Rails / Rack session cookie name"},
	{"_gitlab_session", matchExact, "GitLab", 75, "GitLab session cookie"},
	{"known_sign_in", matchExact, "GitLab", 30, "GitLab known-sign-in cookie"},
	{"_forum_session", matchExact, "Discourse", 70, "Discourse session cookie"},
	{"_mastodon_session", matchExact, "Mastodon", 75, "Mastodon session cookie"},
	{"_redmine_session", matchExact, "Redmine", 75, "Redmine session cookie"},
	{"_open_project_session", matchExact, "OpenProject", 75, "OpenProject session cookie"},
	{"_chatwoot_session", matchExact, "Chatwoot", 70, "Chatwoot session cookie"},
	{"_diaspora_session", matchExact, "diaspora*", 70, "diaspora* session cookie"},
	{"_huginn_session", matchExact, "Huginn", 70, "Huginn session cookie"},
	{"_zammad_session", matchPrefix, "Zammad", 70, "Zammad session cookie"},
	{"_normandy_session", matchExact, "Canvas LMS", 70, "Canvas LMS session cookie"},
	{"canvas_session", matchExact, "Canvas LMS", 65, "Canvas LMS session cookie"},
	{"_decidim_session", matchExact, "Decidim", 70, "Decidim session cookie"},
	{"_dradis_session", matchExact, "Dradis", 70, "Dradis session cookie"},
	{"_errbit_session", matchExact, "Errbit", 70, "Errbit session cookie"},
	{"_spree_session", matchPrefix, "Spree", 55, "Spree Commerce session cookie"},
	{"_solidus_session", matchPrefix, "Solidus", 55, "Solidus session cookie"},
	{"guest_token", matchExact, "Spree", 30, "Spree/Solidus guest order token cookie"},
	{"_gh_sess", matchExact, "GitHub", 45, "GitHub (Rails) session cookie"},
	{"_gh_ent", matchPrefix, "GitHub Enterprise Server", 50, "GitHub Enterprise session cookie"},
	{"user_credentials", matchExact, "Rails", 50, "Authlogic persistence cookie"},
	{"__profilin", matchExact, "rack-mini-profiler", 60, "rack-mini-profiler control cookie"},
	{"vanity_id", matchExact, "", 45, "Vanity A/B testing cookie (vanity gem)"},
	{"_rucaptcha_session_id", matchExact, "Rails", 50, "rucaptcha gem cookie"},
	{"BEEFSESSION", matchExact, "BeEF", 80, "BeEF (Browser Exploitation Framework, Ruby) session cookie"},
	{"cw_d_session_info", matchExact, "Chatwoot", 55, "Chatwoot dashboard session cookie"},
	{"log_session_id", matchExact, "Canvas LMS", 50, "Canvas LMS log session cookie"},
	{"_legacy_normandy_session", matchExact, "Canvas LMS", 65, "Canvas LMS legacy session cookie"},
	{"experimentation_subject_id", matchExact, "GitLab", 35, "GitLab experimentation cookie"},
	{"_bypass_cache", matchExact, "Discourse", 30, "Discourse cache-bypass cookie"},
	{"_shopify_y", matchExact, "Shopify", 30, "Shopify storefront cookie (Rails-based SaaS)"},
	{"_shopify_s", matchExact, "Shopify", 30, "Shopify storefront cookie (Rails-based SaaS)"},
	{"secure_customer_sig", matchExact, "Shopify", 30, "Shopify storefront cookie (Rails-based SaaS)"},
	{"ahoy_visitor", matchExact, "", 40, "Ahoy analytics cookie (ahoy_matey gem)"},
	{"ahoy_visit", matchExact, "", 40, "Ahoy analytics cookie (ahoy_matey gem)"},
	{"remember_user_token", matchExact, "", 50, "Devise remember-me cookie"},
	{"remember_admin_user_token", matchExact, "", 50, "Devise remember-me cookie (admin scope)"},
	{"_passenger_route", matchExact, "", 25, "Phusion Passenger sticky-session cookie"},
	{"request_method", matchExact, "", 20, "legacy Rails request_method cookie"},
	{".session", matchSuffix, "Rack", 35, "Rack-style <app>.session cookie name"},
	// Generic Rails cookie-store convention: `_<application>_session`. Listed
	// last so a specific application match above wins the framework label.
	{"_session", matchSuffix, "Rails", 45, "Rails cookie-store session cookie (_<app>_session)"},
}

// headerSig matches a header value, optionally by substring or regex.
type headerSig struct {
	header      string
	contains    string // case-insensitive substring; "" means "present at all"
	framework   string
	rubyImplied bool
	variant     string
	weight      int
	detail      string
	re          *regexp.Regexp // optional; when set it replaces `contains`
}

var headerSigs = []headerSig{
	// --- Ruby application servers ---
	{header: "Server", contains: "webrick", rubyImplied: true, variant: "Ruby", weight: 85, detail: "WEBrick, Ruby's standard-library web server"},
	{header: "Server", re: reThin, rubyImplied: true, weight: 80, detail: "Thin (Ruby/EventMachine) web server"},
	{header: "Server", re: rePumaSrv, rubyImplied: true, weight: 80, detail: "Puma Ruby web server"},
	{header: "Server", re: reMongrel, rubyImplied: true, weight: 80, detail: "Mongrel Ruby web server"},
	{header: "Server", re: reUnicorn, rubyImplied: true, weight: 80, detail: "Unicorn Ruby web server"},
	{header: "Server", re: reFalcon, rubyImplied: true, weight: 75, detail: "Falcon (async Ruby) web server"},
	{header: "Server", contains: "mod_ruby", rubyImplied: true, variant: "Ruby", weight: 85, detail: "Apache mod_ruby (embedded Ruby interpreter)"},
	{header: "Server", contains: "iodine", rubyImplied: true, weight: 70, detail: "Iodine Ruby web server"},
	{header: "Server", re: regexp.MustCompile(`(?i)^agoo\b`), rubyImplied: true, weight: 70, detail: "Agoo Ruby web server"},
	{header: "Server", re: regexp.MustCompile(`(?i)^itsi\b`), rubyImplied: true, weight: 70, detail: "Itsi Ruby web server"},
	{header: "Server", contains: "ngx_mruby", rubyImplied: true, variant: "mruby", weight: 60, detail: "ngx_mruby (embedded mruby in nginx)"},
	{header: "Server", contains: "mod_mruby", rubyImplied: true, variant: "mruby", weight: 60, detail: "mod_mruby (embedded mruby in Apache)"},
	{header: "Server", contains: "rainbows", rubyImplied: true, weight: 75, detail: "Rainbows! Ruby web server"},
	{header: "Server", contains: "pitchfork", rubyImplied: true, weight: 75, detail: "Pitchfork Ruby web server"},
	{header: "Server", contains: "goliath", rubyImplied: true, weight: 70, detail: "Goliath Ruby web server"},
	{header: "Server", contains: "torquebox", rubyImplied: true, variant: "JRuby", weight: 75, detail: "TorqueBox (JRuby application server)"},
	{header: "Server", contains: "trinidad", rubyImplied: true, variant: "JRuby", weight: 70, detail: "Trinidad (JRuby on Tomcat)"},
	{header: "Server", contains: "jruby", rubyImplied: true, variant: "JRuby", weight: 80, detail: "Server banner advertises JRuby"},
	{header: "Server", contains: "mod_rails", rubyImplied: true, weight: 80, detail: "Phusion Passenger mod_rails"},
	{header: "Server", contains: "mod_rack", rubyImplied: true, weight: 80, detail: "Phusion Passenger mod_rack"},
	// Passenger also hosts Python and Node.js, so on its own it is only a
	// medium signal for Ruby.
	{header: "Server", contains: "phusion passenger", rubyImplied: true, weight: 35, detail: "Phusion Passenger application server (hosts Ruby, also Python/Node.js)"},
	{header: "Server", contains: "phusion_passenger", rubyImplied: true, weight: 35, detail: "Phusion Passenger application server (hosts Ruby, also Python/Node.js)"},
	{header: "X-Powered-By", contains: "phusion passenger", rubyImplied: true, weight: 35, detail: "X-Powered-By advertises Phusion Passenger (hosts Ruby, also Python/Node.js)"},
	{header: "X-Powered-By", contains: "mod_rails", rubyImplied: true, weight: 80, detail: "X-Powered-By advertises mod_rails"},
	{header: "X-Powered-By", contains: "mod_rack", rubyImplied: true, weight: 80, detail: "X-Powered-By advertises mod_rack"},
	{header: "X-Powered-By", contains: "jruby", rubyImplied: true, variant: "JRuby", weight: 80, detail: "X-Powered-By advertises JRuby"},
	{header: "X-Powered-By", re: regexp.MustCompile(`(?i)\bruby\b`), rubyImplied: true, variant: "Ruby", weight: 80, detail: "X-Powered-By advertises Ruby"},
	{header: "X-Powered-By", re: regexp.MustCompile(`(?i)\bsinatra\b`), framework: "Sinatra", rubyImplied: true, weight: 75, detail: "X-Powered-By advertises Sinatra"},
	{header: "X-Powered-By", re: regexp.MustCompile(`(?i)\b(?:ruby on )?rails\b`), framework: "Rails", rubyImplied: true, weight: 75, detail: "X-Powered-By advertises Rails"},
	{header: "X-Powered-By", contains: "hanami", framework: "Hanami", rubyImplied: true, weight: 70, detail: "X-Powered-By advertises Hanami"},
	{header: "X-Powered-By", contains: "padrino", framework: "Padrino", rubyImplied: true, weight: 70, detail: "X-Powered-By advertises Padrino"},

	// --- Rack / Rails middleware headers ---
	{header: "X-Runtime", re: reXRuntime, rubyImplied: true, weight: 35, detail: "Rack::Runtime timing header (seconds with six decimals)"},
	{header: "X-Rack-Cache", framework: "Rack", rubyImplied: true, weight: 65, detail: "Rack::Cache trace header"},
	{header: "X-Rack-CORS", framework: "Rack", rubyImplied: true, weight: 60, detail: "rack-cors debug header"},
	{header: "X-Content-Digest", rubyImplied: true, weight: 30, detail: "Rack::Cache entity digest header"},
	{header: "X-Cascade", contains: "pass", rubyImplied: true, weight: 45, detail: "X-Cascade: pass (Rack router fall-through, Rails/Sinatra)"},
	{header: "X-Rack-Mini-Profiler", rubyImplied: true, weight: 50, detail: "rack-mini-profiler header"},
	{header: "X-Sinatra", framework: "Sinatra", rubyImplied: true, weight: 70, detail: "Sinatra header"},
	{header: "Server-Timing", re: regexp.MustCompile(`\.(?:action_controller|active_record|action_view|active_support|action_dispatch)\b`), framework: "Rails", rubyImplied: true, weight: 75, detail: "Server-Timing lists ActiveSupport::Notifications events (ActionDispatch::ServerTiming, on by default in development)"},
	{header: "X-Web-Console-Session-Id", framework: "Rails Web Console", rubyImplied: true, weight: 85, detail: "web-console session header (interactive Ruby console is mounted)"},
	{header: "X-Web-Console-Mounted-Path", framework: "Rails Web Console", rubyImplied: true, weight: 85, detail: "web-console mount-path header"},
	{header: "X-Meta-Request-Version", framework: "Rails", rubyImplied: true, weight: 65, detail: "meta_request gem header (RailsPanel development tooling)"},
	{header: "Turbolinks-Location", framework: "Rails", rubyImplied: true, weight: 45, detail: "Turbolinks redirect header (turbolinks-rails)"},
	{header: "X-UA-Compatible", re: regexp.MustCompile(`(?i)^IE=Edge,chrome=1$`), rubyImplied: true, weight: 20, detail: "X-UA-Compatible: IE=Edge,chrome=1 response header (Rails 3 BestStandardsSupport default)"},
	{header: "WWW-Authenticate", contains: `realm="Doorkeeper"`, framework: "Rails", rubyImplied: true, weight: 70, detail: "Doorkeeper OAuth provider challenge (doorkeeper gem)"},
	{header: "WWW-Authenticate", contains: `realm="Application"`, framework: "Rails", rubyImplied: true, weight: 45, detail: "HTTP authentication with Rails' default realm \"Application\""},
	{header: "X-Bullet-Footer-Text", framework: "Rails", rubyImplied: true, weight: 70, detail: "Bullet N+1 detector header (development tooling)"},
	{header: "X-Bullet-Console-Text", framework: "Rails", rubyImplied: true, weight: 70, detail: "Bullet N+1 detector header (development tooling)"},
	{header: "X-Rack-Dev-Mark-Env", framework: "Rack", rubyImplied: true, weight: 65, detail: "rack-dev-mark environment header"},
	{header: "X-MiniProfiler-Ids", rubyImplied: true, weight: 15, detail: "MiniProfiler header (rack-mini-profiler; also exists for .NET)"},
	{header: "X-Frame-Options", re: regexp.MustCompile(`(?i)^ALLOWALL$`), rubyImplied: true, weight: 25, detail: "X-Frame-Options: ALLOWALL (a non-standard value that is a Rails idiom)"},
	{header: "X-Ruby-Version", rubyImplied: true, variant: "Ruby", weight: 80, detail: "X-Ruby-Version header"},
	{header: "X-Rails-Version", framework: "Rails", rubyImplied: true, weight: 80, detail: "X-Rails-Version header"},
	{header: "X-Rack-Version", framework: "Rack", rubyImplied: true, weight: 75, detail: "X-Rack-Version header"},
	{header: "Gitlab-Lb", framework: "GitLab", rubyImplied: true, weight: 45, detail: "GitLab load-balancer header"},
	{header: "Gitlab-Sv", framework: "GitLab", rubyImplied: true, weight: 45, detail: "GitLab serving-node header"},
	{header: "X-Discourse-Cached", framework: "Discourse", rubyImplied: true, weight: 60, detail: "Discourse anonymous-cache header"},
	{header: "X-Sorting-Hat-ShopId", framework: "Shopify", rubyImplied: true, weight: 30, detail: "Shopify storefront routing header (Rails-based SaaS)"},
	{header: "X-Sorting-Hat-PodId", framework: "Shopify", rubyImplied: true, weight: 30, detail: "Shopify storefront routing header (Rails-based SaaS)"},
	{header: "Powered-By", contains: "shopify", framework: "Shopify", rubyImplied: true, weight: 30, detail: "Powered-By: Shopify (Rails-based SaaS)"},
	{header: "Link", re: rePreloadLink, framework: "Rails", rubyImplied: true, weight: 35, detail: "Link preload header for fingerprinted asset-pipeline files"},

	// --- Applications ---
	{header: "Server", contains: "mastodon", framework: "Mastodon", rubyImplied: true, weight: 75, detail: "Mastodon server banner"},
	{header: "X-Discourse-Route", framework: "Discourse", rubyImplied: true, weight: 70, detail: "Discourse route header"},
	{header: "X-Discourse-Username", framework: "Discourse", rubyImplied: true, weight: 70, detail: "Discourse username header"},
	{header: "Discourse-Present", framework: "Discourse", rubyImplied: true, weight: 70, detail: "Discourse presence header"},
	{header: "X-Gitlab-Meta", framework: "GitLab", rubyImplied: true, weight: 70, detail: "GitLab request metadata header"},
	{header: "X-Gitlab-Feature-Category", framework: "GitLab", rubyImplied: true, weight: 70, detail: "GitLab feature-category header"},
	{header: "X-Gitlab-Custom-Error", framework: "GitLab", rubyImplied: true, weight: 60, detail: "GitLab error header"},
	{header: "X-GitHub-Enterprise-Version", framework: "GitHub Enterprise Server", rubyImplied: true, weight: 60, detail: "GitHub Enterprise Server version header"},
	{header: "X-Canvas-Meta", framework: "Canvas LMS", rubyImplied: true, weight: 65, detail: "Canvas LMS metadata header"},
	{header: "Foreman_version", framework: "Foreman", rubyImplied: true, weight: 65, detail: "Foreman API version header"},
	{header: "Foreman_api_version", framework: "Foreman", rubyImplied: true, weight: 60, detail: "Foreman API header"},
	{header: "X-Redmine-API-Key", framework: "Redmine", rubyImplied: true, weight: 60, detail: "Redmine API header"},
	{header: "X-Shopify-Stage", framework: "Shopify", rubyImplied: true, weight: 30, detail: "Shopify platform header (Rails-based SaaS)"},
	{header: "X-ShopId", framework: "Shopify", rubyImplied: true, weight: 30, detail: "Shopify platform header (Rails-based SaaS)"},
	{header: "X-Puppet-Version", framework: "Puppet Server", rubyImplied: true, variant: "JRuby", weight: 40, detail: "Puppet Server (runs Ruby code on JRuby)"},
}

// bodySig matches distinctive content in a response body.
type bodySig struct {
	id          string
	re          *regexp.Regexp
	framework   string
	rubyImplied bool
	weight      int
	detail      string
	// errorOnly restricts a signature that matches bare class or error names
	// to error responses and plain pages: documentation, blogs and Q&A sites
	// quote those names constantly without running Ruby.
	errorOnly bool
	// noCode skips the signature on pages that display code samples.
	noCode bool
}

// errOnly marks signatures by id as errorOnly (see bodySig).
var errOnlyIDs = map[string]bool{
	"body.rails-exception-class": true, "body.rails-routing-error": true, "body.rack-class": true,
	"body.sinatra-class": true, "body.ruby-nomethod": true, "body.ruby-uninitialized-const": true,
	"body.ruby-exception-class": true, "body.hanami": true, "body.padrino": true, "body.roda": true,
	"body.grape": true, "body.ruby-backtrace": true, "body.bundler-error": true, "body.erb-source": true,
	"body.ruby-source": true, "body.rails-record-not-found": true, "body.rails-csrf-failure": true,
	"body.template-engine-error": true, "body.db-adapter-error": true, "body.ruby-arity-error": true,
	"body.ruby-syntax-error": true, "body.jruby-trace": true, "body.ruby-nil-class": true,
	"body.rails-validation-message": false, "body.rails-schema": false,
}

// noCodeIDs are signatures for Ruby values leaking into ordinary pages. They
// are skipped on pages that display code (<pre>/<code>), where such strings
// are quoted on purpose.
var noCodeIDs = map[string]bool{
	"body.ruby-object-inspect": true, "body.ruby-hash-inspect": true, "body.rack-env-dump": true,
	"body.asset-js-ujs": true, "body.rails-load-defaults": true, "body.rails-schema": true,
	"body.dockerfile-ruby": true, "body.procfile-ruby": true, "body.rubocop-config": true,
	"body.bundle-config": true, "body.puma-config": true, "body.rails-readme": true,
}

func init() {
	for i := range bodySigs {
		if errOnlyIDs[bodySigs[i].id] {
			bodySigs[i].errorOnly = true
		}
		if noCodeIDs[bodySigs[i].id] {
			bodySigs[i].noCode = true
		}
	}
}

func bs(id, re, framework string, weight int, detail string) bodySig {
	return bodySig{id: id, re: regexp.MustCompile(re), framework: framework, rubyImplied: true, weight: weight, detail: detail}
}

// inert is a body signature that names a technology without implying a Ruby
// runtime on the server (e.g. a static site generated by Jekyll).
func inert(id, re, framework string, detail string) bodySig {
	return bodySig{id: id, re: regexp.MustCompile(re), framework: framework, rubyImplied: false, weight: 20, detail: detail}
}

var bodySigs = []bodySig{
	// --- Ruby errors and backtraces ---
	bs("body.ruby-backtrace", "[\\w./-]+\\.(?:rb|erb|haml|slim|rake|ru):\\d+:in [`']", "", 75, "Ruby backtrace frame (file.rb:LINE:in `method')"),
	bs("body.ruby-nomethod", "undefined (?:local variable or )?method [`'][\\w?!=\\[\\]]+'", "", 65, "Ruby NoMethodError / NameError message"),
	bs("body.ruby-uninitialized-const", `uninitialized constant [A-Z]\w*(?:::[A-Z]\w*)*`, "", 60, "Ruby NameError (uninitialized constant)"),
	bs("body.ruby-exception-class", `\b(?:NoMethodError|ArgumentError|LoadError|RuntimeError|ZeroDivisionError|FrozenError|KeyError|Errno::E[A-Z]+|Encoding::\w+Error|JSON::ParserError|Psych::\w+Error)\b[^<\n]{0,80}\(?(?:wrong number of arguments|cannot load such file|undefined|invalid byte sequence|divided by 0)`, "", 60, "Ruby exception class with a characteristic message"),
	bs("body.ruby-version-string", `\bruby \d+\.\d+\.\d+(?:p\d+)? \(\d{4}-\d{2}-\d{2}`, "", 65, "`ruby -v` style version string"),
	bs("body.ruby-gem-path", `/(?:gems|bundle)/(?:ruby/)?\d+\.\d+\.\d+/(?:gems|bundler/gems)/[\w-]+`, "", 65, "RubyGems installation path leaked"),
	bs("body.ruby-install-path", `/(?:\.rbenv/versions|\.rvm/(?:gems|rubies)|\.asdf/installs/ruby|usr/local/bundle/gems|usr/lib/ruby/(?:vendor_ruby|gems))/`, "", 60, "Ruby installation / version-manager path leaked"),
	bs("body.bundler-error", `Bundler::(?:GemNotFound|GemfileNotFound|LockfileError)|Could not find [\w-]+(?:-\d[\w.]*)? in (?:any of the sources|locally installed gems)|Your Ruby version is \d+\.\d+\.\d+, but your Gemfile specified`, "", 75, "Bundler error message"),
	bs("body.erb-source", `<%=?\s*(?:link_to|render|yield|form_for|form_with|image_tag|stylesheet_link_tag|javascript_include_tag|javascript_importmap_tags|csrf_meta_tags|content_for|t\(|@\w+\.\w+)`, "", 60, "ERB template source leaked (not rendered)"),
	bs("body.ruby-source", `(?m)^\s*(?:class \w+(?:::\w+)* < (?:ApplicationController|ActionController::Base|ActiveRecord::Base|ApplicationRecord|Sinatra::(?:Base|Application))|Rails\.application\.(?:routes\.draw|configure) do|require_relative ['"]\.?/?config/(?:environment|application|boot)['"])`, "", 70, "Ruby source code leaked (not executed)"),

	// --- Rails ---
	bs("body.rails-exception-page", `Action Controller: Exception caught|<title>Action Controller: Exception|Rails\.root: `, "Rails", 85, "Rails development exception page"),
	bs("body.rails-routing-error", `No route matches \[(?:GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS)\]|ActionController::(?:RoutingError|UnknownFormat|InvalidAuthenticityToken|ParameterMissing|BadRequest|UnknownHttpMethod)`, "Rails", 80, "Rails routing / controller exception"),
	bs("body.rails-exception-class", `\b(?:ActiveRecord::\w+|ActionView::(?:Template::Error|MissingTemplate)|ActionDispatch::\w+|AbstractController::\w+|ActiveSupport::\w+|ActiveModel::\w+|ActiveStorage::\w+)\b`, "Rails", 70, "Rails framework class named in the response"),
	bs("body.rails-welcome", `Yay! You(?:&rsquo;|’|')re on Rails!|You(?:&rsquo;|’|')re riding Ruby on Rails!|<title>Ruby on Rails(?:: Welcome aboard| \d[\d.]*)?</title>`, "Rails", 85, "Rails default welcome page"),
	bs("body.rails-default-error-page", `rails-default-error-page|[Tt]he page you were looking for doesn(?:&#39;|&rsquo;|’|')t exist|We(?:&#39;|&rsquo;|’|')re sorry, but something went wrong|The change you wanted was rejected|If you are the application owner check the logs for more information|The server cannot process the request due to a client error|You may have mistyped the address or the page may have moved|Maybe you tried to change something you didn(?:&#39;|&rsquo;|’|')t have access to`, "Rails", 65, "Rails default static error page (public/404|422|500.html)"),
	bs("body.rails-csrf-meta", `<meta\s+name=["']csrf-param["']\s+content=["']authenticity_token["']|<meta\s+content=["']authenticity_token["']\s+name=["']csrf-param["']`, "Rails", 60, "Rails csrf_meta_tags (csrf-param = authenticity_token)"),
	bs("body.rails-authenticity-token", `name=["']authenticity_token["']`, "Rails", 50, "Rails form authenticity_token field"),
	bs("body.rails-utf8-field", `name=["']utf8["'][^>]*value=["'](?:&#x2713;|✓)["']`, "Rails", 45, "Rails form utf8 enforcer field (Rails < 6)"),
	bs("body.rails-ujs", `data-disable-with=|rails-ujs|jquery_ujs|data-turbo-method=`, "Rails", 30, "Rails UJS / Turbo data attributes"),
	bs("body.rails-turbo-track", `data-turbo(?:links)?-track=["'](?:reload|true)["']`, "Rails", 35, "Turbo/Turbolinks asset tracking attribute (Rails default layout)"),
	bs("body.rails-asset-digest", `/assets/[\w./-]+-(?:[0-9a-f]{40}|[0-9a-f]{64})\.(?:js|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot)`, "Rails", 35, "Sprockets fingerprinted asset (/assets/name-<SHA digest>)"),
	// MD5-length and 8-character digests are also produced by Phoenix
	// (phx.digest) and JavaScript bundlers, so they are supporting evidence only.
	bs("body.asset-digest-weak", `/assets/[\w./-]+-(?:[0-9a-f]{8}\.(?:js|css)|[0-9a-f]{32}\.(?:js|css|png|jpe?g|gif|svg|webp|woff2?))`, "", 15, "fingerprinted /assets/ file (Sprockets 2 / Propshaft style; also used by other toolchains)"),
	bs("body.rails-webpacker", `/packs(?:-test)?/(?:js|css|media)/[\w./-]+-[0-9a-f]{8,}`, "Rails", 35, "Webpacker/Shakapacker pack path (/packs/…)"),
	bs("body.rails-importmap", `<script type=["']importmap["'][^>]*data-turbo-track`, "Rails", 50, "importmap-rails script tag"),
	bs("body.rails-active-storage", `/rails/active_storage/(?:blobs|representations|disk|direct_uploads)`, "Rails", 70, "Active Storage URL"),
	bs("body.rails-action-cable", `<meta\s+name=["']action-cable-url["']`, "Rails", 65, "Action Cable meta tag"),
	bs("body.rails-action-text", `<trix-editor|class=["'][^"']*trix-content`, "Rails", 25, "Action Text / Trix editor markup"),
	bs("body.rails-robots", `# See https?://www\.robotstxt\.org/(?:wc/norobots|robotstxt)\.html for documentation on how to use the robots\.txt file`, "Rails", 45, "Rails generator default robots.txt"),
	bs("body.rails-devise-form", `name=["']user\[(?:email|login|password|remember_me)\]["']`, "Rails", 40, "Rails nested form parameters for a Devise-style user model"),
	bs("body.rails-blocked-host", `Blocked hosts?: [^<\n]{1,200}|To allow requests to (?:these hosts|[^,<]{1,100}), (?:make sure|add the following)[^<]{0,120}config\.hosts`, "Rails", 85, "Rails HostAuthorization \"Blocked host\" page"),
	bs("body.rails-unsupported-browser", `Your browser is not supported \(406`, "Rails", 70, "Rails default 406-unsupported-browser page (Rails 7.2 or later)"),
	bs("body.rails-json-error", `^\s*\{"status":"?\d{3}"?,"error":"[A-Za-z' ]{2,40}"(?:,"exception":"[^"]{0,300}"(?:,"traces":.*)?)?\}\s*$`, "Rails", 50, "Rails PublicExceptions JSON error body ({status, error})"),
	bs("body.rails-xml-error", `<hash>\s*<status type="integer">\d{3}</status>\s*<error>`, "Rails", 70, "Rails PublicExceptions XML error body (ActiveSupport to_xml)"),
	bs("body.rails-json-trace", `"traces":\{"Application Trace"|"exception":"#<Action(?:Controller|Dispatch)::`, "Rails", 85, "Rails development JSON exception payload"),
	bs("body.rails-turbo-stream", `<turbo-cable-stream-source|signed-stream-name=`, "Rails", 60, "turbo-rails cable stream source"),
	bs("body.rails-csp-nonce", `<meta\s+name=["']csp-nonce["']`, "Rails", 45, "Rails csp_meta_tag"),
	bs("body.rails-importmap-turbo", `"@hotwired/turbo-rails"\s*:|"@rails/(?:ujs|actioncable|activestorage|actiontext)"\s*:`, "Rails", 55, "importmap pins for Rails JavaScript packages"),
	bs("body.rails-i18n-missing", `class=["']translation_missing["']|translation missing: [a-z]{2}(?:-[A-Za-z]{2})?\.[\w.]+`, "Rails", 60, "Rails I18n missing-translation marker"),
	bs("body.devise-message", `You need to sign in or sign up before continuing\.|Invalid (?:Email|Login|Username) or password\.|Signed out successfully\.|You have to confirm your (?:email address|account) before continuing\.`, "Rails", 55, "Devise default flash/JSON message"),
	bs("body.rails-web-console", `data-mounted-path=["'][^"']*__web_console|__web_console/repl_sessions|id=["']console["'][^>]+data-session-id`, "Rails Web Console", 80, "Rails web-console is embedded (interactive Ruby console — development mode)"),
	bs("body.better-errors", `__better_errors|BetterErrors::|<title>[^<]*better_errors`, "Better Errors", 75, "better_errors development error page"),

	// --- Rails views, helpers and conventions ---
	bs("body.rails-view-annotation", `<!-- BEGIN (?:app|lib|vendor|/)[\w./-]*\.(?:erb|haml|slim|builder|jbuilder)`, "Rails", 85, "Rails rendered-view annotations (annotate_rendered_view_with_filenames — development default)"),
	bs("body.rails-field-with-errors", `class=["']field_with_errors["']`, "Rails", 65, "Action View field_with_errors wrapper"),
	bs("body.rails-error-explanation", `id=["']error_explanation["']`, "Rails", 50, "Rails scaffold error_explanation block"),
	bs("body.rails-button-to", `<form class=["']button_to["']`, "Rails", 60, "Rails button_to helper form"),
	bs("body.rails-submit-commit", `<input type=["']submit["'] name=["']commit["']`, "Rails", 45, "Rails submit helper (name=\"commit\")"),
	bs("body.rails-form-charset", `<form[^>]+accept-charset=["']UTF-8["'][^>]*>\s*<input[^>]+name=["'](?:utf8|authenticity_token|_method)["']`, "Rails", 55, "Rails form helper output (accept-charset then hidden Rails fields)"),
	bs("body.rails-model-form", `<form[^>]+class=["'](?:simple_form |formtastic )?(?:new|edit)_[a-z_]+["'][^>]+id=["'](?:new|edit)_[a-z_]+(?:_\d+)?["']`, "Rails", 55, "Rails model form (form_for class/id convention)"),
	bs("body.rails-data-method", `data-method=["'](?:delete|put|patch|post)["']|data-remote=["']true["']`, "Rails", 35, "Rails UJS data-method / data-remote attributes"),
	bs("body.rails-default-icons", `<link rel=["']icon["'] href=["']/icon\.png["'] type=["']image/png["']>\s*<link rel=["']icon["'] href=["']/icon\.svg["'] type=["']image/svg\+xml["']>`, "Rails", 55, "Rails 7.2+ default layout icon links"),
	bs("body.rails-notice", `<p (?:id=["']notice["']|style=["']color: green["'])>`, "Rails", 35, "Rails scaffold flash notice markup"),
	bs("body.rails-flash-id", `id=["']flash_(?:notice|alert|error|success)["']`, "Rails", 30, "Rails-style flash element ids"),
	bs("body.rails-http-auth", `^HTTP (?:Basic|Token|Digest): Access denied\.\s*$`, "Rails", 75, "Rails HTTP authentication failure body"),
	bs("body.rails-redirect-body", `<html><body>You are being <a href=["'][^"']*["']>redirected</a>\.</body></html>`, "Rails", 55, "Rails redirect_to response body"),
	bs("body.rails-csrf-failure", `Can(?:'|&#39;|’)t verify CSRF token authenticity|ActionController::InvalidAuthenticityToken`, "Rails", 65, "Rails CSRF verification failure message"),
	bs("body.rails-validation-message", `can(?:'|&#39;|’)t be blank|is too short \(minimum is \d+ characters?\)|is too long \(maximum is \d+ characters?\)|is not included in the list|doesn(?:'|&#39;|’)t match (?:Password|Email)\b`, "Rails", 45, "Active Model default validation message"),
	bs("body.rails-record-not-found", `Couldn(?:'|&#39;|’)t find [A-Z]\w+(?:::\w+)* with (?:'|&#39;)?\w+(?:'|&#39;)?=`, "Rails", 70, "Active Record \"Couldn't find … with id=\" message"),
	bs("body.rails-debug-asset", `/assets/[\w./-]+\.(?:js|css)\?body=1|/assets/[\w./-]+\.debug-[0-9a-f]{8,64}\.js`, "Rails", 60, "Sprockets debug-mode asset URL (development)"),
	bs("body.rails-action-text-attachment", `<action-text-attachment\b`, "Rails", 60, "Action Text attachment element"),
	bs("body.rails-local-time", `<time[^>]+data-local=["'](?:time|date|time-ago|time-or-date|weekday|weekday-or-date)["']`, "Rails", 45, "local_time gem markup"),
	bs("body.rails-turbo-meta", `<meta name=["']turbo-(?:refresh-method|refresh-scroll|visit-control|cache-control|prefetch)["']|<meta name=["']turbolinks-cache-control["']|<turbo-frame\b|<turbo-stream\b`, "", 25, "Turbo / Turbolinks markup (Hotwire, the Rails default front end)"),
	bs("body.rails-importmap-app", `"application"\s*:\s*"/assets/application-[0-9a-f]{8,64}\.js"|"controllers/[\w/-]+"\s*:\s*"/assets/controllers/`, "Rails", 55, "importmap-rails pins for application and Stimulus controllers"),
	bs("body.rails-propshaft-manifest", `"[\w./-]+\.(?:js|css)"\s*:\s*\{"digested_path"\s*:`, "Rails", 70, "Propshaft asset manifest"),
	bs("body.vite-ruby", `/vite-dev/|/vite/assets/[\w.-]+-[\w-]{8,}\.(?:js|css)`, "Rails", 45, "vite_ruby asset paths (/vite/, /vite-dev/)"),
	bs("body.rails-service-worker", `// Add a service worker for processing Web Push notifications:`, "Rails", 60, "Rails default PWA service worker"),
	bs("body.rails-readme", `This README would normally document whatever steps are necessary to get the\s+application up and running`, "Rails", 65, "Rails generator default README"),
	bs("body.rails-schema", `ActiveRecord::Schema(?:\[\d+\.\d+\])?\.define\(version:`, "Rails", 80, "db/schema.rb source"),
	bs("body.rails-load-defaults", `config\.load_defaults\s+\d+\.\d+|class Application < Rails::Application`, "Rails", 80, "config/application.rb source"),
	bs("body.devise-links", `Didn(?:'|&#39;|’)t receive (?:confirmation|unlock) instructions\?|/users/(?:password|confirmation|unlock)/new|/users/auth/[a-z0-9_]+`, "Rails", 50, "Devise shared links / route conventions"),
	bs("body.devise-recovery", `(?i)you will receive (?:a password recovery link|an email with instructions (?:on|for) how to (?:reset your password|confirm your (?:email address|account)|unlock your account))`, "Rails", 55, "Devise default flash message"),
	bs("body.cancan-denied", `You are not authorized to access this page\.`, "Rails", 40, "CanCanCan default access-denied message"),
	bs("body.kaminari", `<span class=["']page gap["']>|<nav class=["']pagination["'] role=["']navigation["'] aria-label=["']pager["']>`, "Rails", 45, "Kaminari pagination markup"),
	bs("body.will-paginate", `class=["'](?:previous_page|next_page)(?: disabled)?["']`, "Rails", 40, "will_paginate pagination markup"),
	bs("body.pagy", `<nav[^>]+class=["']pagy[\s"'-]`, "", 45, "Pagy pagination markup"),
	bs("body.paperclip-path", `/system/[a-z_]+/[a-z_]+/\d{3}/\d{3}/\d{3}/(?:original|large|medium|small|thumb)/`, "Rails", 55, "Paperclip attachment URL (id-partitioned /system/ path)"),
	bs("body.carrierwave-path", `/uploads/[a-z_]+/[a-z_]+/\d+/[\w.%-]+\.(?:png|jpe?g|gif|webp|pdf|svg)`, "", 30, "CarrierWave default upload path (uploads/<model>/<mounted_as>/<id>/)"),
	bs("body.dragonfly", `/media/W1siZiIs[\w-]{10,}`, "", 60, "Dragonfly media URL (Base64 job beginning [[\"f\",)"),
	bs("body.graphiql-rails", `/assets/graphiql/rails/|graphiql-rails`, "Rails", 60, "graphiql-rails console"),
	bs("body.apipie", `<title>[^<]*Apipie|/apipie/|apipie-`, "Rails", 55, "Apipie API documentation"),
	bs("body.view-component-preview", `<title>(?:Component Previews|Lookbook)[^<]*</title>|/rails/view_components/`, "Rails", 60, "ViewComponent previews / Lookbook"),
	bs("body.okcomputer", `(?m)^(?:default|database): (?:PASSED|FAILED) `, "Rails", 60, "OkComputer health-check output"),
	bs("body.rails-db-viewer", `<title>Rails DB</title>|/rails/db/`, "Rails", 55, "rails_db database viewer"),

	// --- Ruby runtime leaks in ordinary output ---
	bs("body.ruby-object-inspect", `#&lt;[A-Z]\w*(?:::[A-Z]\w*)*:0x[0-9a-f]{8,16}\b|#<[A-Z]\w*(?:::[A-Z]\w*)*:0x[0-9a-f]{12,16}\b`, "", 70, "Ruby object inspect string leaked into output (#<Class:0x…>)"),
	bs("body.ruby-nil-class", `\bnil:NilClass\b|for an instance of [A-Z]\w+`, "", 65, "Ruby NoMethodError receiver description"),
	bs("body.ruby-hash-inspect", `\{(?::[a-z_]\w*|&quot;[\w ]+&quot;|"[\w ]+")\s?=(?:>|&gt;)\s?(?:"|&quot;|:|\d|nil\b|\{|\[)`, "", 55, "Ruby Hash#inspect output leaked (hash-rocket syntax)"),
	bs("body.ruby-arity-error", `wrong number of arguments \(given \d+, expected \d+(?:\.\.\d+|\+)?\)|no implicit conversion of \w+ into \w+|stack level too deep|private method [`+"`"+`']\w+' called for`, "", 65, "Ruby exception message"),
	bs("body.ruby-syntax-error", `syntax error, unexpected (?:end-of-input|keyword_end|'[^']{1,10}'|tIDENTIFIER|end)|expecting (?:keyword_end|`+"`"+`end'|end-of-input)`, "", 65, "Ruby parser syntax error"),
	bs("body.ruby-version-mismatch", `Your Ruby version is \d+\.\d+\.\d+, but your Gemfile specified`, "", 80, "Bundler Ruby-version mismatch message"),
	bs("body.jruby-trace", `\borg\.jruby\.[A-Za-z.$]+|org/jruby/\w+\.java:\d+`, "", 85, "JRuby frames in a stack trace"),
	bs("body.template-engine-error", `(?:Haml|Slim|Liquid|Erubi|Tilt|Temple)::[A-Z]\w*(?:Error|Exception)`, "", 70, "Ruby template-engine exception"),
	bs("body.db-adapter-error", `(?:PG|Mysql2|SQLite3|Trilogy)::[A-Z]\w+|(?:Sequel|Mongoid|Redis|Dalli)::[A-Z]\w*(?:Error|Exception)\b`, "", 65, "Ruby database/driver exception class"),
	bs("body.rack-env-dump", `<h3 id=["']env-info["']>Rack ENV</h3>|rack\.(?:url_scheme|errors|input|multithread|hijack)\b`, "Rack", 75, "Rack environment keys dumped in the response"),
	bs("body.dockerfile-ruby", `(?m)^(?:ARG RUBY_VERSION=\d+\.\d+|FROM (?:[\w./-]+/)?ruby:\d+\.\d+)`, "", 75, "Dockerfile building on a Ruby image"),
	bs("body.procfile-ruby", `(?m)^(?:web|worker|release):\s*(?:bundle exec |bin/)(?:puma|rails|sidekiq|rackup|unicorn|thin|rake|thrust|good_job|jobs)\b`, "", 70, "Procfile starting a Ruby process"),
	bs("body.rubocop-config", `(?m)^\s*TargetRubyVersion:\s*\d+\.\d+|^inherit_gem:|^require:\s*\n?\s*-?\s*rubocop-`, "", 65, "RuboCop configuration file"),
	bs("body.bundle-config", `(?m)^BUNDLE_(?:PATH|WITHOUT|DEPLOYMENT|FROZEN|JOBS|BIN|GEMFILE|RETRY)[:=]`, "", 70, "Bundler configuration (.bundle/config)"),
	bs("body.puma-config", `(?m)^\s*(?:threads\s+\w+,\s*\w+|workers\s+(?:ENV|\d)|plugin :tmp_restart|pidfile ENV)`, "", 70, "Puma configuration source"),

	// --- More applications and admin frameworks ---
	bs("body.active-admin-footer", `Powered by <a href=["']https?://(?:www\.)?activeadmin\.info["']`, "ActiveAdmin", 70, "ActiveAdmin footer"),
	bs("body.avo", `/avo-assets/|data-controller=["'][^"']*\bavo-`, "Avo", 55, "Avo admin framework"),
	bs("body.trestle", `/assets/trestle/|class=["'][^"']*trestle-`, "Trestle", 55, "Trestle admin framework"),
	bs("body.blazer", `<title>[^<]*Blazer</title>|/assets/blazer/`, "Blazer", 50, "Blazer BI dashboard"),
	bs("body.thredded", `class=["'][^"']*thredded--`, "Thredded", 55, "Thredded forum engine"),
	bs("body.blacklight", `class=["'][^"']*blacklight-[a-z-]+|/assets/blacklight/`, "Blacklight", 60, "Blacklight discovery interface"),
	bs("body.hyrax", `/assets/hyrax/|data-behavior=["']hyrax|class=["'][^"']*hyrax-`, "Hyrax", 55, "Hyrax / Samvera repository"),
	bs("body.archivesspace", `<title>[^<]*ArchivesSpace[^<]*</title>|archivesspace\.org`, "ArchivesSpace", 60, "ArchivesSpace (JRuby on Rails)"),
	bs("body.manageiq", `<title>ManageIQ[^<]*</title>|ManageIQ\.(?:angular|redux|component)`, "ManageIQ", 60, "ManageIQ"),
	bs("body.beef", `<title>BeEF Authentication</title>|BeEF Control Panel`, "BeEF", 75, "BeEF control panel (Ruby)"),
	bs("body.danbooru", `<meta name=["']generator["'] content=["']Danbooru|data-current-user-name=`, "Danbooru", 50, "Danbooru"),
	bs("body.homeland", `<meta name=["']generator["'] content=["']Homeland|homeland-`, "Homeland", 50, "Homeland forum"),
	bs("body.greenlight", `BigBlueButton Greenlight|<title>[^<]*Greenlight[^<]*</title>`, "Greenlight", 55, "BigBlueButton Greenlight"),
	bs("body.chiliproject", `Powered by <a href=["']https?://www\.chiliproject\.org/?["']`, "ChiliProject", 75, "ChiliProject"),
	bs("body.padrino-admin", `Padrino Admin`, "Padrino", 60, "Padrino admin interface"),
	bs("body.asset-js-ujs", `Rails\.(?:ajax|fire|delegate|linkClickSelector|csrfToken)\b|@rails/ujs|rails-ujs`, "Rails", 45, "rails-ujs code in a JavaScript bundle"),
	bs("body.asset-js-cable", `ActionCable\.createConsumer|createConsumer\(\)|ActionCable\.INTERNAL|actioncable-v1-json`, "Rails", 50, "Action Cable client code in a JavaScript bundle"),
	bs("body.asset-js-storage", `ActiveStorage\.(?:start|DirectUpload)|direct-upload:initialize|data-direct-upload-url`, "Rails", 50, "Active Storage client code / direct-upload attributes"),

	// --- Sinatra / Rack / other frameworks ---
	bs("body.sinatra-404", `Sinatra doesn(?:&rsquo;|&#x2019;|’|')t know this ditty|<img src=["'][^"']{0,200}__sinatra__/(?:404|500)\.png`, "Sinatra", 90, "Sinatra default not-found / error page"),
	bs("body.sinatra-bad-request", `^Invalid query parameters: `, "Sinatra", 70, "Sinatra 400 response for an unparseable query"),
	bs("body.sinatra-class", `Sinatra::(?:NotFound|Base|Application|ShowExceptions|BadRequest)`, "Sinatra", 80, "Sinatra class named in the response"),
	bs("body.rack-class", `Rack::(?:ShowExceptions|Lint(?:::LintError)?|QueryParser|Utils|MethodOverride|Session|Multipart|Protection|Attack|Timeout)\b`, "Rack", 70, "Rack class named in the response"),
	bs("body.rack-param-error", `expected (?:Hash|Array) \(got (?:String|Array|Hash|Rack::QueryParser::Params)\) for param|invalid %-encoding \(`, "Rack", 75, "Rack query-parser error message"),
	bs("body.rack-files", `^File not found: /[^\n]{0,200}\n?$`, "Rack", 65, "Rack::Files / Rack::Static not-found body"),
	bs("body.rack-urlmap", `^Not Found: /[^\n]{0,200}$`, "Rack", 50, "Rack::URLMap not-found body"),
	bs("body.rack-attack", `^Retry later\n?$`, "Rack", 50, "Rack::Attack default throttle response"),
	bs("body.rack-protection", `Forbidden by Rack::Protection|rack\.protection`, "Rack", 65, "Rack::Protection response"),
	bs("body.hanami", `<title>Hanami \|[^<]*</title>|Hanami::(?:Router|Action|View|Controller)`, "Hanami", 75, "Hanami framework page"),
	bs("body.padrino", `Padrino::(?:Application|Routing|Rendering)|padrino-framework`, "Padrino", 70, "Padrino framework page"),
	bs("body.roda", `Roda::(?:RodaError|RodaPlugins)`, "Roda", 70, "Roda framework error"),
	bs("body.grape", `Grape::(?:Exceptions|API|Endpoint)`, "Grape", 70, "Grape API framework error"),

	// --- App servers ---
	bs("body.puma-error", `Puma caught this error|An unhandled lowlevel error occurred\. The application logs may have details\.`, "", 85, "Puma low-level error page"),
	bs("body.webrick-error", `(?i)<address>\s*WEBrick/[\d.]+ \(Ruby/\d+\.\d+\.\d+`, "", 90, "WEBrick error page signature (leaks the Ruby version)"),
	bs("body.passenger-error", `Web application could not be started|This error page was generated by Phusion Passenger|Phusion Passenger(?:&reg;|®|\(R\))? is a web server and application server|id=["']passenger|Incomplete response received from application|The issue has been logged for investigation\. Please try again later\.`, "", 35, "Phusion Passenger error page"),
	bs("body.unicorn-error", `unicorn (?:master|worker)\b`, "", 55, "Unicorn process name in the response"),

	// --- Tools, dashboards ---
	bs("body.sidekiq-web", `<title>(?:\[[^\]]+\]\s*)?Sidekiq</title>|Sidekiq::Web|data-poll-path=|class=["'][^"']*sidekiq`, "Sidekiq Web", 60, "Sidekiq Web dashboard markup"),
	bs("body.active-admin", `active_admin(?:\.css|\.js|-[0-9a-f]{8,})|id=["']active_admin_content["']|class=["'][^"']*active_admin`, "ActiveAdmin", 60, "ActiveAdmin interface"),
	bs("body.rails-admin", `rails_admin(?:/|\.css|\.js|-[0-9a-f]{8,})|class=["'][^"']*rails_admin`, "RailsAdmin", 60, "RailsAdmin interface"),
	bs("body.administrate", `/assets/administrate/|class=["'][^"']*administrate`, "Administrate", 50, "Administrate dashboard"),
	bs("body.mini-profiler", `/mini-profiler-resources/includes\.js`, "rack-mini-profiler", 40, "rack-mini-profiler include"),
	bs("body.letter-opener", `<title>LetterOpenerWeb</title>|letter_opener_web/|id=["']letter_opener`, "Letter Opener", 55, "letter_opener mail preview"),
	bs("body.flipper-ui", `<title>[^<]*Flipper</title>|flipper-ui|Flipper::UI`, "Flipper UI", 50, "Flipper feature-flag UI"),
	bs("body.pghero", `<title>PgHero</title>|/assets/pghero/`, "PgHero", 50, "PgHero dashboard"),
	bs("body.resque-web", `<title>Resque\.?</title>|resque-web|class=["']resque`, "Resque Web", 55, "Resque dashboard"),
	bs("body.good-job", `<title>GoodJob[^<]*</title>|/good_job/assets/`, "GoodJob Dashboard", 50, "GoodJob dashboard"),
	bs("body.mission-control", `mission_control/jobs/application|<title>Mission Control - Jobs`, "Mission Control Jobs", 50, "Mission Control Jobs dashboard"),

	// --- Applications ---
	bs("body.gitlab", `gon\.gitlab_url|window\.gon\s*=\s*\{\};\s*gon\.api_version|/assets/webpack/[\w.-]+\.chunk\.js|<meta content=["']GitLab["'] name=["']description`, "GitLab", 75, "GitLab application page markers"),
	bs("body.discourse", `<meta name=["']generator["'] content=["']Discourse|id=["']data-discourse-setup["']|<meta name=["']discourse_theme_id["']|discourse-application`, "Discourse", 75, "Discourse page markers"),
	bs("body.mastodon", `<div id=["']mastodon["']|<script id=["']initial-state["'] type=["']application/json["']`, "Mastodon", 70, "Mastodon application page markers"),
	bs("body.redmine", `Powered by <a href=["']https?://www\.redmine\.org/?["'][^>]*>Redmine</a>|<meta name=["']description["'] content=["']Redmine["']|redmine\.org/guide`, "Redmine", 80, "Redmine page markers"),
	bs("body.openproject", `<meta name=["']application-name["'] content=["']OpenProject["']|<meta name=["']openproject_initializer["']|openproject\.org`, "OpenProject", 65, "OpenProject page markers"),
	bs("body.chatwoot", `window\.chatwootConfig\s*=|<title>[^<]*Chatwoot[^<]*</title>|window\.globalConfig\s*=\s*\{[^}]*INSTALLATION_NAME`, "Chatwoot", 65, "Chatwoot dashboard markers"),
	bs("body.diaspora", `<meta name=["']generator["'] content=["']Diaspora|diaspora\*</a>|gon\.appConfig`, "diaspora*", 70, "diaspora* page markers"),
	bs("body.spree", `Spree\.(?:routes|api_key|ready|url_params)|/assets/spree/|spree/frontend`, "Spree", 65, "Spree Commerce page markers"),
	bs("body.solidus", `/assets/solidus_(?:admin|frontend|backend)|Solidus\.|solidus_starter_frontend`, "Solidus", 60, "Solidus page markers"),
	bs("body.canvas-lms", `window\.INST\s*=|<div id=["']application["'] class=["']ic-app|instructure-ui`, "Canvas LMS", 60, "Canvas LMS page markers"),
	bs("body.foreman", `theforeman\.org|data-react-class=["']ForemanContext|<title>Foreman</title>|foreman-react-component`, "Foreman", 55, "Foreman page markers"),
	bs("body.zammad", `<title>Zammad[^<]*</title>|Zammad Helpdesk|zammad\.org`, "Zammad", 60, "Zammad page markers"),
	bs("body.huginn", `<title>Huginn</title>|huginn/huginn`, "Huginn", 60, "Huginn page markers"),
	bs("body.errbit", `<title>[^<]*Errbit[^<]*</title>|errbit/errbit`, "Errbit", 60, "Errbit page markers"),
	bs("body.decidim", `<meta name=["']generator["'] content=["']Decidim|/decidim-packs/|decidim/[a-z_]+-[0-9a-f]{8,}`, "Decidim", 60, "Decidim page markers"),
	bs("body.refinery", `refinerycms|Refinery CMS`, "Refinery CMS", 60, "Refinery CMS page markers"),
	bs("body.alchemy", `alchemy_cms|Alchemy CMS|alchemy/admin`, "Alchemy CMS", 55, "Alchemy CMS page markers"),
	bs("body.camaleon", `camaleon_cms|Camaleon CMS`, "Camaleon CMS", 60, "Camaleon CMS page markers"),
	bs("body.publify", `<meta name=["']generator["'] content=["']Publify|publify_core`, "Publify", 60, "Publify page markers"),
	bs("body.gollum", `gollum-editor|id=["']gollum-|/gollum/(?:create|edit|pages|latest_changes)`, "Gollum", 60, "Gollum wiki page markers"),
	bs("body.dradis", `<title>[^<]*Dradis[^<]*</title>|dradisframework`, "Dradis", 60, "Dradis page markers"),
	bs("body.metasploit", `<title>Metasploit(?: Pro)?(?: - [^<]*)?</title>`, "Metasploit Pro", 55, "Metasploit web UI (Rails)"),
	bs("body.fatfreecrm", `Fat Free CRM|fat_free_crm`, "Fat Free CRM", 60, "Fat Free CRM page markers"),
	bs("body.loomio", `<title>Loomio[^<]*</title>|loomio\.org`, "Loomio", 45, "Loomio page markers"),
	bs("body.forem", `<meta name=["']application-name["'] content=["'](?:Forem|DEV Community)|data-forem-|forem\.com`, "Forem", 50, "Forem page markers"),

	// --- Ruby-built but not Ruby-served (no runtime implied) ---
	inert("body.static-jekyll", `<meta name=["']generator["'] content=["']Jekyll`, "Jekyll (static site generator)", "Jekyll-generated static site (Ruby at build time only)"),
	inert("body.static-middleman", `<meta name=["']generator["'] content=["']Middleman`, "Middleman (static site generator)", "Middleman-generated static site (Ruby at build time only)"),
	inert("body.static-nanoc", `<meta name=["']generator["'] content=["'][Nn]anoc`, "Nanoc (static site generator)", "Nanoc-generated static site (Ruby at build time only)"),
	inert("body.static-octopress", `<meta name=["']generator["'] content=["']Octopress`, "Octopress (static site generator)", "Octopress-generated static site (Ruby at build time only)"),
	inert("body.static-bridgetown", `<meta name=["']generator["'] content=["']Bridgetown`, "Bridgetown (static site generator)", "Bridgetown-generated static site (Ruby at build time only)"),
}

// gemTokens maps body substrings to a gem / library name reported under Gems.
var gemTokens = []struct {
	token string
	gem   string
}{
	{"data-turbo", "turbo-rails"},
	{"data-turbolinks", "turbolinks"},
	{"data-controller=", "stimulus-rails"},
	{"rails-ujs", "rails-ujs"},
	{"jquery_ujs", "jquery-rails"},
	{"/rails/active_storage/", "activestorage"},
	{"action-cable-url", "actioncable"},
	{"trix-editor", "actiontext"},
	{"src=\"/packs/", "webpacker/shakapacker"},
	{"href=\"/packs/", "webpacker/shakapacker"},
	{"type=\"importmap\"", "importmap-rails"},
	{"user[remember_me]", "devise"},
	{"/users/sign_in", "devise"},
	{"simple_form", "simple_form"},
	{"Warden::", "warden"},
	{"Devise::", "devise"},
	{"Sprockets::", "sprockets"},
	{"Propshaft::", "propshaft"},
	{"Haml::", "haml"},
	{"Slim::", "slim"},
	{"Liquid::", "liquid"},
	{"Nokogiri::", "nokogiri"},
	{"Sequel::", "sequel"},
	{"Mongoid::", "mongoid"},
	{"PG::", "pg"},
	{"Mysql2::", "mysql2"},
	{"SQLite3::", "sqlite3"},
	{"Redis::", "redis"},
	{"Faraday::", "faraday"},
	{"GraphQL::", "graphql"},
	{"Pundit::", "pundit"},
	{"CanCan::", "cancancan"},
	{"OmniAuth::", "omniauth"},
	{"Doorkeeper::", "doorkeeper"},
	{"will_paginate", "will_paginate"},
	{"CarrierWave::", "carrierwave"},
	{"Paperclip::", "paperclip"},
	{"Shrine::", "shrine"},
	{"mini-profiler-resources", "rack-mini-profiler"},
}

// middlewareGems maps a Rack middleware class (as listed by
// /rails/info/properties) to the gem that provides it.
var middlewareGems = map[string]string{
	"Warden::Manager":                   "devise/warden",
	"Rack::Cors":                        "rack-cors",
	"Rack::Attack":                      "rack-attack",
	"Rack::Cache":                       "rack-cache",
	"Rack::MiniProfiler":                "rack-mini-profiler",
	"Rack::Timeout":                     "rack-timeout",
	"Rack::Deflater":                    "rack (Rack::Deflater)",
	"WebConsole::Middleware":            "web-console",
	"BetterErrors::Middleware":          "better_errors",
	"Bullet::Rack":                      "bullet",
	"OmniAuth::Builder":                 "omniauth",
	"Sentry::Rails::CaptureExceptions":  "sentry-rails",
	"Sentry::Rack::CaptureExceptions":   "sentry-ruby",
	"NewRelic::Rack::AgentHooks":        "newrelic_rpm",
	"Datadog::Tracing::Contrib::Rack":   "ddtrace",
	"Honeybadger::Rack::ErrorNotifier":  "honeybadger",
	"Bugsnag::Rack":                     "bugsnag",
	"Airbrake::Rack::Middleware":        "airbrake",
	"Rollbar::Middleware::Rails":        "rollbar",
	"ScoutApm::Middleware":              "scout_apm",
	"Skylight::Middleware":              "skylight",
	"Propshaft::Server":                 "propshaft",
	"Sprockets::Rails::QuietAssets":     "sprockets-rails",
	"Webpacker::DevServerProxy":         "webpacker",
	"Shakapacker::DevServerProxy":       "shakapacker",
	"ViteRuby::DevServerProxy":          "vite_ruby",
	"Flipper::Middleware::Memoizer":     "flipper",
	"Apartment::Elevators::Subdomain":   "apartment",
	"Rack::LiveReload":                  "rack-livereload",
	"ActionDispatch::HostAuthorization": "",
}
