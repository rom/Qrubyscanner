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
	{"remember_user_token", matchExact, "", 50, "Devise remember-me cookie"},
	{"remember_admin_user_token", matchExact, "", 50, "Devise remember-me cookie (admin scope)"},
	{"_passenger_route", matchExact, "", 25, "Phusion Passenger sticky-session cookie"},
	{"request_method", matchExact, "", 20, "legacy Rails request_method cookie"},
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
	{header: "X-GitHub-Request-Id", framework: "GitHub", rubyImplied: true, weight: 30, detail: "GitHub request id header (GitHub is a Rails application)"},
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
	bs("body.rails-default-error-page", `rails-default-error-page|The page you were looking for doesn(?:&#39;|&rsquo;|’|')t exist|We(?:&#39;|&rsquo;|’|')re sorry, but something went wrong|The change you wanted was rejected|If you are the application owner check the logs for more information|The server cannot process the request due to a client error`, "Rails", 65, "Rails default static error page (public/404|422|500.html)"),
	bs("body.rails-csrf-meta", `<meta\s+name=["']csrf-param["']\s+content=["']authenticity_token["']|<meta\s+content=["']authenticity_token["']\s+name=["']csrf-param["']`, "Rails", 60, "Rails csrf_meta_tags (csrf-param = authenticity_token)"),
	bs("body.rails-authenticity-token", `name=["']authenticity_token["']`, "Rails", 50, "Rails form authenticity_token field"),
	bs("body.rails-utf8-field", `name=["']utf8["'][^>]*value=["'](?:&#x2713;|✓)["']`, "Rails", 45, "Rails form utf8 enforcer field (Rails < 6)"),
	bs("body.rails-ujs", `data-disable-with=|rails-ujs|jquery_ujs|data-turbo-method=`, "Rails", 30, "Rails UJS / Turbo data attributes"),
	bs("body.rails-turbo-track", `data-turbo(?:links)?-track=["'](?:reload|true)["']`, "Rails", 35, "Turbo/Turbolinks asset tracking attribute (Rails default layout)"),
	bs("body.rails-asset-digest", `/assets/[\w./-]+-(?:[0-9a-f]{8}|[0-9a-f]{32,64})\.(?:js|css)`, "Rails", 35, "Sprockets/Propshaft fingerprinted asset (/assets/name-<digest>)"),
	bs("body.rails-webpacker", `/packs(?:-test)?/(?:js|css|media)/[\w./-]+-[0-9a-f]{8,}`, "Rails", 35, "Webpacker/Shakapacker pack path (/packs/…)"),
	bs("body.rails-importmap", `<script type=["']importmap["'][^>]*data-turbo-track`, "Rails", 50, "importmap-rails script tag"),
	bs("body.rails-active-storage", `/rails/active_storage/(?:blobs|representations|disk|direct_uploads)`, "Rails", 70, "Active Storage URL"),
	bs("body.rails-action-cable", `<meta\s+name=["']action-cable-url["']`, "Rails", 65, "Action Cable meta tag"),
	bs("body.rails-action-text", `<trix-editor|class=["'][^"']*trix-content`, "Rails", 25, "Action Text / Trix editor markup"),
	bs("body.rails-robots", `# See https?://www\.robotstxt\.org/(?:wc/norobots|robotstxt)\.html for documentation on how to use the robots\.txt file`, "Rails", 45, "Rails generator default robots.txt"),
	bs("body.rails-devise-form", `name=["']user\[(?:email|login|password|remember_me)\]["']`, "Rails", 40, "Rails nested form parameters for a Devise-style user model"),
	bs("body.rails-web-console", `data-mounted-path=["'][^"']*__web_console|__web_console/repl_sessions|id=["']console["'][^>]+data-session-id`, "Rails Web Console", 80, "Rails web-console is embedded (interactive Ruby console — development mode)"),
	bs("body.better-errors", `__better_errors|BetterErrors::|<title>[^<]*better_errors`, "Better Errors", 75, "better_errors development error page"),

	// --- Sinatra / Rack / other frameworks ---
	bs("body.sinatra-404", `Sinatra doesn(?:&rsquo;|&#x2019;|’|')t know this ditty|__sinatra__/(?:404|500)\.png`, "Sinatra", 90, "Sinatra default not-found / error page"),
	bs("body.sinatra-bad-request", `^Invalid query parameters: `, "Sinatra", 70, "Sinatra 400 response for an unparseable query"),
	bs("body.sinatra-class", `Sinatra::(?:NotFound|Base|Application|ShowExceptions|BadRequest)`, "Sinatra", 80, "Sinatra class named in the response"),
	bs("body.rack-class", `Rack::(?:ShowExceptions|Lint(?:::LintError)?|QueryParser|Utils|MethodOverride|Session|Multipart|Protection|Attack|Timeout)\b`, "Rack", 70, "Rack class named in the response"),
	bs("body.rack-param-error", `expected (?:Hash|Array) \(got (?:String|Array|Hash|Rack::QueryParser::Params)\) for param|invalid %-encoding \(`, "Rack", 75, "Rack query-parser error message"),
	bs("body.rack-protection", `Forbidden by Rack::Protection|rack\.protection`, "Rack", 65, "Rack::Protection response"),
	bs("body.hanami", `<title>Hanami \|[^<]*</title>|Hanami::(?:Router|Action|View|Controller)`, "Hanami", 75, "Hanami framework page"),
	bs("body.padrino", `Padrino::(?:Application|Routing|Rendering)|padrino-framework`, "Padrino", 70, "Padrino framework page"),
	bs("body.roda", `Roda::(?:RodaError|RodaPlugins)`, "Roda", 70, "Roda framework error"),
	bs("body.grape", `Grape::(?:Exceptions|API|Endpoint)`, "Grape", 70, "Grape API framework error"),

	// --- App servers ---
	bs("body.puma-error", `Puma caught this error`, "", 85, "Puma low-level error page"),
	bs("body.webrick-error", `(?i)<address>\s*WEBrick/[\d.]+ \(Ruby/\d+\.\d+\.\d+`, "", 90, "WEBrick error page signature (leaks the Ruby version)"),
	bs("body.passenger-error", `Web application could not be started|This error page was generated by Phusion Passenger|Phusion Passenger(?:&reg;|®|\(R\))? is a web server and application server|id=["']passenger`, "", 35, "Phusion Passenger error page"),
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
	bs("body.gitlab", `content=["']GitLab["'][^>]*property=["']og:site_name["']|property=["']og:site_name["'][^>]*content=["']GitLab["']|gon\.gitlab_url|window\.gon\s*=\s*\{\};\s*gon\.api_version|<meta content=["']GitLab["'] name=["']description`, "GitLab", 75, "GitLab page markers"),
	bs("body.discourse", `<meta name=["']generator["'] content=["']Discourse|id=["']data-discourse-setup["']|<meta name=["']discourse_theme_id["']|discourse-application`, "Discourse", 75, "Discourse page markers"),
	bs("body.mastodon", `<div id=["']mastodon["']|content=["']Mastodon["'][^>]*property=["']og:site_name|<script id=["']initial-state["'] type=["']application/json["']|mastodon/mastodon`, "Mastodon", 70, "Mastodon page markers"),
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
	bs("body.decidim", `<meta name=["']generator["'] content=["']Decidim|decidim-[a-z]+|decidim\.org`, "Decidim", 60, "Decidim page markers"),
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
