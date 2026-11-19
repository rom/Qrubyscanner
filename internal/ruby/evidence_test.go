package ruby

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/qrubyscanner/internal/probe"
)

// TestSignatureTable exercises the passive signatures one response at a time.
func TestSignatureTable(t *testing.T) {
	type tc struct {
		name   string
		status int
		hdr    map[string]string
		body   string
		signal string
	}
	cases := []tc{
		{"doorkeeper", 401, map[string]string{"WWW-Authenticate": `Bearer realm="Doorkeeper", error="invalid_token"`}, "", "header.www-authenticate"},
		{"basic-realm", 401, map[string]string{"WWW-Authenticate": `Basic realm="Application"`}, "HTTP Basic: Access denied.\n", "body.rails-http-auth"},
		{"bullet", 200, map[string]string{"X-Bullet-Footer-Text": "[]"}, "", "header.x-bullet-footer-text"},
		{"allowall", 200, map[string]string{"X-Frame-Options": "ALLOWALL"}, "", "header.x-frame-options"},
		{"mod_ruby", 200, map[string]string{"Server": "Apache/2.2.3 (CentOS) mod_ruby/1.2.6 Ruby/1.8.7(2008-08-11)"}, "", "header.server"},
		{"iodine", 200, map[string]string{"Server": "iodine 0.7.57"}, "", "header.server"},
		{"view-annotation", 200, nil, "<!-- BEGIN app/views/posts/new.html.erb\n--><h1>New</h1>", "body.rails-view-annotation"},
		{"field-with-errors", 422, nil, `<div class="field_with_errors"><input name="post[title]"></div>`, "body.rails-field-with-errors"},
		{"error-explanation", 422, nil, `<div id="error_explanation"><h2>2 errors prohibited this post</h2></div>`, "body.rails-error-explanation"},
		{"button-to", 200, nil, `<form class="button_to" method="post" action="/posts/1">`, "body.rails-button-to"},
		{"submit-commit", 200, nil, `<input type="submit" name="commit" value="Create Post" data-disable-with="Create Post" />`, "body.rails-submit-commit"},
		{"form-charset", 200, nil, `<form action="/posts" accept-charset="UTF-8" method="post"><input type="hidden" name="authenticity_token" value="x" />`, "body.rails-form-charset"},
		{"model-form", 200, nil, `<form class="new_user" id="new_user" action="/users" method="post">`, "body.rails-model-form"},
		{"data-method", 200, nil, `<a data-confirm="Sure?" rel="nofollow" data-method="delete" href="/posts/1">Destroy</a>`, "body.rails-data-method"},
		{"default-icons", 200, nil, "<link rel=\"icon\" href=\"/icon.png\" type=\"image/png\">\n    <link rel=\"icon\" href=\"/icon.svg\" type=\"image/svg+xml\">", "body.rails-default-icons"},
		{"notice", 200, nil, `<p style="color: green">Post was successfully created.</p>`, "body.rails-notice"},
		{"redirect-body", 302, nil, `<html><body>You are being <a href="http://h/login">redirected</a>.</body></html>`, "body.rails-redirect-body"},
		{"validation", 422, nil, `{"errors":{"email":["can't be blank"],"password":["is too short (minimum is 6 characters)"]}}`, "body.rails-validation-message"},
		{"record-not-found", 404, nil, `Couldn't find Post with 'id'=999`, "body.rails-record-not-found"},
		{"debug-asset", 200, nil, `<script src="/assets/application.js?body=1"></script>`, "body.rails-debug-asset"},
		{"action-text", 200, nil, `<action-text-attachment sgid="x"></action-text-attachment>`, "body.rails-action-text-attachment"},
		{"local-time", 200, nil, `<time datetime="2026-01-01T00:00:00Z" data-local="time-ago">January 1</time>`, "body.rails-local-time"},
		{"propshaft-manifest", 200, nil, `{"application.css":{"digested_path":"application-8b441ae0.css","integrity":null}}`, "body.rails-propshaft-manifest"},
		{"vite-ruby", 200, nil, `<script src="/vite-dev/@vite/client" type="module"></script>`, "body.vite-ruby"},
		{"service-worker", 200, nil, "// Add a service worker for processing Web Push notifications:\n//", "body.rails-service-worker"},
		{"readme", 200, nil, "# README\n\nThis README would normally document whatever steps are necessary to get the\napplication up and running.", "body.rails-readme"},
		{"schema", 200, nil, "ActiveRecord::Schema[7.1].define(version: 2024_01_01_000000) do", "body.rails-schema"},
		{"devise-links", 200, nil, `<a href="/users/password/new">Forgot your password?</a>`, "body.devise-links"},
		{"devise-recovery", 200, nil, `You will receive an email with instructions on how to reset your password in a few minutes.`, "body.devise-recovery"},
		{"cancan", 403, nil, `You are not authorized to access this page.`, "body.cancan-denied"},
		{"kaminari", 200, nil, `<nav class="pagination" role="navigation" aria-label="pager"><span class="page gap">…</span></nav>`, "body.kaminari"},
		{"will-paginate", 200, nil, `<div class="pagination"><span class="previous_page disabled">←</span></div>`, "body.will-paginate"},
		{"pagy", 200, nil, `<nav class="pagy nav" aria-label="Pages">`, "body.pagy"},
		{"paperclip", 200, nil, `<img src="/system/users/avatars/000/000/012/thumb/me.png">`, "body.paperclip-path"},
		{"dragonfly", 200, nil, `<img src="/media/W1siZiIsIjIwMTYvMDEvMDEvYS5wbmciXV0/a.png">`, "body.dragonfly"},
		{"object-inspect", 200, nil, `Welcome #&lt;User:0x00007f8b1c0a2b38&gt;`, "body.ruby-object-inspect"},
		{"nil-class", 500, nil, `undefined method 'name' for nil:NilClass`, "body.ruby-nil-class"},
		{"hash-inspect", 200, nil, `<span>{:status=&gt;"ok", :count=&gt;3}</span>`, "body.ruby-hash-inspect"},
		{"arity", 500, nil, `wrong number of arguments (given 1, expected 2)`, "body.ruby-arity-error"},
		{"syntax", 500, nil, `syntax error, unexpected end-of-input, expecting keyword_end`, "body.ruby-syntax-error"},
		{"bundler-mismatch", 500, nil, `Your Ruby version is 3.1.2, but your Gemfile specified 3.2.0`, "body.ruby-version-mismatch"},
		{"jruby", 500, nil, "at org.jruby.RubyProc.call(RubyProc.java:274)\norg/jruby/RubyKernel.java:1052:in `require'", "body.jruby-trace"},
		{"template-engine", 500, nil, `Haml::SyntaxError: Illegal nesting`, "body.template-engine-error"},
		{"db-adapter", 500, nil, `PG::ConnectionBad: could not connect to server`, "body.db-adapter-error"},
		{"rack-env", 500, nil, `<h3 id="env-info">Rack ENV</h3>`, "body.rack-env-dump"},
		{"dockerfile", 200, nil, "ARG RUBY_VERSION=3.3.6\nFROM docker.io/library/ruby:$RUBY_VERSION-slim AS base\n", "body.dockerfile-ruby"},
		{"procfile", 200, nil, "web: bundle exec puma -C config/puma.rb\nworker: bundle exec sidekiq\n", "body.procfile-ruby"},
		{"rubocop", 200, nil, "AllCops:\n  TargetRubyVersion: 3.2\n", "body.rubocop-config"},
		{"bundle-config", 200, nil, "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_WITHOUT: \"development:test\"\n", "body.bundle-config"},
		{"puma-config", 200, nil, "threads threads_count, threads_count\nplugin :tmp_restart\n", "body.puma-config"},
		{"activeadmin-footer", 200, nil, `Powered by <a href="https://activeadmin.info">Active Admin</a> 3.2.0`, "body.active-admin-footer"},
		{"avo", 200, nil, `<link rel="stylesheet" href="/avo-assets/avo.base.css">`, "body.avo"},
		{"blacklight", 200, nil, `<body class="blacklight-catalog blacklight-catalog-index">`, "body.blacklight"},
		{"beef", 200, nil, `<title>BeEF Authentication</title>`, "body.beef"},
		{"chiliproject", 200, nil, `Powered by <a href="https://www.chiliproject.org/">ChiliProject</a>`, "body.chiliproject"},
		{"js-ujs", 200, nil, `Rails.ajax({url:"/x",type:"POST"});Rails.csrfToken()`, "body.asset-js-ujs"},
		{"js-cable", 200, nil, `const consumer=ActionCable.createConsumer();`, "body.asset-js-cable"},
		{"js-storage", 200, nil, `<input type="file" data-direct-upload-url="/rails/active_storage/direct_uploads">`, "body.asset-js-storage"},
		{"graphiql", 200, nil, `<script src="/assets/graphiql/rails/application-abc.js"></script>`, "body.graphiql-rails"},
		{"okcomputer", 200, nil, "default: PASSED Application is running (0s)\ndatabase: PASSED Schema version: 20240101 (0s)\n", "body.okcomputer"},
		{"rails-404-subtitle", 404, nil, `<p>You may have mistyped the address or the page may have moved.</p>`, "body.rails-default-error-page"},
		{"json-error-string-status", 500, nil, `{"status":"500","error":"Internal Server Error"}`, "body.rails-json-error"},
	}
	for _, c := range cases {
		d := Analyze(Input{TargetURL: "http://h/", Root: resp(c.status, c.hdr, c.body)})
		if !hasSignal(d, c.signal) {
			t.Errorf("%s: missing %s (got %v)", c.name, c.signal, signals(d))
		}
	}
}

func signals(d *Detection) []string {
	var out []string
	for _, e := range d.Evidence {
		out = append(out, e.Signal)
	}
	return out
}

func TestMoreCookies(t *testing.T) {
	for name, signal := range map[string]string{
		"user_credentials": "cookie.user_credentials", "__profilin": "cookie.profilin", "BEEFSESSION": "cookie.beefsession",
		"remember_admin_token": "cookie.devise-remember", "cw_d_session_info": "cookie.cw_d_session_info",
		"_legacy_normandy_session": "cookie.legacy_normandy_session",
	} {
		d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, "", &http.Cookie{Name: name, Value: "x"})})
		if !hasSignal(d, signal) {
			t.Errorf("cookie %s: want %s, got %v", name, signal, signals(d))
		}
	}
	// Shopify's several platform markers count once.
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Sorting-Hat-ShopId": "1", "X-Sorting-Hat-PodId": "2", "Powered-By": "Shopify"}, "",
		&http.Cookie{Name: "_shopify_y", Value: "x"}, &http.Cookie{Name: "_shopify_s", Value: "y"})})
	n := 0
	for _, e := range d.Evidence {
		if e.Signal == "stack.shopify" {
			n++
		}
	}
	if n != 1 || d.Confidence != 55 || !hasStr(d.Frameworks, "Shopify") {
		t.Fatalf("shopify should count once at 55: n=%d conf=%d", n, d.Confidence)
	}
}

func TestGuardsOnNewSignatures(t *testing.T) {
	// A tutorial page that shows Ruby output in code blocks is not a leak.
	tutorial := "<html><body><article><p>In irb you will see:</p><pre><code>#&lt;User:0x00007f8b1c0a2b38&gt;\n{:status=&gt;\"ok\"}\nrack.url_scheme</code></pre>" +
		strings.Repeat("<p>more tutorial text</p>", 150) + "</article></body></html>"
	if d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, tutorial)}); d.Confidence != 0 {
		t.Errorf("tutorial page scored %d: %v", d.Confidence, signals(d))
	}
	// Laravel also says "has already been taken"; it must not match.
	if d := Analyze(Input{TargetURL: "http://h/", Root: resp(422, nil, `{"errors":{"email":["The email has already been taken."]}}`)}); d.Confidence != 0 {
		t.Errorf("Laravel validation text matched: %v", signals(d))
	}
	// Phoenix writes the same redirect body as Rails.
	ph := resp(302, map[string]string{"X-Request-Id": "GOliXQOLSIlh6XAAsijD"}, `<html><body>You are being <a href="/login">redirected</a>.</body></html>`, &http.Cookie{Name: "_app_key", Value: "SFMyNTY.x"})
	if d := Analyze(Input{TargetURL: "http://h/", Root: ph}); d.Confidence != 0 {
		t.Errorf("Phoenix redirect body matched: %v", signals(d))
	}
	// A Rails dev 404 that merely echoes the Sinatra probe path is not Sinatra.
	echo := resp(404, nil, `<h2>No route matches [GET] "/__sinatra__/404.png"</h2>`)
	if d := Analyze(Input{TargetURL: "http://h/", Root: echo}); hasStr(d.Frameworks, "Sinatra") {
		t.Error("echoed path flagged as Sinatra")
	}
}

func TestRedirectHopBody(t *testing.T) {
	r := resp(200, nil, "<html>login</html>")
	r.HopBodies = []string{`<html><body>You are being <a href="http://h/users/sign_in">redirected</a>.</body></html>`}
	d := Analyze(Input{TargetURL: "http://h/", Root: r})
	if !hasSignal(d, "body.rails-redirect-body") || !d.IsRuby {
		t.Fatalf("redirect hop body not used: %v", signals(d))
	}
}

func TestVersionSourcesFromFilesAndHeaders(t *testing.T) {
	d := deep(resp(200, nil, "x"), map[string]*probe.Response{
		"http://h/Dockerfile": resp(200, nil, "ARG RUBY_VERSION=3.3.6\nFROM docker.io/library/ruby:$RUBY_VERSION-slim AS base\n")})
	if d.Version != "3.3.6" || !strings.Contains(d.VersionSource, "Dockerfile") || findVuln(d, Ruby2ShellID) == nil {
		t.Fatalf("Dockerfile version: %q via %q %v", d.Version, d.VersionSource, vulnIDs(d))
	}
	d = deep(resp(200, nil, "x"), map[string]*probe.Response{"http://h/.rubocop.yml": resp(200, nil, "AllCops:\n  TargetRubyVersion: 3.1\n")})
	if d.Version != "" || d.Branch != "3.1" {
		t.Fatalf("rubocop branch: %q %q", d.Version, d.Branch)
	}
	if v := findVuln(d, Ruby2ShellID); v == nil || v.Severity != "critical" {
		t.Errorf("3.1 branch is wholly affected: %+v", v)
	}
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, map[string]string{"X-Ruby-Version": "3.4.13", "X-Rails-Version": "7.2.2.2", "X-Rack-Version": "3.1.14"}, "")})
	if d.Version != "3.4.13" || d.FrameworkVersions["Rails"] != "7.2.2.2" || d.FrameworkVersions["Rack"] != "3.1.14" {
		t.Fatalf("version headers: %q %v", d.Version, d.FrameworkVersions)
	}
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(500, nil, "truffleruby 23.1.0, like ruby 3.2.2, GraalVM CE Native [x86_64-linux]")})
	if d.Variant != "TruffleRuby" || d.Version != "3.2.2" || len(d.Vulnerabilities) != 0 {
		t.Fatalf("truffleruby: %q %q %v", d.Variant, d.Version, vulnIDs(d))
	}
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(500, nil, "Your Ruby version is 3.1.2, but your Gemfile specified 3.2.0")})
	if d.Version != "3.1.2" {
		t.Fatalf("bundler mismatch version: %q", d.Version)
	}
}

func TestDeepBehaviouralProbes(t *testing.T) {
	root := resp(200, nil, "<html>home</html>")
	ctrl := resp(404, map[string]string{"Content-Type": "text/html"}, strings.Repeat("x", 500))
	json404 := resp(404, map[string]string{"Content-Type": "application/json; charset=UTF-8"}, `{"status":404,"error":"Not Found"}`)
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, Control: ctrl, JSONErrorProbe: json404})
	if !hasSignal(d, "behavior.rails-json-error") || !hasSignal(d, "body.rails-json-error") || !d.IsRuby {
		t.Fatalf("JSON error probe: %v", signals(d))
	}
	// An API that always answers JSON 404s is not switching format.
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, Control: json404, JSONErrorProbe: json404})
	if hasSignal(d, "behavior.rails-json-error") {
		t.Error("format switch needs an HTML baseline")
	}

	asset := resp(404, map[string]string{"Content-Type": "text/plain"}, "Not found")
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, Control: ctrl, AssetProbe: asset})
	if !hasSignal(d, "behavior.asset-server-not-found") {
		t.Fatalf("asset probe: %v", signals(d))
	}
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, Control: asset, AssetProbe: asset})
	if hasSignal(d, "behavior.asset-server-not-found") {
		t.Error("asset probe must differ from the baseline")
	}

	d = deep(root, map[string]*probe.Response{
		"http://h/cable":                      resp(404, map[string]string{"Content-Type": "text/plain; charset=utf-8"}, "Page not found"),
		"http://h/__sinatra__/404.png":        resp(200, map[string]string{"Content-Type": "image/png"}, "\x89PNG"),
		"http://h/manifest.json":              resp(200, nil, `{"name": "App","icons":[{"src": "/icon.png"}],"theme_color": "red"}`),
		"http://h/config/credentials.yml.enc": resp(200, nil, "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0--aXZpdml2aXZpdml2--dGFndGFndGFndGFndGFndGFn\n"),
		"http://h/assets/application-abc.js":  resp(200, nil, `import"@rails/ujs";ActionCable.createConsumer()`),
	})
	for _, sig := range []string{"diag.action-cable", "diag.sinatra-dev-image", "diag.rails-pwa-manifest", "diag.credentials-enc", "body.asset-js-cable"} {
		if !hasSignal(d, sig) {
			t.Errorf("missing %s in %v", sig, signals(d))
		}
	}
	for _, e := range d.Evidence {
		if strings.Contains(e.Data+e.Snippet, "c2VjcmV0") {
			t.Error("encrypted credentials content copied into evidence")
		}
	}
}

func TestRailsVersionHint(t *testing.T) {
	root := resp(200, map[string]string{
		"X-Permitted-Cross-Domain-Policies": "none", "Referrer-Policy": "strict-origin-when-cross-origin", "X-XSS-Protection": "0",
	}, `<meta name="csrf-param" content="authenticity_token" />`)
	d := deep(root, map[string]*probe.Response{"http://h/icon.svg": resp(200, nil, `<svg><circle cx="256" cy="256" r="256" fill="red"/></svg>`)})
	if !strings.HasPrefix(d.RailsVersionHint, "7.2 or later") {
		t.Fatalf("hint = %q", d.RailsVersionHint)
	}
	old := resp(200, nil, `<input name="utf8" type="hidden" value="&#x2713;" /><input type="hidden" name="authenticity_token" value="x">`,
		&http.Cookie{Name: "_app_session", Value: "0e9jNxCOwgeSJTrnzi4dzqtnedf5EclPNiyYLEN4%3D--Csa3Bwa%2Bdq8HuJvj--by1Ey7DCFV7sugGXV%2Fiy6A%3D%3D"})
	d = Analyze(Input{TargetURL: "http://h/", Root: old})
	if !strings.Contains(d.RailsVersionHint, "5.2 or later, before 6.0") {
		t.Fatalf("hint = %q", d.RailsVersionHint)
	}
	// An exact version makes the hint redundant.
	d = Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Rails-Version": "7.1.3"}, `<meta name="csrf-param" content="authenticity_token" />`)})
	if d.RailsVersionHint != "" {
		t.Errorf("hint should be empty when the version is known: %q", d.RailsVersionHint)
	}
	var h railsHint
	h.atLeast("7.0", "a")
	h.atLeast("6.0", "b")
	h.below("8.0", "c")
	h.below("9.0", "d")
	if h.min != "7.0" || h.max != "8.0" {
		t.Errorf("bounds: %+v", h)
	}
}

func TestAssetCandidates(t *testing.T) {
	page := resp(200, nil, `<script src="/assets/vendor-aaa.js"></script><script src="/assets/application-bbb.js"></script>
<script src="https://cdn.example/x.js"></script><link href="/assets/application-ccc.css"><script src="/packs/js/main-ddd.js"></script><script src="/assets/../etc.js"></script>`)
	got := AssetCandidates(page, 2)
	if len(got) != 2 || got[0] != "/assets/application-bbb.js" || got[1] != "/packs/js/main-ddd.js" {
		t.Fatalf("candidates = %v", got)
	}
	if AssetCandidates(nil, 2) != nil || AssetCandidates(page, 0) != nil {
		t.Error("nil / zero guards")
	}
}

func TestRackETagDigest(t *testing.T) {
	body := "<html><body>hello</body></html>"
	// sha256(body)[:32], as Rack::ETag >= 2.1 computes it.
	r := resp(200, map[string]string{"ETag": `W/"` + sha256Prefix(body) + `"`}, body)
	d := Analyze(Input{TargetURL: "http://h/", Root: r})
	if !hasSignal(d, "header.rack-etag-digest") || !d.IsRuby || !hasStr(d.Frameworks, "Rack") {
		t.Fatalf("Rack::ETag digest not recognised: %v", signals(d))
	}
	// A 32-hex ETag that is not the body digest proves nothing.
	r = resp(200, map[string]string{"ETag": `"0123456789abcdef0123456789abcdef"`}, body)
	if d := Analyze(Input{TargetURL: "http://h/", Root: r}); hasSignal(d, "header.rack-etag-digest") {
		t.Error("unrelated ETag matched")
	}
}

func TestCSRFTokenFormat(t *testing.T) {
	urlsafe := strings.Repeat("aB3_-xYz", 10) + "abcdef" // 86 chars
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, `<meta name="csrf-param" content="authenticity_token" /><meta name="csrf-token" content="`+urlsafe+`" />`)})
	if !hasSignal(d, "body.rails-csrf-token-format") || !strings.Contains(d.RailsVersionHint, "6.1 or later") {
		t.Fatalf("86-char token: %v hint=%q", signals(d), d.RailsVersionHint)
	}
	padded := strings.Repeat("aB3+/xYz", 10) + "abcdef=="
	d = Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, `<meta name="csrf-token" content="`+padded+`" />`)})
	if !hasSignal(d, "body.rails-csrf-token-format") || !strings.Contains(d.RailsVersionHint, "before 6.1") {
		t.Fatalf("88-char token: %v hint=%q", signals(d), d.RailsVersionHint)
	}
	// Laravel's 40-character token is not a Rails masked token.
	d = Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, `<meta name="csrf-token" content="`+strings.Repeat("a1", 20)+`">`)})
	if d.Confidence != 0 {
		t.Errorf("Laravel-style token matched: %v", signals(d))
	}
}

func TestSignedCookiePayloads(t *testing.T) {
	mac := "--0123456789abcdef0123456789abcdef01234567"
	cases := map[string]string{
		// {"_rails":{"message":"IjEi","exp":null,"pur":"cookie.x"}}
		"eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqRWkiLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS54In19": "cookie.rails-envelope",
		// {"session_id":"abc","_csrf_token":"def"}
		"eyJzZXNzaW9uX2lkIjoiYWJjIiwiX2NzcmZfdG9rZW4iOiJkZWYifQ==": "cookie.rails-json-session",
		// c2VjcmV0ZGF0YXNlY3JldGRhdGE=--aXZpdml2aXZpdml2aXY=
		"YzJWamNtVjBaR0YwWVhObFkzSmxkR1JoZEdFPS0tYVhacGRtbDJhWFpwZG1sMmFYWT0=": "cookie.rails-cbc-encrypted",
	}
	for payload, want := range cases {
		d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, "", &http.Cookie{Name: "c", Value: payload + mac})})
		if !hasSignal(d, want) {
			t.Errorf("want %s, got %v", want, signals(d))
		}
		for _, e := range d.Evidence {
			if strings.Contains(e.Data+e.Snippet, payload[:20]) {
				t.Errorf("cookie payload copied into evidence for %s", want)
			}
		}
	}
}

func TestFormatProbeAndRobots(t *testing.T) {
	root := resp(200, nil, "<html>home</html>")
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, FormatProbe: resp(406, nil, "")})
	if !hasSignal(d, "behavior.rails-format-406") {
		t.Fatalf("format probe: %v", signals(d))
	}
	d = Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, FormatProbe: resp(406, nil, ""), Control: resp(406, nil, "")})
	if hasSignal(d, "behavior.rails-format-406") {
		t.Error("a server that 406s unknown paths is no signal")
	}
	for body, fw := range map[string]string{
		"User-Agent: *\nDisallow: /autocomplete/users\nDisallow: /autocomplete/projects\n":       "GitLab",
		"User-agent: *\nDisallow: /issues/gantt\nDisallow: /issues/calendar\n":                   "Redmine",
		"User-agent: *\nDisallow: /projects/*/repository\nDisallow: /projects/*/work_packages\n": "OpenProject",
	} {
		d := deep(root, map[string]*probe.Response{"http://h/robots.txt": resp(200, nil, body)})
		if !hasStr(d.Frameworks, fw) {
			t.Errorf("robots.txt for %s not recognised: %v", fw, d.Frameworks)
		}
	}
}

// Static hosts (S3, Vercel) use the body's MD5 as ETag; observed on a
// Vercel-served site. That must not be mistaken for Rack::ETag.
func TestMD5ETagIsNotRack(t *testing.T) {
	body := "<html><body>static</body></html>"
	sum := md5.Sum([]byte(body))
	r := resp(200, map[string]string{"ETag": `"` + hex.EncodeToString(sum[:]) + `"`, "Server": "Vercel"}, body)
	if d := Analyze(Input{TargetURL: "http://h/", Root: r}); d.Confidence != 0 {
		t.Fatalf("MD5 ETag scored %d: %v", d.Confidence, signals(d))
	}
}
