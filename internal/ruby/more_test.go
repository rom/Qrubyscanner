package ruby

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/qrubyscanner/internal/probe"
)

func deep(root *probe.Response, extra map[string]*probe.Response) *Detection {
	return Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, Extra: extra})
}

func TestApplicationEndpoints(t *testing.T) {
	// GitLab: API answers 401 without a token; /help may disclose the version.
	d := deep(resp(200, nil, `<meta content="GitLab" property="og:site_name">`, &http.Cookie{Name: "_gitlab_session", Value: "x"}),
		map[string]*probe.Response{
			"http://h/api/v4/version": resp(401, nil, `{"message":"401 Unauthorized"}`),
			"http://h/help":           resp(200, nil, `<h1>GitLab Community Edition <span>13.10.2</span></h1>`),
		})
	if !hasSignal(d, "diag.gitlab-api") || d.FrameworkVersions["GitLab"] != "13.10.2" {
		t.Fatalf("gitlab: %v %v", d.FrameworkVersions, d.Evidence)
	}
	ids := strings.Join(vulnIDs(d), ",")
	if !strings.Contains(ids, "CVE-2021-22205") || !strings.Contains(ids, Ruby2ShellID) {
		t.Errorf("gitlab 13.10.2 leads: %s", ids)
	}
	d = deep(resp(200, nil, "x"), map[string]*probe.Response{
		"http://h/api/v4/version": resp(200, nil, `{"version":"17.1.0-ee","revision":"abc"}`)})
	if d.FrameworkVersions["GitLab"] != "17.1.0" {
		t.Errorf("gitlab api version: %v", d.FrameworkVersions)
	}

	d = deep(resp(200, nil, `<script>window.chatwootConfig = {}</script>`), map[string]*probe.Response{
		"http://h/api": resp(200, nil, `{"version":"3.5.2","timestamp":"t","queue_services":"ok","data_services":"ok"}`)})
	if d.FrameworkVersions["Chatwoot"] != "3.5.2" || !d.IsRuby {
		t.Errorf("chatwoot: %v", d.FrameworkVersions)
	}

	d = deep(resp(200, map[string]string{"X-GitHub-Request-Id": "1"}, "x"), map[string]*probe.Response{
		"http://h/api/v3/meta": resp(200, nil, `{"verifiable_password_authentication":true,"installed_version":"3.12.1"}`)})
	if d.FrameworkVersions["GitHub Enterprise Server"] != "3.12.1" {
		t.Errorf("ghes: %v", d.FrameworkVersions)
	}

	d = deep(resp(200, map[string]string{"Foreman_api_version": "2"}, "x"), map[string]*probe.Response{
		"http://h/api/status": resp(200, nil, `{"result":"ok","status":200,"version":"3.5.1","api_version":2}`)})
	if d.FrameworkVersions["Foreman"] != "3.5.1" {
		t.Errorf("foreman: %v", d.FrameworkVersions)
	}

	d = deep(resp(200, nil, `<meta name="generator" content="Discourse 3.2.0.beta2 - https://github.com/discourse/discourse version abc">`), nil)
	if d.FrameworkVersions["Discourse"] != "3.2.0.beta2" || !hasStr(d.Frameworks, "Discourse") {
		t.Errorf("discourse: %v %v", d.FrameworkVersions, d.Frameworks)
	}
	if findVuln(d, Ruby2ShellID) == nil {
		t.Error("discourse 3.2 bundles an affected Ruby")
	}
}

func TestExposureProbes(t *testing.T) {
	root := resp(200, map[string]string{"X-Runtime": "0.010000"}, `<meta name="csrf-param" content="authenticity_token" />`)
	d := deep(root, map[string]*probe.Response{
		"http://h/rails/info/routes":                             resp(200, nil, `<table id="route_table"><th>Controller#Action</th></table>`),
		"http://h/rails/mailers":                                 resp(200, nil, `<h1>Mailer Previews</h1>`),
		"http://h/rails/conductor/action_mailbox/inbound_emails": resp(200, nil, `<title>Rails Conductor</title>`),
		"http://h/up":                  resp(200, nil, `<!DOCTYPE html><html><body style="background-color: green"></body></html>`),
		"http://h/config.ru":           resp(200, nil, "require_relative \"config/environment\"\nrun Rails.application\n"),
		"http://h/Rakefile":            resp(200, nil, "require_relative \"config/application\"\nRails.application.load_tasks\n"),
		"http://h/packs/manifest.json": resp(200, nil, `{"application.js":"/packs/js/application-abc.js","entrypoints":{}}`),
		"http://h/sidekiq":             resp(200, nil, `<title>Sidekiq</title><span class="version">Sidekiq v6.3.1</span>`),
		"http://h/.env":                resp(200, nil, "DB_PASSWORD=x\n"),
		"http://h/admin":               resp(200, nil, `<body class="active_admin logged_out">`),
	})
	for _, sig := range []string{"diag.rails-routes", "diag.rails-mailers", "diag.rails-conductor", "diag.rails-health",
		"diag.config-ru", "diag.rakefile", "diag.webpacker-manifest", "diag.dotenv-generic", "body.sidekiq-web", "body.active-admin"} {
		if !hasSignal(d, sig) {
			t.Errorf("missing %s", sig)
		}
	}
	if d.RailsEnv != "development" {
		t.Errorf("env = %q", d.RailsEnv)
	}
	if !hasStr(d.Addons, "Sidekiq Web") || !hasStr(d.Addons, "ActiveAdmin") || d.FrameworkVersions["Sidekiq"] != "6.3.1" {
		t.Errorf("addons %v versions %v", d.Addons, d.FrameworkVersions)
	}
	if findVuln(d, "CVE-2022-23837") == nil {
		t.Errorf("sidekiq 6.3.1 lead missing: %v", vulnIDs(d))
	}

	d = deep(resp(200, nil, "x"), map[string]*probe.Response{
		"http://h/.ruby-version": resp(200, nil, "jruby-9.4.5.0\n"),
		"http://h/config.ru":     resp(200, nil, "require './app'\nrun Sinatra::Application\n"),
	})
	if d.Variant != "JRuby" || !hasStr(d.Frameworks, "Sinatra") {
		t.Errorf("jruby/sinatra: %q %v", d.Variant, d.Frameworks)
	}
	// HTML served for a dotfile path is not that dotfile.
	d = deep(resp(200, nil, "x"), map[string]*probe.Response{
		"http://h/.ruby-version":       resp(200, nil, "<html>3.3.1</html>"),
		"http://h/.env":                resp(200, nil, "<html>RAILS_ENV=</html>"),
		"http://h/config/database.yml": resp(200, nil, "<!DOCTYPE html>adapter: x"),
	})
	if d.Version != "" || hasSignal(d, "diag.dotenv") || hasSignal(d, "diag.database-yml") {
		t.Errorf("HTML mistaken for a project file: %+v", d.Evidence)
	}
}

func TestSmallHelpers(t *testing.T) {
	for in, want := range map[string]string{"Ruby on Rails": "Rails", "Spree Commerce": "Spree", "diaspora": "diaspora*", "Phusion Passenger": "", " Redmine ": "Redmine"} {
		if got := canonicalApp(in); got != want {
			t.Errorf("canonicalApp(%q)=%q", in, got)
		}
	}
	for in, want := range map[string]string{"Diaspora 0.7": "diaspora*", "Decidim 0.27": "Decidim", "Publify": "Publify", "Refinery CMS": "Refinery CMS",
		"Alchemy CMS": "Alchemy CMS", "Camaleon CMS": "Camaleon CMS", "Redmine": "Redmine", "WordPress": ""} {
		if got := frameworkFromGenerator(in); got != want {
			t.Errorf("frameworkFromGenerator(%q)=%q", in, got)
		}
	}
	if promotedOr("puma") != "Puma" || promotedOr("zzz") != "zzz" {
		t.Error("promotedOr")
	}
	if pathOf("::bad") == "" || pathOf("/x?y#z") != "/x" {
		t.Error("pathOf fallbacks")
	}
	if mediaType("Text/HTML; charset=utf-8") != "text/html" || mediaType("a/b") != "a/b" {
		t.Error("mediaType")
	}
	for _, sig := range []string{"header.x", "stack.p", "cookie.x", "diag.x", "behavior.x", "component.version.x", "url.x", "favicon.x", "body.x"} {
		if w, h := provenanceDefaults(sig); w == "" || h == "" {
			t.Errorf("provenance %s", sig)
		}
	}
	c := controlSignature(resp(200, map[string]string{"Content-Type": "text/html"}, "0123456789"))
	if c.matches(nil) || c.matches(resp(404, nil, "0123456789")) || c.matches(resp(200, map[string]string{"Content-Type": "application/json"}, "0123456789")) ||
		c.matches(resp(200, nil, strings.Repeat("x", 50))) || !c.matches(resp(200, nil, "012345678")) {
		t.Error("control signature matching")
	}
	if e := controlSignature(resp(204, nil, "")); !e.matches(resp(204, nil, "")) {
		t.Error("empty bodies with equal status should match")
	}
	if (ctrlSig{}).matches(resp(200, nil, "")) {
		t.Error("absent baseline never matches")
	}
	if !sensitivePath("http://h/config/master.key") || sensitivePath("http://h/index.html") {
		t.Error("sensitivePath")
	}
	if clampLen("abcdef", 3) != "abc…" {
		t.Error("clampLen")
	}
}

const csafDocJSON = `{
  "document":{"title":"Example advisory","tracking":{"id":"EX-2026-01"}},
  "product_tree":{"branches":[
    {"category":"vendor","name":"Example","branches":[
      {"category":"product_name","name":"Sinatra","branches":[
        {"category":"product_version","name":"3.0.0","product":{"name":"Sinatra 3.0.0","product_id":"PID-1"}},
        {"category":"product_version_range","name":"vers:gem/>=2.0.0|<2.2.3","product":{"name":"Sinatra 2.x","product_id":"PID-2"}}
      ]}
    ]}
  ]},
  "vulnerabilities":[{"cve":"CVE-2099-9999","title":"RCE in Example",
    "scores":[{"cvss_v3":{"baseSeverity":"CRITICAL","baseScore":9.8}}],
    "product_status":{"known_affected":["PID-1","PID-2"]},
    "references":[{"url":"https://example/csaf"}]}]
}`

func TestConvertCSAF(t *testing.T) {
	f, err := ParseFeed([]byte(csafDocJSON))
	if err != nil {
		t.Fatal(err)
	}
	entries := f.CMS["sinatra"]
	if len(entries) != 1 || entries[0].ID != "CVE-2099-9999" || entries[0].Severity != "critical" {
		t.Fatalf("csaf entries: %+v", f.CMS)
	}
	cat := &Catalog{cms: map[string][]FeedEntry{}, eol: map[string]string{}}
	cat.Merge(f)
	for v, want := range map[string]bool{"3.0.0": true, "3.0.1": false, "2.1.0": true, "2.2.3": false} {
		if got := len(cat.CorrelateCMS("Sinatra", v)) > 0; got != want {
			t.Errorf("sinatra %s: got %v want %v", v, got, want)
		}
	}
	for score, want := range map[float64]string{9.5: "critical", 7.5: "high", 5.0: "medium", 1.0: "low", 0: "unknown"} {
		if got := scoreToSeverity(score); got != want {
			t.Errorf("scoreToSeverity(%v)=%q", score, got)
		}
	}
	if r := parseComparatorRange("<=1.2.3 >1.0.0"); r.LessThan != "1.2.4" || r.Introduced != "1.0.1" {
		t.Errorf("comparator range: %+v", r)
	}
	if versionFromName("Rails v7.1.2") != "7.1.2" || versionFromName("none") != "" {
		t.Error("versionFromName")
	}
}

func TestOSVVariants(t *testing.T) {
	osv := `[{"id":"CVE-2099-1","summary":"core","affected":[{"package":{"ecosystem":"","name":"ruby"},
	  "ranges":[{"type":"SEMVER","events":[{"introduced":"3.3.0"},{"last_affected":"3.3.5"}]}],"versions":["3.2.1"]}],
	  "references":[{"type":"WEB","url":"https://w"},{"type":"ADVISORY","url":"https://a"}],"database_specific":{"severity":"MODERATE"}},
	 {"id":"GHSA-none","details":"no ranges","affected":[{"package":{"ecosystem":"RubyGems","name":"x"}}]}]`
	f, err := ParseFeed([]byte(osv))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Ruby) != 1 {
		t.Fatalf("ruby-core OSV entries: %+v", f)
	}
	c := &Catalog{}
	c.Merge(f)
	if len(c.CorrelateRuby("Ruby", "3.3.5")) != 1 || len(c.CorrelateRuby("Ruby", "3.3.6")) != 0 || len(c.CorrelateRuby("Ruby", "3.2.1")) != 1 {
		t.Errorf("OSV ranges: %+v", f.Ruby[0].Affected)
	}
	if c.CorrelateRuby("Ruby", "") != nil || c.CorrelateRuby("Ruby", "zz") != nil || c.CorrelateRuby("JRuby", "3.3.5") != nil {
		t.Error("guards")
	}
}

func TestLoadCataloguesOverHTTP(t *testing.T) {
	fav := `{"schema":"qrubyscanner-favicon-catalog/1","favicons":[{"hash":"42","product":"P","framework":"P","ruby":true},{"hash":"","product":"skip"}]}`
	pack := `{"id":"http-pack","version":"2","headers":[{"header":"X-Http-Pack","weight":10}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fav":
			_, _ = w.Write([]byte(fav))
		case "/pack":
			_, _ = w.Write([]byte(pack))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	ctx := context.Background()
	if n, err := LoadFaviconCatalog(ctx, ts.URL+"/fav", ts.Client()); err != nil || n == 0 {
		t.Fatalf("favicon over http: %d %v", n, err)
	}
	if _, err := LoadFaviconCatalog(ctx, ts.URL+"/missing", ts.Client()); err == nil || err.Error() == "" {
		t.Error("404 favicon catalogue accepted")
	}
	p := filepath.Join(t.TempDir(), "fav.json")
	_ = os.WriteFile(p, []byte(fav), 0o644)
	if _, err := LoadFaviconCatalog(ctx, p, nil); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p, []byte(`{"schema":"bad"}`), 0o644)
	if _, err := LoadFaviconCatalog(ctx, p, nil); err == nil || err.Error() == "" {
		t.Error("bad favicon schema accepted")
	}
	if _, err := LoadFaviconCatalog(ctx, p+".nope", nil); err == nil {
		t.Error("missing favicon file accepted")
	}
	if n, err := LoadSignaturePack(ctx, ts.URL+"/pack", ts.Client()); err != nil || n != 1 {
		t.Fatalf("pack over http: %d %v", n, err)
	}
	if _, err := LoadSignaturePack(ctx, ts.URL+"/missing", ts.Client()); err == nil || err.Error() == "" {
		t.Error("404 pack accepted")
	}
}
