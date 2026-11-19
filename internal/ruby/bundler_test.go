package ruby

import (
	"strings"
	"testing"

	"github.com/rom/qrubyscanner/internal/probe"
)

const sampleLock = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (6.1.4)
      rack (~> 2.0, >= 2.0.9)
    devise (4.5.0)
    nokogiri (1.13.0-x86_64-linux)
    puma (5.6.2)
    rack (2.2.3)
    rails (6.1.4)
    ruby-saml (1.16.0)
    sidekiq (6.3.1)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails (~> 6.1.4)

RUBY VERSION
   ruby 3.0.2p107

BUNDLED WITH
   2.2.22
`

const sampleGemfile = `source "https://rubygems.org"
ruby "3.0.2"
gem "rails", "~> 6.1.4"
gem 'puma'
gem "sinatra", ">= 2.0"
`

func TestClassifyBundler(t *testing.T) {
	if classifyBundler(sampleLock) != "lock" || classifyBundler(sampleGemfile) != "gemfile" || classifyBundler("<html>gem 'x'</html>") != "" || classifyBundler("") != "" {
		t.Fatal("classification")
	}
}

func TestBuildInventory(t *testing.T) {
	inv := buildBundlerInventory(sampleGemfile, sampleLock)
	if inv == nil || inv.RubyRequire != "3.0.2" || inv.RubyLocked != "ruby 3.0.2p107" || inv.BundledWith != "2.2.22" {
		t.Fatalf("inventory header: %+v", inv)
	}
	if len(inv.Platforms) != 1 || inv.gemVersion("rails") != "6.1.4" || inv.gemVersion("rack") != "2.2.3" {
		t.Fatalf("gems: %+v", inv.Gems)
	}
	// A Gemfile-only gem keeps its constraint and is not "concrete".
	if inv.gemVersion("sinatra") != "" {
		t.Error("constraint must not be treated as a version")
	}
	// Nested dependency lines (6 spaces) are not specs.
	n := 0
	for _, g := range inv.Gems {
		if g.Name == "rack" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("rack listed %d times", n)
	}
	if buildBundlerInventory("", "") != nil || buildBundlerInventory("nope", "nope") != nil {
		t.Error("empty inventory should be nil")
	}
	if v, variant := lockedRubyVersion("ruby 3.1.4p0 (jruby 9.4.5.0)"); v != "3.1.4p0" || variant != "JRuby" {
		t.Errorf("jruby lock: %s %s", v, variant)
	}
	if _, variant := lockedRubyVersion("truffleruby 23.1.0"); variant != "TruffleRuby" {
		t.Error("truffleruby lock")
	}
}

func TestExposedLockfileDrivesCorrelation(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: resp(200, nil, "x"),
		Extra: map[string]*probe.Response{"http://h/Gemfile.lock": resp(200, nil, sampleLock), "http://h/Gemfile": resp(200, nil, sampleGemfile)}})
	if !d.IsRuby || !hasSignal(d, "diag.gemfile-lock") || !hasSignal(d, "diag.gemfile") {
		t.Fatalf("lockfile exposure not detected: %+v", d.Evidence)
	}
	if d.Version != "3.0.2p107" && d.Version != "3.0.2" {
		t.Fatalf("version from lock: %q", d.Version)
	}
	if d.FrameworkVersions["Rails"] != "6.1.4" || d.FrameworkVersions["Rack"] != "2.2.3" || d.FrameworkVersions["Puma"] != "5.6.2" {
		t.Fatalf("component versions: %v", d.FrameworkVersions)
	}
	all := strings.Join(vulnIDs(d), ",")
	for _, want := range []string{Ruby2ShellID, "CVE-2022-32224", "CVE-2022-30123", "CVE-2022-24790", "CVE-2022-23837"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %s in %s", want, all)
		}
	}
	if !strings.Contains(d.AppServer, "Puma") {
		t.Errorf("app server from lock: %q", d.AppServer)
	}
	byGem := map[string]BundlerGem{}
	for _, g := range d.Bundler.Gems {
		byGem[g.Name] = g
	}
	has := func(g BundlerGem, id string) bool {
		for _, v := range g.Vulnerabilities {
			if v.ID == id {
				return true
			}
		}
		return false
	}
	if !has(byGem["ruby-saml"], "CVE-2024-45409") || !has(byGem["ruby-saml"], "CVE-2025-25291") || !has(byGem["devise"], "CVE-2019-5421") {
		t.Errorf("gem-level leads missing: saml=%d devise=%d", len(byGem["ruby-saml"].Vulnerabilities), len(byGem["devise"].Vulnerabilities))
	}
	// nokogiri is locked with a platform suffix ("1.13.0-x86_64-linux").
	if !has(byGem["nokogiri"], "CVE-2022-24836") {
		t.Errorf("nokogiri 1.13.0 should carry CVE-2022-24836: %d leads", len(byGem["nokogiri"].Vulnerabilities))
	}
	// Promoted components are correlated at the top level only.
	if len(byGem["rails"].Vulnerabilities)+len(byGem["rack"].Vulnerabilities)+len(byGem["actionpack"].Vulnerabilities)+len(byGem["puma"].Vulnerabilities) != 0 {
		t.Error("promoted gems must not be double-counted in the inventory")
	}
}

func TestOperatorSuppliedLockfile(t *testing.T) {
	root := resp(200, map[string]string{"X-Runtime": "0.010000"}, `<meta name="csrf-param" content="authenticity_token" />`)
	d := Analyze(Input{TargetURL: "http://h/", Deep: true, Root: root, BundlerFiles: [][]byte{[]byte(sampleLock)}})
	if d.Bundler == nil || d.FrameworkVersions["Rails"] != "6.1.4" {
		t.Fatalf("operator lockfile ignored: %+v", d.FrameworkVersions)
	}
	if v := findVuln(d, Ruby2ShellID); v == nil || v.Severity != "critical" {
		t.Fatalf("lock-time Ruby 3.0.2 should flag Ruby2Shell: %+v", v)
	}
}

func TestRailsInfoParser(t *testing.T) {
	if !isRailsInfo(railsInfoPage) || isRailsInfo("") || isRailsInfo("Rails version only") {
		t.Fatal("isRailsInfo")
	}
	if parseRailsInfo("<p>nothing</p>") != nil {
		t.Error("no rows should be nil")
	}
	for in, want := range map[string]string{
		"ruby 3.1.2p20 (2022-04-12 revision 4491bb740a) [x86_64-linux]": "3.1.2p20",
		"2.7.6-p219 (x86_64-linux)":                                     "2.7.6p219",
		"3.3.0":                                                         "3.3.0",
		"n/a":                                                           "",
	} {
		if got := rubyVersionFromDescription(in); got != want {
			t.Errorf("rubyVersionFromDescription(%q)=%q want %q", in, got, want)
		}
	}
	if railsInfoObservations(nil) != nil {
		t.Error("nil facts")
	}
}
