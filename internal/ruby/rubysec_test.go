package ruby

import (
	"strings"
	"testing"
)

// These pin a handful of well-known advisories against the catalogue generated
// from the RubySec database, including the fixed versions on each branch.
func TestRubySecCatalogue(t *testing.T) {
	c := DefaultCatalog()
	type row struct {
		component, version, id string
		want                   bool
	}
	for _, r := range []row{
		{"Rails", "5.2.2", "CVE-2019-5418", true}, {"Rails", "5.2.2.1", "CVE-2019-5418", false},
		{"Rails", "6.0.3", "CVE-2020-8165", true}, {"Rails", "6.0.3.1", "CVE-2020-8165", false},
		{"Rails", "7.0.3", "CVE-2022-32224", true}, {"Rails", "7.0.3.1", "CVE-2022-32224", false},
		{"Rails", "3.2.10", "CVE-2013-0156", true}, {"Rails", "3.2.11", "CVE-2013-0156", false},
		// filed under both actionpack and actionview upstream: ranges are unioned
		{"Rails", "4.2.5", "CVE-2016-0752", true}, {"Rails", "4.2.5.1", "CVE-2016-0752", false},
		// upstream typo "< 5.20" corrected to "< 5.2.0"
		{"Rails", "6.1.7", "CVE-2025-24293", true}, {"Rails", "5.2.8", "CVE-2025-24293", true}, {"Rails", "5.1.7", "CVE-2025-24293", false},
		{"Rack", "2.2.12", "CVE-2025-27610", true}, {"Rack", "2.2.13", "CVE-2025-27610", false}, {"Rack", "3.1.11", "CVE-2025-27610", true},
		{"Puma", "6.4.1", "CVE-2024-21647", true}, {"Puma", "6.4.2", "CVE-2024-21647", false},
		{"Sinatra", "2.1.0", "CVE-2022-29970", true}, {"Sinatra", "2.2.0", "CVE-2022-29970", false},
		{"Phusion Passenger", "5.3.1", "CVE-2018-12029", true}, {"Phusion Passenger", "5.3.2", "CVE-2018-12029", false},
		{"GitLab", "16.7.1", "CVE-2023-7028", true}, {"GitLab", "16.7.2", "CVE-2023-7028", false},
		{"GitLab", "16.0.0", "CVE-2023-2825", true}, {"GitLab", "16.0.1", "CVE-2023-2825", false},
		{"Mastodon", "4.2.6", "CVE-2024-25623", true}, {"Mastodon", "4.2.7", "CVE-2024-25623", false},
		{"GitHub Enterprise Server", "3.12.3", "CVE-2024-4985", true}, {"GitHub Enterprise Server", "3.12.4", "CVE-2024-4985", false},
	} {
		got := strings.Contains(ids(c.CorrelateCMS(r.component, r.version)), r.id)
		if got != r.want {
			t.Errorf("%s %s: %s flagged=%v, want %v", r.component, r.version, r.id, got, r.want)
		}
	}
	for _, r := range []row{
		{"nokogiri", "1.13.3", "CVE-2022-24836", true}, {"nokogiri", "1.13.4", "CVE-2022-24836", false},
		{"devise", "4.5.0", "CVE-2019-5421", true}, {"devise", "4.6.0", "CVE-2019-5421", false},
		{"ruby-saml", "1.16.0", "CVE-2024-45409", true}, {"ruby-saml", "1.17.0", "CVE-2024-45409", false},
		{"rexml", "3.3.8", "CVE-2024-49761", true}, {"rexml", "3.3.9", "CVE-2024-49761", false},
	} {
		got := strings.Contains(ids(c.CorrelatePackage(r.component, r.version)), r.id)
		if got != r.want {
			t.Errorf("gem %s %s: %s flagged=%v, want %v", r.component, r.version, r.id, got, r.want)
		}
	}
	// Ruby core, including patch-level versions.
	for v, want := range map[string]bool{"3.3.0": true, "3.3.1": false, "3.2.3": true, "3.2.4": false, "2.7.8": true} {
		got := strings.Contains(ids(c.CorrelateRuby("Ruby", v)), "CVE-2024-27282")
		if got != want {
			t.Errorf("Ruby %s: CVE-2024-27282 flagged=%v want %v", v, got, want)
		}
	}
	if !strings.Contains(ids(c.CorrelateRuby("Ruby", "2.0.0p353")), "CVE-2014-8080") || strings.Contains(ids(c.CorrelateRuby("Ruby", "2.0.0p594")), "CVE-2014-8080") {
		t.Error("patch-level range for CVE-2014-8080")
	}
	// Curated prerequisites survive the merge with generated ranges.
	for _, v := range c.CorrelateCMS("Rails", "5.2.2", ObservedFacts{Env: "production"}) {
		if v.ID == "CVE-2019-5420" && v.Applicability != "contradicted" {
			t.Errorf("CVE-2019-5420 prerequisite lost: %+v", v)
		}
	}
	if RubySecRevision == "" {
		t.Error("revision missing")
	}
	ruby, rest := c.Counts()
	if ruby < 90 || rest < 1300 {
		t.Errorf("catalogue smaller than expected: %d ruby, %d component/gem", ruby, rest)
	}
	// JRuby has its own advisories and is not checked against CRuby's.
	if len(c.CorrelateCMS("JRuby", "1.7.0")) == 0 {
		t.Error("JRuby advisories missing")
	}
}

func TestOverlay(t *testing.T) {
	gen := []FeedEntry{{ID: "A", Affected: []RangeSpec{lo("2.0")}}}
	cur := []FeedEntry{{ID: "A", Note: "n", Affected: []RangeSpec{lo("9.0")}, Prereqs: []Prereq{{Kind: "env", Want: "development"}}, AlertUnknownVersion: true}, {ID: "B"}}
	out := overlay(gen, cur)
	if len(out) != 2 || out[0].Affected[0].LessThan != "2.0" || len(out[0].Prereqs) != 1 || !out[0].AlertUnknownVersion || out[0].Note != "n" || out[1].ID != "B" {
		t.Fatalf("overlay: %+v", out)
	}
}
