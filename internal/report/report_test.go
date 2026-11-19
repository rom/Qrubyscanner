package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rom/qrubyscanner/internal/ruby"
	"github.com/rom/qrubyscanner/internal/scanner"
)

func sampleResult() *scanner.ScanResult {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &scanner.ScanResult{
		Meta: scanner.Meta{
			Tool: "qrubyscanner", Version: "0.1.0", Mode: "deep",
			StartedAt: now, FinishedAt: now, Ports: []int{80, 443},
		},
		Targets: []scanner.TargetResult{{
			Host:   "198.51.100.10",
			Inputs: []string{"198.51.100.10"},
			Services: []scanner.ServiceResult{{
				Host: "198.51.100.10", Port: 80, Scheme: "http", URL: "http://198.51.100.10:80/",
				PortOpen: true,
				HTTP:     &scanner.HTTPInfo{Status: 200, Server: "Apache", PoweredBy: "Ruby/2.7.3", Title: "Café ☕"},
				Ruby: &ruby.Detection{
					IsRuby: true, Verdict: ruby.VerdictConfirmed, Confidence: 95,
					Variant: "Ruby", Version: "2.7.3", VersionSource: "X-Powered-By header",
					EndOfLife: true, EOLDetail: "Ruby 2.7 reached end of security support on 2023-03-31",
					Frameworks: []string{"Discourse"},
					Evidence:   []ruby.Evidence{{Signal: "header.x-powered-by", Detail: "advertises Ruby", Weight: 80, Data: "Ruby/2.7.3"}},
					Vulnerabilities: []ruby.Vulnerability{{
						ID: "CVE-2022-28738", Severity: "critical", Title: "Regexp double free",
						AffectedVersions: "< 2.7.6", MatchBasis: "version-correlation",
					}},
				},
			}},
		}},
		Summary: scanner.Summary{HostsScanned: 1, OpenPorts: 1, HTTPServices: 1, RubyConfirmed: 1, Vulnerabilities: 1},
	}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, sampleResult(), "text"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"RUBY SERVICE SCAN REPORT", "CVE-2022-28738", "Discourse", "END OF LIFE"} {
		if !strings.Contains(s, want) {
			t.Fatalf("text output missing %q\n%s", want, s)
		}
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, sampleResult(), "json"); err != nil {
		t.Fatal(err)
	}
	var round map[string]interface{}
	if err := json.Unmarshal(b.Bytes(), &round); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestXML(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, sampleResult(), "xml"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "<?xml") {
		t.Fatalf("XML missing header: %q", b.String()[:20])
	}
	if !strings.Contains(b.String(), "<scan>") {
		t.Fatal("XML missing <scan> root")
	}
}

func TestRTF(t *testing.T) {
	var b bytes.Buffer
	if err := WriteReport(&b, sampleResult(), "rtf"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), `{\rtf1`) {
		t.Fatal("RTF missing header")
	}
}

func TestPDF(t *testing.T) {
	var b bytes.Buffer
	if err := WriteReport(&b, sampleResult(), "pdf"); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-1.4")) {
		t.Fatal("PDF missing header")
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Fatal("PDF missing EOF")
	}
	if !bytes.Contains(out, []byte("startxref")) {
		t.Fatal("PDF missing startxref")
	}
}

func TestUnknownFormats(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, sampleResult(), "pdf"); err == nil {
		t.Fatal("pdf is not a valid scan output format")
	}
	if err := WriteReport(&b, sampleResult(), "json"); err == nil {
		t.Fatal("json is not a valid report format")
	}
}
