package report

import (
	"strings"

	"github.com/rom/qrubyscanner/internal/ruby"
	"github.com/rom/qrubyscanner/internal/scanner"
)

// worseSeverity returns whichever severity string ranks higher.
func worseSeverity(a, b string) string {
	if ruby.SeverityRank(b) > ruby.SeverityRank(a) {
		return strings.ToLower(b)
	}
	if a == "" {
		return ""
	}
	return strings.ToLower(a)
}

// HighestSeverity returns the worst vulnerability severity across the scan and
// its rank (0 when there are no vulnerabilities).
func HighestSeverity(res *scanner.ScanResult) (string, int) {
	worst := ""
	for _, t := range res.Targets {
		for _, s := range t.Services {
			if s.Ruby == nil {
				continue
			}
			for _, v := range s.Ruby.Vulnerabilities {
				if ruby.SeverityRank(v.Severity) > ruby.SeverityRank(worst) {
					worst = v.Severity
				}
			}
		}
	}
	return strings.ToLower(worst), ruby.SeverityRank(worst)
}

// FailOn reports whether the scan meets a severity/EOL gate: "eol" triggers on
// any end-of-life Ruby branch; "low"/"medium"/"high"/"critical" trigger when any
// vulnerability lead is at least that severe.
func FailOn(res *scanner.ScanResult, level string) bool {
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "eol" {
		return HasEOL(res)
	}
	threshold := ruby.SeverityRank(level)
	if threshold == 0 {
		return false
	}
	_, rank := HighestSeverity(res)
	return rank >= threshold
}

// HasEOL reports whether any detected service runs an end-of-life Ruby branch.
func HasEOL(res *scanner.ScanResult) bool {
	for _, t := range res.Targets {
		for _, s := range t.Services {
			if s.Ruby != nil && s.Ruby.EndOfLife {
				return true
			}
		}
	}
	return false
}
