package ruby

import (
	"html"
	"regexp"
	"strings"
)

// RailsInfoFacts holds values observed on an exposed /rails/info/properties
// page. Rails serves that page only to "local" requests in development, so
// seeing it remotely means the application runs in development mode (or with
// consider_all_requests_local) behind a proxy that makes every client look
// local — a serious misconfiguration in itself.
type RailsInfoFacts struct {
	RailsVersion    string `json:"rails_version,omitempty" xml:"rails_version,omitempty"`
	RubyVersion     string `json:"ruby_version,omitempty" xml:"ruby_version,omitempty"`
	RubyDescription string `json:"ruby_description,omitempty" xml:"ruby_description,omitempty"`
	RubyGemsVersion string `json:"rubygems_version,omitempty" xml:"rubygems_version,omitempty"`
	RackVersion     string `json:"rack_version,omitempty" xml:"rack_version,omitempty"`
	Environment     string `json:"environment,omitempty" xml:"environment,omitempty"`
	AppRoot         string `json:"app_root,omitempty" xml:"app_root,omitempty"`
	DatabaseAdapter string `json:"database_adapter,omitempty" xml:"database_adapter,omitempty"`
	SchemaVersion   string `json:"schema_version,omitempty" xml:"schema_version,omitempty"`
	// System is the platform triple (e.g. "x86_64-linux") when shown.
	System     string   `json:"system,omitempty" xml:"system,omitempty"`
	Middleware []string `json:"middleware,omitempty" xml:"middleware>item,omitempty"`
}

var (
	reInfoRow    = regexp.MustCompile(`(?is)<td[^>]*class=["']name["'][^>]*>(.*?)</td>\s*<td[^>]*class=["']value["'][^>]*>(.*?)</td>`)
	reInfoLi     = regexp.MustCompile(`(?is)<li[^>]*>(.*?)</li>`)
	reTags       = regexp.MustCompile(`(?s)<[^>]*>`)
	reRubyVerVal = regexp.MustCompile(`(\d+\.\d+\.\d+)(?:-?p(\d+))?`)
	rePlatform   = regexp.MustCompile(`[\[(]((?:x86_64|x64|i[3-6]86|aarch64|arm64|arm|universal|java|ppc64le|s390x)[\w.-]*)[\])]`)
)

const maxMiddleware = 80

// isRailsInfo reports whether a body looks like /rails/info/properties.
func isRailsInfo(body string) bool {
	if body == "" {
		return false
	}
	return containsFold(body, "Rails version") && containsFold(body, "Ruby version") &&
		(containsFold(body, "Rack version") || containsFold(body, "Middleware") || containsFold(body, "Application root"))
}

// parseRailsInfo extracts the properties table. It returns nil when nothing
// useful could be read.
func parseRailsInfo(body string) *RailsInfoFacts {
	rows := reInfoRow.FindAllStringSubmatch(body, 64)
	if len(rows) == 0 {
		return nil
	}
	f := &RailsInfoFacts{}
	for _, r := range rows {
		name := strings.ToLower(cleanCell(r[1]))
		raw := r[2]
		val := clampLen(cleanCell(raw), 200)
		switch name {
		case "rails version":
			f.RailsVersion = val
		case "ruby version":
			f.RubyDescription = val
			f.RubyVersion = rubyVersionFromDescription(val)
			if m := rePlatform.FindStringSubmatch(val); m != nil {
				f.System = m[1]
			}
		case "rubygems version":
			f.RubyGemsVersion = val
		case "rack version":
			f.RackVersion = val
		case "environment":
			f.Environment = val
		case "application root":
			f.AppRoot = val
		case "database adapter":
			f.DatabaseAdapter = val
		case "database schema version":
			f.SchemaVersion = val
		case "middleware":
			for _, li := range reInfoLi.FindAllStringSubmatch(raw, maxMiddleware) {
				if m := clampLen(cleanCell(li[1]), 120); m != "" {
					f.Middleware = append(f.Middleware, m)
				}
			}
		}
	}
	if f.RailsVersion == "" && f.RubyVersion == "" && f.RackVersion == "" {
		return nil
	}
	return f
}

// rubyVersionFromDescription normalises "ruby 3.1.2p20 (2022-04-12 revision
// …) [x86_64-linux]", "2.7.6-p219 (x86_64-linux)" or "3.3.0" to a version
// string, keeping a patch level as "pNNN".
func rubyVersionFromDescription(s string) string {
	m := reRubyVerVal.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	if m[2] != "" {
		return m[1] + "p" + m[2]
	}
	return m[1]
}

// cleanCell strips tags, decodes entities and collapses whitespace.
func cleanCell(s string) string {
	s = reTags.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

func clampLen(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// railsInfoObservations renders the facts as short human-readable lines for
// reports and the session log.
func railsInfoObservations(f *RailsInfoFacts) []string {
	if f == nil {
		return nil
	}
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+": "+v)
		}
	}
	add("Rails version", f.RailsVersion)
	add("Ruby", f.RubyDescription)
	add("RubyGems version", f.RubyGemsVersion)
	add("Rack version", f.RackVersion)
	add("Environment", f.Environment)
	add("Application root", f.AppRoot)
	add("Database adapter", f.DatabaseAdapter)
	add("Schema version", f.SchemaVersion)
	if len(f.Middleware) > 0 {
		out = append(out, "Middleware stack: "+strings.Join(f.Middleware, ", "))
	}
	return out
}

// Observations exposes the facts as display lines.
func (f *RailsInfoFacts) Observations() []string { return railsInfoObservations(f) }
