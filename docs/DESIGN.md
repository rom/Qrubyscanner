# qrubyscanner — Design

This document describes the architecture of `qrubyscanner`, the Ruby-detection
heuristics it uses, the scoring model, and the data schema shared by all output
formats.

## Goals and non-goals

**Goals**

- Decide, with auditable evidence, whether a network service is backed by Ruby.
- Optionally fingerprint the Ruby version, variant, frameworks, gems and server
  modules, and correlate known version-based vulnerabilities.
- Surface any published `security.txt`.
- Accept flexible targets and ports, emit multiple machine formats, and render
  human reports — from both a CLI and a web GUI.
- Build anywhere with **no external dependencies**.

**Non-goals**

- No exploitation, authentication bypass, fuzzing, or write operations. Every
  probe is a read-only GET.
- No brute force or large-scale untargeted scanning features.

## Package layout

```
cmd/qrubyscanner      CLI entrypoint: flags, config merge, output/report wiring
internal/
  version            build metadata (overridable via -ldflags)
  target             target spec parsing/expansion (URL, IP, CIDR, range, wildcard)
  portspec           port spec parsing (single, list, range)
  probe              low-level TCP connect checks and bounded HTTP(S) fetches;
                     a Recorder hook feeds every exchange to the audit trail
  pcap               dependency-free libpcap writer: reconstructs HTTP exchanges
                     as raw-IPv4 TCP conversations with valid checksums
  corpus             sanitised record/replay fixture of a scan's detection inputs
                     (leaf: depends only on probe); drives offline replay
  ruby               Ruby detection, fingerprinting, vuln correlation (the core)
                     — catalog.go (data-driven vuln/EOL catalogue + feed loader),
                     feeds_import.go (OSV + CSAF importers), vulndb.go (built-in
                     data incl. Ruby2Shell), version.go (4-component / patch-
                     level versions), railsinfo.go (/rails/info/properties),
                     bundler.go (Gemfile.lock inventory), probes.go (probe
                     catalogue), favicon.go + faviconcat.go (mmh3 favicon map),
                     signatures*.go (header/cookie/body signature catalogues),
                     sigpack.go (runtime-loadable, versioned signature packs)
  securitytxt        RFC 9116 security.txt discovery and parsing
  webserver          web-server identification + reverse-proxy/CDN/WAF/LB detection
  dnsenum            subdomain discovery for "*.domain" via Certificate Transparency
  scanner            orchestration: expand → connect → probe → analyse → aggregate;
                     a host-level scheduler (HostConcurrency) over a global
                     service-concurrency pool; enrich.go (DNS, jitter, per-host
                     gate), checkpoint.go (resume), audit.go (PCAP + decision log),
                     replay.go (reconstruct a ScanResult from a recorded corpus)
  report             rendering: text, JSON, XML, RTF, PDF (from one doc model)
  config             YAML-subset parser and typed configuration
  web                embedded single-page GUI + JSON API over the scanner
```

Dependencies flow one way: `scanner` imports `probe`, `ruby`, `securitytxt`,
`target`, `portspec`, `webserver` and `pcap`; `report` and `web` import
`scanner`; `cmd` wires it all together. `pcap` is self-contained (it depends on
nothing in the tree). There are no import cycles.

## Pipeline

```
targets ──► target.Expand ──► endpoints (host [+scheme/port/path])
                                   │
                        for each endpoint × port
                                   ▼
                        probe.CheckPort (TCP connect)
                                   │ open
                                   ▼
                 probe.Fetch root (scheme per --tls / URL / port)
                                   │
              ┌────────────────────┼─────────────────────────┐
              ▼                    ▼                          ▼
      ruby.Analyze(root)     deep: fetch probe paths     securitytxt lookup
                            + Rack param probe   
                                   ▼
                        scanner.ServiceResult
                                   ▼
                 aggregate by host ─► ScanResult ─► report.*
```

A bounded worker pool (`--concurrency`) runs the per-service work. Redirects
are followed manually so headers and cookies from **every hop** become
evidence; response bodies are read up to a byte cap.

**DNS wildcards.** A `*.example.com` target is expanded before scanning by the
`dnsenum` package, which queries Certificate Transparency (crt.sh) for names
issued under the domain, normalises and de-duplicates them, and optionally
filters to names that resolve. The resulting hosts are scanned like any other.

**Progress.** `scanner.Options.OnProgress` receives `ProgressEvent`s: one per
enumeration step and one per completed service probe (carrying a monotonic
`done`/`total` counter, the host/port, open state and any Ruby verdict). The
scanner serialises these callbacks. The CLI renders them as an in-place counter
or, with `--verbose`, a line per service; the web server forwards each event to
the browser as a line of NDJSON, ending with the final result.

## Detection model

Detection is **evidence-based and additive**. Each matched signal contributes a
weight; the confidence is the capped sum (0–100), mapped to a verdict band
(`confirmed` ≥ 70, `likely` ≥ 50, `possible` ≥ 25, else `none`). A service is
reported as Ruby at confidence ≥ 50. Every signal is retained as an `Evidence`
record (signal id, source, human detail, raw data, weight) so a verdict is
always explainable, and each distinct signal is counted once.

### Signal categories

**Response headers**
- Ruby application-server banners: `WEBrick/x (Ruby/y/date)` (which embeds the
  running Ruby version), Thin, Puma, Unicorn, Mongrel, Falcon, Rainbows!,
  TorqueBox/Trinidad (⇒ JRuby), `mod_rails` / `mod_rack`.
- Phusion Passenger in `Server` / `X-Powered-By` — counted **once** and only as
  a medium signal, because Passenger also hosts Python and Node.js.
- Rack middleware headers: `X-Runtime` in Rack::Runtime's exact six-decimal
  form, `X-Rack-Cache`, `X-Rack-CORS`, `X-Cascade: pass`.
- Header *combinations* that are Rails defaults: a Rack::ETag weak validator
  with `Cache-Control: max-age=0, private, must-revalidate`; and the default
  security-header set (`X-Permitted-Cross-Domain-Policies: none` with
  `X-Download-Options` / `Referrer-Policy` defaults). Express' helmet emits a
  similar set but always adds `X-DNS-Prefetch-Control`, which disqualifies it.
- `Link: </assets/…-<digest>.css>; rel=preload` for fingerprinted pipeline assets.
- Application headers: `X-Gitlab-Meta`, `X-Discourse-Route`,
  `X-GitHub-Enterprise-Version`, `Server: Mastodon`, `Foreman_version`, …

**Cookies**
- Names: `rack.session`, `_session_id`, the Rails cookie-store convention
  `_<app>_session`, application cookies (`_gitlab_session`, `_forum_session`,
  `_mastodon_session`, `_redmine_session`, …), Devise `remember_user_token`.
- **Value formats** (the value itself is never recorded): the Rails 5.2+
  AES-GCM encrypted cookie `data--iv--tag`, the signed `payload--hmac` form,
  and a Marshal payload (`BAh…--hmac`), which is definitive for Ruby.

**Response bodies**
- Ruby backtrace frames (`file.rb:LINE:in 'method'`), `NoMethodError` /
  `uninitialized constant` messages, `ruby -v` strings, RubyGems / rbenv / RVM
  paths, Bundler errors, leaked ERB or Ruby source.
- Rails: the development exception page, routing errors, framework class names,
  the welcome page, the static `public/404|422|500.html` pages,
  `csrf-param = authenticity_token`, `authenticity_token` fields,
  Sprockets/Propshaft digests, Webpacker packs, Active Storage URLs, Action
  Cable meta tags, the generator's default `robots.txt`.
- Sinatra ("doesn't know this ditty"), Rack class names and query-parser
  errors, Hanami, Padrino, Roda, Grape; Puma / WEBrick / Passenger error pages.
- Tools: web-console, better_errors, Sidekiq Web, ActiveAdmin, RailsAdmin, …
- Applications: GitLab, Discourse, Mastodon, Redmine, OpenProject, Chatwoot,
  diaspora*, Spree/Solidus, Canvas LMS, Foreman, Zammad, …
- Static-site generators (Jekyll, Middleman, Nanoc, Bridgetown) are **named but
  inert**: Ruby ran at build time, not on the server, so they add no weight.

**Diagnostics and project files** (deep mode)
- `/rails/info/properties` — parsed into structured facts (Ruby, Rails, Rack,
  RubyGems versions, environment, middleware stack, database adapter).
- `/rails/info/routes`, mailer previews, Rails Conductor, `/up` (Rails ≥ 7.1).
- Readable `Gemfile`, `Gemfile.lock`, `.ruby-version`, `.tool-versions`,
  `config.ru`, `Rakefile`; exposed `config/master.key`, `config/secrets.yml`,
  `config/database.yml`, `.env`, Rails logs (content is validated, values are
  never stored).

**Behaviour** (deep mode)
- The **Rack parameter-type probe**: `/?p[]=1&p[k]=1` declares one parameter as
  both array and hash. Rack's query parser rejects that, and Rails/Sinatra
  answer 400; other stacks accept it. It only counts when the plain request
  succeeded and the 400 differs from the soft-404 baseline.
- **Request-id sanitisation**: the parameter probe carries a crafted
  `X-Request-Id`; ActionDispatch::RequestId echoes it with everything but word
  characters, `-` and `@` removed. A verbatim echo or a fresh id does not count.
- **Unknown HTTP method**: Puma answers a bare, empty `501` before the
  application runs, which identifies the app server even on a hardened
  production deployment; Rails behind other servers answers `405`.
- Generator defaults: Rails' `icon.svg` and `406-unsupported-browser.html`
  (Rails ≥ 7.2), an empty `favicon.ico` (Rails ≤ 7.1).
- Middleware traces: `Server-Timing` event names (`*.action_controller`),
  a UUID `X-Request-Id` with `X-Runtime`, Rack 3's lower-case cookie
  attributes, Sinatra's default header set.
- Sinatra's bare `<h1>Not Found</h1>` with `X-Cascade: pass`.
- The guaranteed-404 response is requested in **every** mode and analysed like
  any other body: a front page served by a CDN or a JavaScript front end often
  hides an application that is plain to see on a path it routes itself. It
  also doubles as the soft-404 baseline that gates behavioural signals on
  catch-all servers.

**Conventions, leaks and bundles**
- Rails form-helper and view-helper output, pagination gems, attachment URL
  schemes, Devise and Active Model messages, HTTP-auth failure bodies, the
  `redirect_to` body (the fetcher keeps a bounded prefix of each redirect
  hop's body for this).
- Ruby values rendered by mistake: `#<Class:0x…>`, hash-rocket dumps,
  `nil:NilClass`. These are skipped on pages that display code samples.
- Deep mode asks for the not-found path again with `Accept:
  application/json`, a missing `/assets/` file and `/cable`, reads asset
  manifests, and fetches up to two referenced JavaScript bundles to look for
  rails-ujs / Action Cable / Active Storage client code.
- A **Rails version hint** is derived from generation-specific defaults when
  no exact version is known. Only lower bounds are taken from header sets,
  since applications that manage their own headers keep old ones across
  upgrades. The hint is display-only.

**Negative fingerprints**
- **Phoenix (Elixir)** mirrors Rails' default `Cache-Control`, secure headers
  and MD5-digested `/assets/` files. It is recognised by its `_<app>_key`
  cookie, short base64 request ids, missing `X-Runtime` and `phx-` attributes;
  on such a response the Rails-like header combinations and asset digests are
  not counted.
- **Prose pages** (documentation, blogs, Q&A): signatures that match bare
  class or error names apply only to error responses and plain pages.
- Asset digests are tiered: SHA-length digests count as Rails evidence; MD5-
  length and 8-character digests, which other toolchains also emit, are
  supporting evidence only.

### Version, variant, frameworks, gems, app server

- **Ruby version** precedence: `/rails/info/properties` > running-process
  sources (WEBrick banner/footer, welcome page, `ruby -v` string, product
  token) > declared sources (`.ruby-version`, `.tool-versions`, `Gemfile.lock`
  `RUBY VERSION`, exact `Gemfile` `ruby` directive, version-manager paths).
  A RubyGems ABI directory yields only the **branch**. Patch levels
  (`2.0.0p594`) are kept and compared as a fourth version component.
- **Variant**: `Ruby` (CRuby, default), `JRuby`, `TruffleRuby`.
- **Component versions** (`framework_versions`): Rails, Rack, Sinatra, Puma,
  Phusion Passenger, WEBrick, Thin, Sidekiq and applications, from banners,
  `/rails/info/properties`, gem paths in backtraces, the lockfile and
  application endpoints (`/api/v1/instance`, `/api/v3/meta`, …).
- **Gems**: from signatures, the middleware list and backtrace gem paths.
- **App server**: best-effort (`Puma 6.4.2`, `Phusion Passenger 6.0.22`,
  `WEBrick 1.9.2`, …), falling back to the lockfile.
- **End of life** is evaluated per release branch against ruby-lang.org's
  published security-maintenance end dates relative to the current date.

### Vulnerability correlation and feeds

The vulnerability data is a **data-driven catalogue** (`internal/ruby/catalog.go`):
`vulndb_rubysec.go` is generated by `scripts/gen_vulndb.py` from the RubySec
advisory database, and `vulndb.go` holds curated entries that are overlaid on
it (generated ranges win; curated prerequisites and notes are kept). The
generator takes the complement of each advisory's patched and unaffected
version sets to obtain affected ranges, and unions the ranges of an advisory
filed under several Rails component gems.

In that catalogue each entry is a `FeedEntry` with one or more `RangeSpec`
affected ranges (`branch` / `introduced` / `fixed` / `lt` / `eq`), matched
against the parsed version. Three maps are kept: **Ruby core** (CRuby only),
**components** (frameworks, applications and stack components such as Rails,
Rack, Sinatra, Passenger, GitLab, Mastodon) and **gems**.

Correlation has four entry points:

- `CorrelateRuby(version)` — the normal case.
- `CorrelateRubyBranch(branch)` — when only the branch is known, an entry
  matches only if both the first and a notional last release of the branch are
  affected, i.e. the whole branch is (Ruby2Shell on 3.2 and older).
- `CorrelateCMS(component, version)` / `CorrelatePackage(gem, version)`.
- `UnknownVersionLeads()` — entries flagged `alert_unknown_version` (only
  Ruby2Shell is) yield an `info`-severity, `unverified` lead when Ruby is
  detected with no version at all.

Ruby2Shell additionally has per-product entries for self-hosted software that
bundles its own Ruby; these are dropped whenever a Ruby version was actually
observed, since an observation beats an inference.

Each entry may carry structured **prerequisites** (`framework`, `app-server`,
`os`, `gem`, `env`) resolved against the scan's evidence into *observed* /
*contradicted* / *unknown*. A lead is qualified, never dropped.

External **feeds** are loaded from a file or URL and `Merge`d on top of the
built-in data, overriding EOL dates by branch. `ParseFeed` accepts the native
`qrubyscanner-vuln-feed/1` schema, **OSV** records (RubyGems ecosystem names
are keyed by gem) and **CSAF 2.0** advisories.

Correlation runs only in deep mode and only for services classified as Ruby.
These are **leads derived from version strings**, never confirmed, exploited
findings — and nothing resembling an exploit is ever sent.

### Web server, reverse proxy, CDN and WAF

The `webserver` package analyses the root response plus deep-mode probe
responses (an `OPTIONS` request, a guaranteed-404, and status endpoints) to:

- **Identify the web server** — product, version, OS hint and server-level
  modules — from `Server` banners (all values are considered), module/runtime
  headers (`X-AspNet-Version`, `X-Mod-Pagespeed`, …), the `DAV` header, and
  error-page signatures (nginx/Apache/IIS/LiteSpeed). If a `Server` value is a
  CDN token the origin product is reported as concealed.
- **Detect a front layer** — CDN, WAF, cache or load balancer — from
  distinctive headers (`CF-RAY`, `X-Amz-Cf-Id`, `X-Sucuri-ID`, `X-Iinfo`,
  `X-Varnish`, …), cookies (`__cf_bm`, `incap_ses_*`, `AWSALB`, `BIGipServer*`,
  …) and block/challenge page bodies (Cloudflare, Sucuri, Incapsula,
  ModSecurity, Wordfence, F5 ASM). Any front layer sets `Concealed`, so the
  operator knows the real origin reply may be hidden, cached, filtered or
  challenged; a note summarises the implication.

Every proxy/server finding carries a numeric `confidence` (0-100) and a
low/medium/high `tier`; Ruby evidence items carry the same tier (derived from
their weight). This makes the basis for each conclusion auditable.

### Enrichment, politeness and resume

A global token-bucket `Limiter` in the probe layer caps requests per second;
per-host concurrency and jitter are enforced in the scanner's worker loop;
transient failures are retried with backoff. Hosts are optionally resolved
(forward + reverse DNS), and open non-HTTP ports yield a short grabbed banner.
A checkpoint file records each completed service as NDJSON so an interrupted
scan resumes by skipping finished work. Requests can carry custom headers,
Basic/Bearer/cookie auth and a Host override, and route through an http(s) or
SOCKS5 proxy (a minimal dependency-free SOCKS5 client).

### Audit trail: PCAP capture and session log

The `Fetcher` exposes a `Recorder` interface that receives every request/
response `Exchange` (across redirect hops too). The scanner's `audit.go` builds
a concurrency-safe sink that fans each exchange out to the optional outputs:

- **PCAP** (`--pcap`): the sink reconstructs the wire bytes of the request
  (request line, `Host`, headers) and response (status line, headers, body) and
  hands them to the `pcap` package, which synthesises a complete TCP
  conversation — three-way handshake, PSH/ACK data segments chunked at a 1460-
  byte MSS, and a graceful FIN teardown — with correct sequence/ack numbers and
  valid IPv4 and TCP checksums. The file uses link type `RAW` (IPv4), so it is a
  real libpcap file that opens in Wireshark/tcpdump. Each exchange gets a fresh
  ephemeral client port so concurrent flows stay distinct; non-IP hosts are
  mapped to stable `10/8` addresses. It is a faithful record of what was
  requested and returned (plaintext, even for TLS targets, since probing is
  local), not a packet-timing-accurate wire capture.
- **Session log** (`--log`): a plain-text journal. Each exchange is logged as it
  happens (method, URL, status, key response headers); then, per service, a
  `DECISION` block states the web server, any reverse proxy, the Ruby verdict and
  version, and walks the evidence highest-weight-first, printing each item's
  provenance (where/how/probe/matcher/snippet/line). This is the narrative
  companion to the structured `evidence[]` in the machine outputs.

Both are opened by the scanner and closed on completion; write failures are
best-effort and never abort a scan.

## Data schema

All formats serialise the same `ScanResult`:

```
ScanResult
├─ meta      { tool, version, mode, started_at, finished_at, duration_ms, ports[] }
├─ targets[] { host, inputs[], services[] }
│    └─ service { host, port, tls, scheme, url, port_open, error,
│                 http   { status, proto, server, powered_by, title,
│                          content_type, redirects, tls{…}, headers{} },
│                 ruby   { is_ruby, verdict, confidence, variant, version,
│                          version_source, branch, end_of_life, eol_detail,
│                          version_observations[], version_conflict,
│                          frameworks[], framework_versions{}, gems[],
│                          modules[], addons[], app_server, rails_env,
│                          rails_info_exposed, rails_info_url, rails_info{…},
│                          bundler{ruby_require,ruby_locked,gems[]},
│                          evidence[]{signal,source,detail,data,weight,
│                              confidence,where,how,pattern,snippet,line,probe},
│                          vulnerabilities[]{id,severity,title,
│                              affected_versions,description,reference,match_basis,
│                              prerequisites[],applicability} },
│                 security_txt { present, url, signed, contact[], expires,
│                          expired, encryption[], acknowledgments[],
│                          preferred_languages[], canonical[], policy[],
│                          hiring[], csaf[] } }
└─ summary   { hosts_scanned, services_probed, open_ports, http_services,
               ruby_confirmed, ruby_likely, ruby_possible, vulnerabilities,
               security_txt }
```

(Per-service results also carry `banner`, and the Ruby block adds
`favicon_hash`; targets carry resolved `addresses` and
`ptr` names.)

JSON and XML emit this directly (XML is rooted at `<scan>`; maps are omitted as
XML cannot represent them). CSV flattens one row per service; SARIF 2.1.0
exposes findings (CVEs, EOL, exposed Rails info) as results with rules for CI
ingestion; NDJSON streams one object per service. Text, RTF, PDF and HTML are
produced from a single intermediate **document model**
(`internal/report/doc.go`) of headings, key/value rows, bullets and rules, so
the human formats stay consistent. `report.Diff` compares two results, and
`report.FailOn` powers `--fail-on` severity/EOL gating.

## Self-contained RTF, PDF and HTML

To avoid third-party dependencies, the writers are implemented directly (HTML
is rendered from the same document model with inline, theme-aware CSS):

- **RTF** — emits an `{\rtf1 …}` document with Helvetica, bold headings, sized
  text and bullet paragraphs; control characters are escaped and non-ASCII is
  encoded as `\uN?`.
- **PDF** — a minimal PDF 1.4 generator (`internal/report/pdfwriter.go`): US
  Letter pages of left-aligned text in the standard Helvetica / Helvetica-Bold
  fonts (no embedding), with word wrapping, pagination, horizontal rules and a
  correct cross-reference table and trailer.

## Configuration

`internal/config` includes a deliberately small YAML-subset parser (comments,
space-indented nested maps, scalar key/values, block lists of scalars, quoted
scalars; tabs rejected). It is sufficient for the documented schema and keeps
the tool dependency-free. Booleans are parsed as pointers so the CLI can tell
"unset in config" from "explicitly false" when merging flag precedence.

## Security considerations

- The tool only reads; it never submits forms or attempts exploitation.
- The web GUI binds to localhost by default and inserts all scan-derived text
  into the DOM as text, never HTML, so hostile response content cannot be
  reflected into the operator's browser. Request bodies are size-capped and the
  server-side scan is time-bounded.
- Response bodies are read up to a byte cap to bound memory.
- Target expansion is capped per spec to prevent accidental massive sweeps.
- Subdomain enumeration reads only public Certificate Transparency data; it
  does not brute-force DNS or probe the target during discovery.
