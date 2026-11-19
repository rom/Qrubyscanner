# Changelog

All notable changes to **qrubyscanner** are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial version. `qrubyscanner` is the Ruby counterpart of
[qphpscanner](https://github.com/rom/qphpscanner): it reuses that tool's
scanner, probe, report, config, audit-trail and web-GUI layers unchanged in
behaviour, and replaces the detection core with a Ruby one.

### Added

- **Ruby detection** from many independent signals: application-server banners
  (WEBrick, Puma, Thin, Unicorn, Falcon, Phusion Passenger, TorqueBox),
  Rack/Rails middleware headers and header *combinations* (Rack::Runtime's
  `X-Runtime`, Rack::ETag with Rails' default `Cache-Control`, the Rails
  default security-header set), session-cookie names **and wire formats**
  (Rails AES-GCM `data--iv--tag`, signed `payload--hmac`, Marshal `BAh…`),
  Ruby backtraces and exception messages, Rails / Sinatra / Rack / Hanami /
  Padrino / Roda / Grape pages, and ~30 Ruby applications (GitLab, Discourse,
  Mastodon, Redmine, OpenProject, Chatwoot, …).
- **Behavioural probes**, gated against the soft-404 baseline: Rack's query
  parser (a parameter declared as both array and hash is rejected with 400),
  `X-Request-Id` sanitisation (ActionDispatch::RequestId), and an unknown HTTP
  method (Puma's bare 501, which also identifies the app server).
- **More passive evidence**: Rails generator defaults (`icon.svg`,
  `406-unsupported-browser.html`, empty `favicon.ico`), `Server-Timing` event
  names, Rack 3 cookie-attribute casing, Sinatra's default header set,
  web-console / meta_request / Turbolinks headers, Rails JSON and XML error
  bodies, the HostAuthorization "Blocked host" page, turbo-rails stream
  sources, importmap pins, I18n and Devise messages, Rack::Files /
  Rack::URLMap / Rack::Attack replies, Puma and Passenger production errors.
- **The not-found page is analysed in every mode**, and deep mode also
  requests `/users/sign_in` and `/session/new`: real deployments frequently
  serve a static or cached front page and only show the application on paths
  it routes itself.
- **Evidence tuned against ~130 public sites**: Ahoy cookies, SHA-digested
  assets of any type, Haml attribute quoting, the Rails 3 `X-UA-Compatible`
  header; and guards against the false positives that survey exposed —
  Phoenix (Elixir) look-alike headers, class names quoted in documentation,
  short asset digests, GitHub Pages hosting, marketing pages naming a product.
- **A much larger evidence set** (about 170 body, 75 header and 45 cookie
  signatures): Rails form/view-helper conventions, pagination and attachment
  gems, Devise / Active Model / CanCanCan messages, HTTP-auth bodies and
  realms, the `redirect_to` body on redirect hops, Ruby values leaking into
  output, JRuby / TruffleRuby / mruby markers, more application servers and
  applications, Shopify storefronts, and development tooling headers.
- **More deep-mode probes**: JSON error format, missing-asset behaviour,
  `/cable`, Propshaft / Webpacker / Vite manifests, default PWA files,
  Sinatra's error image, referenced JavaScript bundles, and project files
  (`Dockerfile`, `Procfile`, `.rubocop.yml`, `.bundle/config`,
  `db/schema.rb`, `config/*.rb`, `credentials.yml.enc`).
- **Rails version hint** (`rails_version_hint`) estimated from
  generation-specific defaults when no exact version is disclosed; and new
  Ruby-version sources (`Dockerfile`, `X-Ruby-Version`, Bundler mismatch
  messages; branch from `.rubocop.yml`).
- **Vulnerability catalogue generated from the RubySec advisory database**:
  about 1,500 advisories (92 for Ruby, ~150 for Rails and its component gems,
  JRuby, ~1,200 across ~470 gems), with a generator (`scripts/gen_vulndb.py`,
  `make vulndb`) and curated GitLab / Mastodon / GitHub Enterprise Server
  additions. Several hand-written ranges were corrected by the generated data.
- **Verifiable fingerprints**: Rack::ETag digest recomputation, signed-cookie
  envelope decoding, CSRF-token shape, Rails format negotiation
  (`/?format=xml` → 406), and default `robots.txt` files of GitLab, Redmine,
  OpenProject and Discourse.
- **Deep is the default scan depth**; `--mode detect` limits a scan to the
  yes/no verdict with two requests per service.
- A GitHub Actions workflow running `make check`.
- **Ruby version discovery** from `/rails/info/properties`, WEBrick banners and
  error-page footers, the Rails welcome page, `ruby -v` strings, exposed
  `.ruby-version` / `.tool-versions` / `Gemfile.lock`, version-manager paths,
  and — branch only — RubyGems ABI directories in backtraces. Every observation
  is kept with its source; conflicts are flagged.
- **Ruby2Shell (GHSA-34m4-m9fh-gqp5)** detection by version: affected
  2.4.0 – 3.3.13, 3.4.0 – 3.4.12 and 4.0.0 – 4.0.9; fixed in 3.3.14, 3.4.13 and
  4.0.10. Also flagged from a release branch alone when the whole branch is
  affected (3.2 and older), from a self-hosted product's bundled Ruby (GitLab,
  GitHub Enterprise Server, Mastodon, OpenProject, Discourse, Chatwoot), and as
  an `info` "could not be ruled out" lead when Ruby is detected but discloses
  no version.
- **Vulnerability catalogue**: ~35 Ruby-core advisories, plus Rails, Rack,
  Sinatra, Phusion Passenger, GitLab, Mastodon and Discourse entries and gem
  advisories (puma, webrick, sidekiq, devise, ruby-saml, rexml, carrierwave,
  …), with four-component (`7.0.8.1`) and patch-level (`2.0.0p594`) version
  ranges, structured prerequisites (framework / app server / OS / gem /
  environment) and end-of-life evaluation per Ruby branch. Extensible with
  native, OSV (RubyGems) and CSAF feeds via `--vuln-feed`.
- **Bundler inventory**: exposed or operator-supplied (`--gemfile`) `Gemfile` /
  `Gemfile.lock` are parsed into a gem inventory, merged with gems observed in
  backtrace paths, and correlated with gem advisories.
- **Exposure checks** for Rails development tooling (`/rails/info/routes`,
  web-console, better_errors, mailer previews) and secrets
  (`config/master.key`, `secrets.yml`, `database.yml`, `.env`, logs). Secret
  values are never copied into results.
- Everything inherited from qphpscanner: flexible targets and ports, TLS
  control, text / JSON / XML / CSV / SARIF / NDJSON output, text / RTF / PDF /
  HTML reports, scan diffing, `--fail-on` exit codes, rate limiting and
  politeness controls, resume, PCAP + session-log audit trail, record & replay
  corpora, signature packs, favicon catalogue, YAML config with full CLI
  parity, shell completions, and the web GUI.
