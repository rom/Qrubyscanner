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
- **Behavioural probe** of Rack's query parser (a parameter declared as both
  array and hash is rejected with 400), gated against the soft-404 baseline.
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
