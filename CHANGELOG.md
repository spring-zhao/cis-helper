# Changelog

All notable changes to `cis-helper` will be documented in this file.

## [0.1.0] - 2026-03-19

### Added

- Initial `cis-helper` SDK release
- `NewHelper` / `Close` lifecycle APIs
- Cached JWT-SVID, JWT bundle, X.509-SVID, and X.509 bundle access
- Periodic background refresh with atomic cache replacement
- Structured logging and pluggable metrics
- TLS client config generation for `mtls` and `one_way_tls`
- Demo program and repository documentation
- Example HTTPS server and client built on the SDK TLS helper

### Changed

- Reimplemented SPIRE agent access around SPIFFE Workload API proto semantics
- Moved Workload API client logic into a dedicated file for maintainability
- Defaulted JWT audience to `spire-server` when omitted
- Made `TrustDomain` optional:
  if set, bundle APIs return the selected trust-domain subset
  if empty, bundle APIs return all cached JWT and X.509 bundles
- Replaced the single `demo` command with `fetch-svid`, `https-server`, and `https-client`

### Verified

- `go test ./...` passes with workspace-local Go caches
