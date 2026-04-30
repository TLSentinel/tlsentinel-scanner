# Changelog

All notable changes to the TLSentinel scanner are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses TLSentinel's `YYYY.M.P` versioning scheme — `M` bumps
on breaking changes, `P` is bugfix-only. Pre-release tags (`-beta.N`,
`-rc.N`) bake each `.0` before it ships.

## Unreleased

### Added

- **Hard local concurrency cap on per-cycle endpoint scans.** New optional
  environment variable `TLSENTINEL_SCANNER_MAX_CONCURRENCY` (default `64`)
  clamps the server-supplied `ScanConcurrency` so a misconfigured or compromised
  server cannot push the scanner past what its host can handle without FD or
  goroutine exhaustion. The cap covers per-cycle endpoint scans only — host
  TLS handshakes and SAML metadata fetches. Network discovery sweeps continue
  to use their own independent in-binary ceiling
  (`discoveryConcurrency = 50`); discovery is server-config-independent so the
  same threat model does not apply. Server values at or below the cap pass
  through unchanged; values above the cap are pulled down with a single
  warning log line per cycle (`"clamping server-supplied scan concurrency to
  local cap"`). A zero or negative server value still falls through to
  `runScanCycle`'s own default (5) — the cap never *raises* concurrency, it
  only lowers absurd requests.
- **Clearer concurrency fields in the startup log.** The "scanner started"
  line now uses `scan_concurrency` and `scan_max_concurrency` instead of the
  ambiguous `concurrency` / `max_concurrency`, and also surfaces
  `discovery_concurrency` so an operator can see all the bounds at a glance
  rather than wondering whether the cap covers discovery too. (It doesn't.)
- **Concurrency-change log on config refresh.** The config-poll loop already
  logged schedule changes; it now also logs when `ScanConcurrency` changes
  between polls (`"scan concurrency updated" from=N to=M`), mirroring the
  existing schedule-update pattern so a UI edit leaves a breadcrumb in the
  scanner log instead of taking effect silently.

## v2026.5.0 — 2026-04-27

Initial 1.0 release. The scanner shipped alongside the v2026.5.0 server
release; see the [server CHANGELOG](../server/CHANGELOG.md) for the matching
end-to-end feature set. Notable scanner-side changes during the v2026.5.0
development arc:

- Full SAML metadata parsing with raw XML payload posted to the API for
  storage and downstream processing.
- SSL 3.0 probe added to the TLS profile sweep (legacy version detection).
- Discovery sweep retries with exponential backoff on transient API errors.
- Cron callback overlap protection: a slow scan or sweep no longer stacks
  concurrent invocations on the same cron entry.
- Schedule reload: a malformed cron expression on a config refresh keeps the
  prior schedule active rather than dropping the entry.
- Discovery range size cap to prevent OOM on large CIDR sweeps.
- Context propagation through the API client, discovery probes, and scan
  probes so cancellation actually unwinds in-flight work.
- HTTP response bodies fully drained on every code path to enable connection
  reuse.
- SAML metadata fetch size limit.

This file starts with v2026.5.0 as the baseline; older history lives in the
git log.
