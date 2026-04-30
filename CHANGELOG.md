# Changelog

All notable changes to the TLSentinel scanner are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses TLSentinel's `YYYY.M.P` versioning scheme — `M` bumps
on breaking changes, `P` is bugfix-only. Pre-release tags (`-beta.N`,
`-rc.N`) bake each `.0` before it ships.

## Unreleased

### Added

- **Hard local concurrency cap.** New optional environment variable
  `TLSENTINEL_SCANNER_MAX_CONCURRENCY` (default `64`) clamps the server-supplied
  per-cycle scan concurrency so a misconfigured or compromised server cannot
  push the scanner past what its host can handle without FD or goroutine
  exhaustion. Server values at or below the cap pass through unchanged; values
  above the cap are pulled down with a single warning log line per cycle. A
  zero or negative server value still falls through to `runScanCycle`'s own
  default (5) — the cap never *raises* concurrency, it only lowers absurd
  requests.

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
