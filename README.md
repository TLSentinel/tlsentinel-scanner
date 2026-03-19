![TLSentinel](https://tlsentinel.github.io/assets/tlsentinel_logo_light_horizontal.png)

# TLSentinel — Scanner

The scanner agent for the [TLSentinel](https://github.com/tlsentinel/tlsentinel-server) certificate monitoring platform.

The scanner registers with the TLSentinel server using a scanner token, fetches its assigned hosts, performs TLS handshakes to collect certificate data and cipher-suite profiles, and posts results back to the server. Scan interval and concurrency are configured server-side and picked up dynamically — changes take effect within the next poll tick without restarting the agent.

Scanners are designed to run anywhere that can reach your monitored hosts — alongside the server, in a separate network segment, or in a remote datacenter.

## How it works

1. On startup the scanner fetches its configuration (name, scan interval, concurrency) from the server using its token. It retries every 15 seconds until the server is reachable, so it is safe to start before the server in a Compose stack.
2. Each scan cycle fetches the list of assigned hosts and probes each one concurrently up to the configured concurrency limit.
3. For each host the scanner performs two probes:
   - **Certificate probe** — completes a TLS handshake, extracts the full certificate chain as PEM, resolves the active fingerprint and TLS version, then posts everything to the server in a single request.
   - **TLS profile probe** — enumerates supported TLS versions (1.0 / 1.1 / 1.2 / 1.3) and cipher suites, then posts the profile separately.
4. After each cycle the scanner refreshes its config and waits out the remaining interval, polling for config changes every 30 seconds. A shortened interval takes effect on the next poll tick.
5. `SIGINT` / `SIGTERM` trigger a clean shutdown. Any in-flight scan cycle completes before the process exits.

## Prerequisites

- Go 1.22+
- A running [tlsentinel-server](https://github.com/tlsentinel/tlsentinel-server) instance
- A scanner token created in **Settings → Scanners**

## Getting Started

**1. Clone the repository**

```sh
git clone https://github.com/tlsentinel/tlsentinel-scanner.git
cd tlsentinel-scanner
```

**2. Configure environment**

```sh
cp env.example .env
```

| Variable | Required | Description |
|---|---|---|
| `TLSENTINEL_API_URL` | ✅ | Base URL of the TLSentinel server, e.g. `https://tlsentinel.example.com` |
| `TLSENTINEL_API_TOKEN` | ✅ | Scanner token from Settings → Scanners (prefix: `scanner_`) |

**3. Run**

```sh
make run
```

## Building

```sh
# Build scanner binary for the current platform
make build

# Binaries are written to bin/
# e.g. bin/server_linux_amd64, bin/server_darwin_arm64
```

Cross-compilation targets: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.

## Docker

```sh
# Build the production image
make docker

# Or build manually:
docker build \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t tlsentinel/tlsentinel-scanner:latest \
  .

docker run \
  -e TLSENTINEL_API_URL=https://tlsentinel.example.com \
  -e TLSENTINEL_API_TOKEN=scanner_... \
  tlsentinel/tlsentinel-scanner:latest
```

## Project Layout

```
cmd/
  scanner/        # Entry point — scan loop, graceful shutdown
internal/
  api_client.go   # HTTP client for the TLSentinel probe API
  scan.go         # TLS certificate probe (handshake, chain extraction)
  probe.go        # TLS profile probe (version + cipher enumeration)
  logger/         # Zap logger initialisation
  version/        # Build-time version stamping
```

## License

MIT — see [LICENSE](LICENSE).
