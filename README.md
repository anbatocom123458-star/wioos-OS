# WIOOS

WIOOS is a modular operating-system/runtime project. The initial Railway target is a userspace prototype inside a Linux container; it does not boot a separate kernel or control host hardware.

## Phase 1 prototype

The Rust workspace currently provides:

- An HTTP service that listens on Railway's `PORT` (or `3000` locally).
- A minimal waiting-for-verification page for pending client IPs.
- Operator verification through standard input (`verify <IP>`) or `wioos-runtime verify <IP>`.
- File-backed verification state with an inter-process lock and atomic replacement.
- Client IP resolution that ignores forwarded headers unless the direct peer belongs to a configured trusted proxy CIDR.
- A public `/health` endpoint for deployment health checks.

After approval, the response explicitly identifies itself as a runtime prototype; the WIOOS shell and system services are not implemented yet.

## Run locally

```sh
cargo run -p wioos-runtime
```

In another terminal, send a request to `http://localhost:3000`, then approve the logged IP in the runtime terminal:

```text
verify 127.0.0.1
```

The standalone operator command is also available:

```sh
cargo run -p wioos-runtime -- verify 127.0.0.1
```

Run the test suite with `cargo test --workspace`.

## Railway configuration

Railway builds the included `Dockerfile` and checks `/health`. Attach a persistent volume at `/data` so verification state survives restarts. Configure `WIOOS_TRUSTED_PROXY_CIDRS` with the actual CIDRs of the trusted proxy layer before relying on forwarded client IPs. The app deliberately does not trust `X-Forwarded-For` by default; when no trusted CIDR is configured, it records the TCP peer address, which may be Railway's proxy rather than the original client.

An authorized operator with shell access to the running service can approve an address with:

```sh
/usr/local/bin/wioos-runtime verify 203.0.113.8
```

This is a prototype deployment shape, not a claim that Railway shell sessions attach to the server process's standard input. The command updates the shared file-backed state so subsequent requests are served as verified. Run a single service replica with one attached volume; this local state store is not a multi-region database.

## Security and limitations

Verification protects access through the app's own HTTP response only; it is not a general-purpose identity system. The state file and volume must be protected by the deployment operator. Client IP is an imperfect identity signal, especially behind NAT, VPNs, or changing networks. Forwarded headers are accepted only from configured proxy peers, and malformed chains fall back to the TCP peer. Railway proxy CIDRs must be confirmed from trusted deployment documentation and kept current.

No hardware functions are simulated or claimed. Railway runs this prototype in a Linux container and does not grant it kernel, driver, or physical-device control. WIOOS does not guarantee absolute security.

## Roadmap

1. Expand runtime architecture, configuration, and observability.
2. Build the responsive WIOOS shell, settings, time service, and network center.
3. Add app and package models, then store integration.
4. Add driver and security management abstractions.
5. Build sandboxing, permissions, and external package installation.
6. Add the native application SDK and prepare x86_64/ARM64 targets.
