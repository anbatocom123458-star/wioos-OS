# WIOOS — PHASE 1 Architecture Plan & Preparation Report

Status: ACTIVE — merged from lead analysis + copilot inspection report (task_0001).

Source of truth: `/workspaces/wioos-OS/prompt` (35 sections). This document covers
preparation and PHASE 1 scope only: repository architecture, Rust workspace, WIO
runtime, configuration, logging, HTTP/public Railway service, verification flow.
It also serves as the missing architecture plan required by prompt section 4
(a Phase-1 implementation had already been written into the working tree before
this plan existed — see section 2 for how that is handled).

## 0. Reference material found

- The only specification in the workspace (searched `/workspaces` and `$HOME`)
  is the `prompt` file itself. There are no skill/reference docs (no AGENTS.md,
  CLAUDE.md, .github, docs/). Per prompt section 3, `prompt` is therefore the
  single required reading, and it has been read in full.
- Git history: 2 commits (`Initial commit`, `Create prompt`) on `main`,
  remote `origin = https://github.com/anbatocom123458-star/wioos-OS`.

## 1. Environment facts (verified, not assumed)

| Item | Fact |
|---|---|
| OS | Ubuntu 24.04.5 LTS, x86_64, kernel 6.8 (GitHub Codespaces) |
| Rust toolchain | not preinstalled; rustup reachable over network (HTTP 200), installed during preparation |
| Node / npm | v24.21.0 / 11.19.0 (not needed for PHASE 1 backend) |
| Python | 3.14.2 (not needed for PHASE 1 backend) |
| Docker | CLI present (29.8.0-1); daemon usability unverified |
| Disk | ~18 GB free on workspace volume |
| Railway CLI | not present; deployment not exercised from this environment |

## 2. Current repository state and how it is handled

The working tree contains an uncommitted PHASE-1 implementation that appeared
while inspection was running (written by a concurrent process outside this
session): workspace `Cargo.toml`, `crates/wioos-runtime/` (main, config, state,
verification, web), `Dockerfile`, `railway.json`, `.dockerignore`, `Cargo.lock`,
rewritten `README.md`.

Review result: the code is small, has real tests, no placeholders, no
TODO/FIXME, no hardcoded public IPs or secrets, and matches the README. Per the
rule "Không phá code đang hoạt động nếu chưa có lý do", it is kept as the
PHASE 1 baseline; this plan documents and validates it instead of discarding it.
Open hygiene items: `.gitignore` added during preparation; no `LICENSE` file
despite `license = "MIT"` in the workspace manifest; nothing committed yet.

Known conflict to resolve with the owner (prompt section 30 vs reality): the
prompt names `github.com/wioos28/*` as the official organization, while this
repository lives under `anbatocom123458-star/wioos-OS`.

## 3. Target architecture (PHASE 1)

Deliberately kept at one workspace, one crate, one binary. The prompt forbids
creating abstraction layers and file counts for their own sake; more crates are
only justified when a later phase creates a real second consumer.

```
wioos-OS/
├── Cargo.toml                 # workspace root (members: crates/*)
├── rust-toolchain.toml        # TODO: pin toolchain for reproducible builds
├── .gitignore                 # target/, data/
├── crates/wioos-runtime/      # the WIO runtime (single deployable)
│   └── src/
│       ├── main.rs            # wiring: config -> store -> router -> operator loop
│       ├── config.rs          # typed env config (PORT, WIOOS_STATE_DIR,
│       │                      #   WIOOS_TRUSTED_PROXY_CIDRS); no secrets in code
│       ├── state.rs           # verification store: file-backed, flock + atomic
│       │                      #   rename; the only owner of persistence
│       ├── verification.rs    # pure logic: command parsing, UTC timestamps
│       └── web.rs             # HTTP adapter: verification gate + pages
├── ui/                        # Phase 2: WIO UI shell assets (not yet)
├── docs/                      # this plan, threat model, runbooks
└── data/                      # runtime state (gitignored)
```

Boundary rules (the inter-component API required by prompt section 5):

1. `state.rs` owns all persistence. Nothing else touches the state file.
2. `verification.rs` stays pure (no I/O, no HTTP types) so the CLI, the stdin
   operator loop and the future GUI all share exactly one implementation
   (prompt section 31: one backend, never two management systems).
3. `web.rs` is an adapter: it can be replaced (native windowing, other
   transport) without touching state/verification logic. Core logic never
   imports axum types.
4. All routes except an explicit allowlist (`/health` for Railway health
   checks) must pass the verification gate — enforced by default-deny
   middleware so a future route cannot ship unprotected by accident.
5. Config comes from the environment only. No hardcoded IP, no secret, no
   plaintext password anywhere (prompt section 33).

Future split criteria (not implemented now): create `wio-api` only when a
second process (GUI shell or `wio` CLI over IPC) needs the same services;
split out driver manager / app manager / store crates when those phases land.

## 4. Verification flow — security review (prompt sections 7, 31, 33)

Verdict table against section 7:

| Requirement | Status | Evidence / required change |
|---|---|---|
| Waiting screen, no emoji, no icon, minimal | OK | `WAITING_PAGE` in web.rs: typography + CSS only |
| Log `WIOOS VERIFICATION REQUEST / IP / TIME / STATUS: PENDING` | OK | printed per request in `index()`, RFC3339 UTC timestamp |
| Operator command `verify <ip>` | OK | `parse_verify_command`: exactly 2 tokens, strict `IpAddr` parse |
| Malformed IP rejected | OK | tests cover `not-an-ip` and missing IP |
| Command injection rejected | OK | no shell involved; extra tokens rejected (test `192.0.2.1; echo bad`) |
| Unknown IP: reject command + log | OK | `VerifyOutcome::NotPending` -> `STATUS: REJECTED` with reason |
| Duplicate verification handled | OK | `AlreadyVerified` -> `REJECTED`, logged |
| Race conditions | OK (single host) | `flock` exclusive lock + atomic `rename`; not multi-region (documented) |
| Fake verification state | ASSUMPTION | state is local JSON: anyone with volume write access can forge it. Accepted in threat model; volume must be operator-protected |
| Spoofed headers / do not trust XFF blindly | OK (deployment ASSUMPTION) | `resolve_client_ip` ignores `X-Forwarded-For` unless the TCP peer is inside `WIOOS_TRUSTED_PROXY_CIDRS`; malformed chain falls back to peer; 3 unit tests |
| Persistence beyond RAM | OK (deployment ASSUMPTION) | `data/verification.json`; Railway needs an attached volume at `/data` (documented in README) |

X-Forwarded-For analysis: the right-to-left walk (consume `XFF` entries while
the current hop is a trusted proxy) is the standard safe algorithm. Honest
limitation: with no `WIOOS_TRUSTED_PROXY_CIDRS` configured the recorded IP is
Railway's proxy address, so all clients share one identity and the gate cannot
distinguish users. That is a deployment blocker, not a code bug — the value must
be filled with Railway's real proxy CIDRs from trusted Railway documentation
before public launch.

Operator path analysis: the stdin loop and the `wioos-runtime verify <ip>`
argv path both call the same `parse_verify_command` + `VerificationStore::verify`
— one backend with two entry points, which satisfies section 31. The README
honestly notes Railway does not promise shell stdin attached to the running
process; the file-backed CLI path is the reliable one.

Enforcement gaps found (to fix in PHASE 1 hardening):

1. Only `/` is gated today; there is no default-deny middleware, so a future
   route can be added unprotected by accident.
2. The waiting page never re-checks status: after the operator verifies the IP
   the visitor must reload manually. Section 34 expects verification to lead to
   the main interface. Needs a self-only status endpoint plus small polling
   (no other IPs may ever be exposed).
3. No rate/volume limit: each new IP appends an entry to the state file forever
   — a cheap disk-growth vector. Needs pruning and/or a size cap.
4. No startup warning: when the peer is a private address and no trusted proxy
   CIDR is configured, the runtime should log a loud warning that client IPs
   are being recorded as the proxy address.
5. State file uses default umask permissions; should be `0600`.

Threat model and limitations (required by prompt sections 24 and 33):
verification gates access at the application's HTTP layer only. It is not an
identity system. WIOOS does not guarantee absolute security. IP-based identity
is weak behind NAT/VPN/network changes. An attacker with write access to the
volume, control of the trusted proxy layer, or privileges inside the container
can bypass or forge state. Logs contain client IPs by design (section 7) and
must be treated as sensitive. No claim is made about malware detection or
hardware control; the Railway build is a userspace prototype in a Linux
container.

Top 5 hardening actions, in order:

1. Configure `WIOOS_TRUSTED_PROXY_CIDRS` with verified Railway proxy CIDRs and
   add the startup warning from gap 4.
2. Add default-deny gate middleware with `/health` allowlist (gap 1).
3. Add self-only status endpoint + waiting-page polling (gap 2) so the
   section-34 flow (verify -> main interface appears) works without a manual
   reload.
4. Add state-file size cap/pruning and `0600` permissions (gaps 3 and 5).
5. Pin the toolchain (`rust-toolchain.toml`), add CI running
   `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --workspace`,
   add `LICENSE`.

## 5. Build / test / deployment checklist (prompt section 35)

Commands that must pass before PHASE 1 is declared stable:

```sh
cargo fmt --check
cargo clippy --all-targets --workspace -- -D warnings
cargo test --workspace
cargo build --release --workspace
```

Validation results (2026-10-07, this environment):

- `cargo fmt --check` — PASS (formatting was applied first)
- `cargo clippy --all-targets --workspace -- -D warnings` — PASS (0 warnings)
- `cargo test --workspace` — PASS (6/6 tests: command parsing, injection
  rejection, XFF trust rules, persistence/duplicate handling)
- `cargo build --release --workspace` — PASS
- Live end-to-end check of the section-7/34 flow — PASS: request 1 returned
  `Waiting for verification` with log `WIOOS VERIFICATION REQUEST / IP / TIME /
  STATUS: PENDING`; `verify 127.0.0.1` printed `STATUS: VERIFIED`; duplicate
  verify and unknown-IP verify printed `STATUS: REJECTED`; request 2 returned
  `Access granted`; `/health` returned `ok`.

Deployment shape: `railway.json` builds the `Dockerfile`, health-checks
`/health`, restarts on failure. The Docker image runs as non-root user `wioos`
(uid 10001) with state at `/data`. A real Railway deploy (public URL, verify
flow, volume attach) has NOT been exercised from this environment and remains
an open verification item.

## 6. Assumptions and unknowns

- Railway proxy CIDRs, volume availability and deploy status: unknown here;
  must be confirmed against official Railway documentation / the owner's
  project settings.
- Docker image build not executed in this environment (daemon unverified).
- The concurrent writer of the Phase-1 files (external session) is not
  identified; the files were reviewed here and treated as baseline.
- Repository/org naming conflict (`anbatocom123458-star` vs prompt's `wioos28`)
  is an owner decision, not silently resolved.

## 7. Gate to PHASE 2

PHASE 2 (WIO UI shell, home screen, Settings, Time Service, Network Center)
must not start until: the section-5 commands pass, the 5 hardening actions are
done or explicitly deferred by the owner, and one Railway deploy with a real
verification flow has been observed.
