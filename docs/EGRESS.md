# Raincoat — Egress Bridge / Endpoint Indirection (NEXT PHASE, not yet implemented)

Status: **planned / next phase.** Implement only after the core MVP is finished, committed, and pushed.

## Goal
Let the child process see only a **local or generic endpoint**, while Raincoat privately forwards
traffic to the real upstream endpoint outside the sandbox. The child never learns the real upstream
hostname (from its environment), and the profile that contains the upstream is not mounted into the
sandbox unless the user explicitly allows it.

**Generic by construction.** No hard-coded agent, model provider, environment variable name, or
service. Everything is driven by **profile configuration**, never agent-specific CLI flags.

## Profile schema
```toml
[egress]
mode = "bridge"          # off | bridge (MVP). reserve: transparent, mitm (later, disabled by default)

[[egress.bridge]]
name = "primary-api"
env = "SOME_BASE_URL"                       # the ONLY env var injected into the child for this bridge
child_endpoint = "http://127.0.0.1:18080"   # what the child sees / connects to
upstream_endpoint = "https://real-upstream.example.com"  # host-side only; NEVER shown to the child
hide_upstream_from_child = true
preserve_host = false     # if false, rewrite Host header to the upstream host; if true, keep child's
```
`[[egress.bridge]]` is an array-of-tables: **multiple bridge entries** must be supported.

## Required behavior (MVP)
1. Read the profile on the HOST side BEFORE starting the sandbox.
2. Start a local egress bridge listening on each `child_endpoint`.
3. Inject ONLY the configured child-visible env var (`env` -> `child_endpoint`) into the child.
4. Child sees e.g. `SOME_BASE_URL=http://127.0.0.1:18080`.
5. Child does NOT see the real upstream endpoint anywhere in its environment.
6. The profile file (which contains the upstream) is NOT mounted into the sandbox unless the user
   explicitly allows it (`--allow-read`/`--allow-write` of that path). Default: not mounted.
7. Forward requests from the local child endpoint to the configured upstream endpoint.
8. Preserve request method, path, query string, headers, and body where appropriate.
9. Support streaming responses where practical (many agent/CLI HTTP APIs stream).
10. Log that an egress bridge was enabled — but NOT secret values or sensitive request bodies.

### Audit log (example)
```
Egress bridge enabled: primary-api
Child-visible endpoint: http://127.0.0.1:18080
Upstream endpoint: hidden
Injected env var: SOME_BASE_URL
```
Do NOT log the real upstream endpoint by default. A future verbose/debug mode must require explicit
opt-in before logging upstream endpoints.

## Scope
- **MVP:** basic HTTP forwarding first (child_endpoint is plain HTTP on loopback).
- **Longer-term:** HTTPS upstreams; streaming responses; multiple bridge entries; header rewrite
  rules; Host header policy; domain allow/block policy; optional transparent egress mode; optional
  explicit MITM mode (disabled by default).

## Limitations to document (honestly)
- The bridge hides the real upstream **hostname** from the child's environment.
- It does NOT necessarily hide the fact that the child is using a custom/local endpoint.
- Full HTTPS hostname rewriting without exposing a custom endpoint may require MITM, control of the
  original certificate, or transparent network-level routing.
- Raincoat must NOT claim to bypass detection by any specific tool or service.

## Key implementation consideration (network namespace interaction) — resolve during design
The child reaches the bridge at `127.0.0.1:<port>`. That only works if the child's loopback is the
same loopback the host bridge listens on:
- With **`--net full`** (no `--unshare-net`), the sandbox shares the host network namespace, so the
  child's `127.0.0.1` IS the host loopback and reaches the bridge. This is the straightforward MVP
  path, BUT it means the child also has general network access.
- With **`--net off`** (`--unshare-net`), the child gets an isolated netns whose loopback is NOT the
  host's, so a host-side loopback bridge is unreachable. Making egress-only networking work under an
  otherwise-isolated netns needs one of: a veth pair + host-side forwarding, a userspace network
  (slirp/passt/pasta), an abstract/UNIX socket shim, or transparent routing — all deferred.
- **MVP decision (proposed):** when `[egress] mode = "bridge"` is active, run the child so it can
  reach the bridge (share loopback / net path), and DOCUMENT that egress-bridge mode currently
  implies the child can reach the local bridge. Design the code so a future "egress-only" netns
  (bridge reachable, everything else blocked) can slot in without changing the profile schema.

## Suggested module shape (for the implementation phase)
- New `egress` module: parse `[egress]` + `[[egress.bridge]]` from the profile (via the `toml`
  module — extend it for array-of-tables `[[...]]` if not already supported), start/stop host-side
  listeners, forward HTTP with streaming, and expose the injected env pairs + audit lines.
- `net_guard`/`runner` interplay for loopback reachability (see above).
- Env injection: the bridge's `env=child_endpoint` pairs feed into the child env like `--set-env`,
  but are sourced from the egress config, not the CLI.
- Audit: `egress` provides redacted audit lines (upstream hidden by default).
- Keep it generic: nothing provider-specific anywhere.
