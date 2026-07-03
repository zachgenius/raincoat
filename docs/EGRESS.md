# Raincoat — Egress Bridge / Endpoint Indirection

Status: **implemented (MVP).** Host-side HTTP(S) forward proxy per bridge (`src/egress.*`), wired
into the live sandbox by the runner. See the honest networking model below.

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

## Scope — implemented in the MVP vs future
**Implemented now (`src/egress.*`, wired into the runner):**
- Plain-HTTP `child_endpoint` on the host loopback (one listener per bridge; thread-per-connection).
- **HTTPS upstreams** — TLS is terminated to the upstream via OpenSSL (`upstream_endpoint = "https://…"`).
- **Streaming responses** — the upstream response is piped back to the child until EOF, so
  chunked/streamed agent/LLM APIs work (`[egress].streaming`, default true).
- **Multiple bridge entries** — each `[[egress.bridge]]` gets its own loopback listener and its own
  injected env var.
- **Host header policy** via `preserve_host` (send the upstream's Host, or keep the child's).
- **Header rewrite** — per-bridge `strip_headers` (drop request headers before forwarding) and
  `inject_headers` (add headers to the upstream request, never shown to the child). Hop-by-hop
  `Connection`/`Proxy-Connection` headers are dropped and `Connection: close` is forced (MVP: no
  keep-alive).
- **Env injection + upstream hiding** — only `env = child_endpoint` reaches the child; the upstream
  URL is kept host-side and the profile is masked if reachable inside the sandbox.
- **Audit redaction** — upstreams recorded as `hidden` by default (see below).

**Still future (deferred; the schema/code is shaped so these slot in):**
- A true **network jail** — an egress-only netns (bridge reachable, everything else blocked) via a
  veth pair + host forwarding or a userspace net (slirp/passt/pasta). Today egress shares the host
  net namespace (see Limitations).
- **`guarded` mode / domain allow-block policy** and **DNS policy** (`[network_policy]`, `[dns]`) —
  parsed/reserved, not enforced.
- **Transparent egress mode** (no explicit endpoint) and an explicit **MITM mode** (disabled by
  default), which would be needed for full HTTPS hostname rewriting without a custom endpoint.

## Limitations to document (honestly)
- The bridge hides the real upstream **hostname/URL** from the child's **environment/config** — the
  child is only handed `child_endpoint` via the injected env var, and a `--profile` reachable inside
  the sandbox is masked (shadowed with an empty file) so the upstream cannot be read out of it.
- **The upstream is NOT network-jailed and its resolved IP:port is observable to the child.** Because
  an active egress bridge SHARES the host network namespace (no `--unshare-net`, see below), the child
  can read raincoat's live connection to the upstream out of `/proc/net/tcp` (e.g. a `127.0.0.1:19191`
  upstream appears there as `0100007F:4AF7`). The bridge hides the upstream *URL* from the child's
  env/config; it does NOT hide the upstream *IP:port* from a child that inspects shared `/proc/net`.
  A true jail (net-namespace isolation + a veth/slirp path) is out of MVP scope. The audit line
  discloses this shared-net model explicitly so it is never a silent leak.
- The child also retains **general network access** under the shared namespace — the bridge is
  URL-indirection, not a network firewall.
- It does NOT necessarily hide the fact that the child is using a custom/local endpoint.
- Full HTTPS hostname rewriting without exposing a custom endpoint may require MITM, control of the
  original certificate, or transparent network-level routing.
- Raincoat must NOT claim to bypass detection by any specific tool or service.

## Audit redaction (per-bridge)
By default every upstream is recorded as `Upstream endpoint: hidden`. Redaction for a bridge is
forced on when ANY of: the global `[egress].redact_upstreams_in_audit` is true (default), the
bridge's own `hide_upstream` is true (default), or the audit log is child-readable (fail-closed,
regardless of the settings). To surface exactly one upstream in the audit you must BOTH set
`[egress].redact_upstreams_in_audit = false` AND set that single bridge's `hide_upstream = false`;
every other bridge stays hidden by its own default-true `hide_upstream`.

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
- **MVP decision (implemented):** when `[egress] mode = "bridge"` is active, the runner does NOT
  unshare the net namespace, so the child shares the host loopback and reaches the bridge. This is
  the documented tradeoff: the child can reach the local bridge AND retains general host network
  access, and the upstream IP:port is visible via shared `/proc/net/tcp` (see Limitations). This
  REPLACES the earlier phase-1.5 "bridge fails closed to off" placeholder for the case where
  bridges are actually configured. The code is structured so a future "egress-only" netns (bridge
  reachable, everything else blocked) can slot in without changing the profile schema.

## Suggested module shape (for the implementation phase)
- New `egress` module: parse `[egress]` + `[[egress.bridge]]` from the profile (via the `toml`
  module — extend it for array-of-tables `[[...]]` if not already supported), start/stop host-side
  listeners, forward HTTP with streaming, and expose the injected env pairs + audit lines.
- `net_guard`/`runner` interplay for loopback reachability (see above).
- Env injection: the bridge's `env=child_endpoint` pairs feed into the child env like `--set-env`,
  but are sourced from the egress config, not the CLI.
- Audit: `egress` provides redacted audit lines (upstream hidden by default).
- Keep it generic: nothing provider-specific anywhere.
