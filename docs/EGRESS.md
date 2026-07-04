# Raincoat — Egress Bridge / Endpoint Indirection

Status: **implemented (MVP).** Host-side HTTP(S) forward proxy per bridge (`src/egress.*`), wired
into the live sandbox by the runner. See the honest networking model below. A separate
**guarded proxy** (`[network_policy]`, `src/proxy.*`) enforces a domain allow/block policy over the
child's general egress — see [Network policy / guarded proxy](#network-policy--guarded-proxy-filtering-forward-proxy).

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

**Isolated network namespace (IMPLEMENTED — pasta jail):**
- When an egress bridge is active AND `pasta` is available AND the profile does not opt out
  (`[egress].isolate_netns != "off"`, default `auto`), the child runs inside pasta's private
  network namespace: `pasta --config-net -t none -T <bridge-ports> -- bwrap …`. bwrap does NOT
  `--unshare-net` in this mode — it JOINS pasta's netns. MEASURED on a real host:
  - the child reaches each bridge at its unchanged `127.0.0.1:<child_port>` (pasta forwards that
    ns-loopback port to the host-side bridge via `-T`);
  - **the `/proc/net/tcp` upstream leak is FIXED** — the host-side bridge's upstream socket lives
    in the HOST netns, so it is invisible from inside the child's namespace;
  - `-t none` makes the jail TIGHTER than shared mode: only the forwarded bridge port(s) are
    reachable on the ns loopback — other host-loopback services are NOT;
  - the child is **NOT** fully network-jailed: pasta NATs general outbound traffic, so the child
    retains general outbound internet by IP. This is a **NAT, not a per-destination firewall** —
    the audit says so explicitly and never overclaims.
- **`isolate_netns = "strict"` — the real "only the bridge" firewall (IMPLEMENTED).** Strict keeps
  everything above AND blocks the child's general internet by adding `-o 127.0.0.1` to the pasta
  invocation: `pasta --config-net -t none -o 127.0.0.1 -T <bridge-ports> -- bwrap …`. `-o 127.0.0.1`
  binds pasta's outbound to loopback, so pasta can no longer NAT the child's traffic out any real
  interface — only the `-T` bridge forward(s) keep working. MEASURED on this host: with `-o 127.0.0.1`
  the child's connections to real IPs (e.g. `1.1.1.1`) **time out**, while the forwarded bridge port
  **still reaches the upstream**. The child can therefore reach **ONLY** the configured bridge
  endpoint(s) — **no general internet, and no other host-loopback service**. For the strict level
  **only**, this is a genuine **per-destination (bridge-only) egress firewall**; the audit + a stderr
  note say exactly that. Strict **requires pasta**: there is no safe shared-loopback equivalent
  (sharing the host loopback would hand the child general host network), so `strict` with pasta
  **absent fails CLOSED** — the run is refused with a clear, actionable error rather than silently
  downgraded to general internet. (`auto`/`on` are unchanged: they still NAT general outbound.)
- When `pasta` is absent (or `isolate_netns = "off"`) raincoat falls back to the shared-loopback
  model below, with the honest shared-net warning. (`strict` is the exception: it refuses instead of
  falling back, so "strict" never silently means "general internet".)
- `raincoat doctor` reports whether the jail is available: `[ OK ] egress network jail:
  available (pasta) <path>` when pasta (or slirp4netns) is present, or `[INFO] … unavailable —
  egress bridge shares the host network namespace` otherwise. It is informational, never a
  `[FAIL]` — a missing helper only means the shared-loopback fallback is used.

**Still future (deferred; the schema/code is shaped so these slot in):**
- A general **domain/CIDR allow-list egress firewall** (reach an arbitrary *set* of named upstreams,
  everything else blocked). Note the **`strict` level already provides the bridge-only case** of this
  — with `isolate_netns = "strict"` (pasta required) the child reaches ONLY the forwarded bridge
  port(s) and nothing else, general internet included. What remains future is a *configurable* per
  destination/domain policy beyond "only the configured bridge endpoint(s)". The `auto`/`on` NAT jail
  still does not filter arbitrary outbound internet.
- **Host-loopback mapping on newer pasta** (`--map-host-loopback`). The pasta build measured here
  is older and lacks it, so the host is reached via NAT (the ns default gateway) rather than the
  child's `127.0.0.1`. The bridge sidesteps this by keeping the host-side listener and letting
  pasta `-T` forward the ns-loopback bridge port to it, so `child_endpoint = http://127.0.0.1:PORT`
  still works unchanged; a newer pasta would simply make host-loopback reachability native.
- **DNS policy** (`[dns]`) — parsed/reserved, not enforced.
- **Transparent egress mode** (no explicit endpoint) and an explicit **MITM mode** (disabled by
  default), which would be needed for full HTTPS hostname rewriting without a custom endpoint.

> **Note — `guarded` / `[network_policy]` is now IMPLEMENTED (phase 4).** The domain allow/block
> policy is enforced by a host-side filtering forward proxy (`src/proxy.*`); see the dedicated
> **[Network policy / guarded proxy](#network-policy--guarded-proxy-filtering-forward-proxy)**
> section below. It is a *name-based* allow/block firewall (composed with the strict netns jail),
> not a CIDR firewall, and — without the jail — only constrains proxy-aware clients.

## Network policy / guarded proxy (filtering forward proxy)
Status: **implemented (phase 4).** Distinct from the egress *bridge* above: the bridge does URL
indirection for a *known* upstream; the **guarded proxy** enforces a **domain allow/block policy**
over the child's *general* HTTP(S) egress. Driven entirely by `[network_policy]` — no
provider/service names baked in.

### How it works
When `[network_policy].enabled`, the runner starts a small host-side **filtering forward proxy**
(`src/proxy.*`, `ProxyServer`) bound on a loopback ephemeral port BEFORE launching the sandbox,
then injects the proxy endpoint into the child as **both** the lowercase and UPPERCASE spellings of
`http_proxy` / `https_proxy` / `all_proxy`. Any pre-existing proxy vars (from `[proxy]`,
`--set-env`, `--allow-env`, in any case) are **erased first**, and `no_proxy` is left **absent** (an
empty bypass list) so a proxy-aware client cannot be told to skip the guard. Raincoat's guarded
proxy therefore takes precedence over any external proxy, and an external proxy URL (which can carry
credentials) is never handed to the child.

The proxy checks each request's target **host** against the policy and:
- **Plain HTTP** — parses the absolute-form request line (`GET http://host/path`), applies policy,
  and if allowed forwards the request to the origin and streams the response back. A blocked host
  gets `HTTP/1.1 403 Forbidden`.
- **HTTPS via `CONNECT`** — applies policy on the host; if allowed, replies `200 Connection
  Established` and **blind-tunnels** bytes both ways (**no TLS interception / no MITM**); if blocked,
  replies `403` and closes. Because there is no MITM, only the CONNECT target host (SNI-equivalent)
  is policy-checked, not the inner HTTP request.

### Policy engine (`host_allowed`, pure + unit-tested)
Evaluated in order:
1. **`block_hosts` wins** — exact match or dot-suffix match (`evil.com` blocks `api.evil.com`). A
   blocked host is never allowed regardless of `default_action`.
2. **Metadata blocking** (when `block_private_metadata_endpoints`, default true) — blocks the cloud
   metadata endpoints `169.254.169.254`, `[fd00:ec2::254]`, `metadata.google.internal`, the bare
   name `metadata`, every entry in `metadata_endpoints`, ANY link-local `169.254.0.0/16` literal,
   and the numeric IPv4/IPv6 forms of a metadata address.
3. **`default_action`** — `"deny"` allows ONLY hosts matching `allow_hosts` (exact/dot-suffix), i.e.
   allow-list mode; `"allow"` permits anything not blocked above (block-list mode).

An empty/unparseable host **fails closed** (denied). A typo'd `default_action` in a profile is
**rejected** (not silently defaulted), so `"den"` can never silently degrade an intended `"deny"`
allow-list.

### SSRF / DNS-rebinding guard (post-resolution recheck)
After policy passes on the literal request host, the proxy re-checks **every** address
`getaddrinfo` returns *before dialing* and refuses (`403`) if any resolved address is a `block_hosts`
IP literal or (when enabled) a metadata / link-local address. This closes the "name that resolves to
a blocked/metadata IP" bypass on both the HTTP and CONNECT paths.

### The jail composition — real firewall vs proxy-only-clients
The guarded proxy's strength depends **entirely** on whether the child can go *around* it. Raincoat
composes it with the pasta netns jail (`[egress].isolate_netns`) and discloses the active mode in
the audit **and** on stderr every run:

| Mode | What the jail does | What the policy is |
|------|--------------------|--------------------|
| `isolate_netns = "strict"` (pasta required) | `pasta … -o 127.0.0.1 -T <proxy-port>` forwards ONLY the proxy port and blocks all other outbound | **A REAL domain-level egress firewall** — the proxy is the child's ONLY egress path; direct/raw-IP/proxy-ignoring connections are blocked. |
| `auto` / `on` (NAT jail) | pasta NATs general outbound | **Proxy-aware clients only** — a client that ignores `http_proxy` or dials a raw IP still reaches the internet. |
| shared loopback (no pasta / `isolate_netns = "off"`) | none — child shares the host net namespace | **Proxy-aware clients only** — plus the child retains general host network access. |

So: **only `strict` (with pasta) turns the allow/block list into a genuine firewall.** In the other
modes it constrains *cooperating* clients but a non-proxy-aware or raw-IP client bypasses it — the
stderr note and audit say exactly this, and never overclaim. To use a **name** block-list as a hard
firewall even in strict mode, also list the pinned IP literal(s) and/or prefer `default_action =
"deny"` with an explicit allow-list, because name-based filtering cannot reverse-map an IP back to a
blocked name (the NAME-vs-IP asymmetry, documented in `src/proxy.hpp`).

### Netns / conflict rules
Like the bridge, the guarded proxy needs loopback reachability, so the sandbox must share the host
netns or join the pasta jail with the proxy port forwarded. `[network_policy].enabled` therefore
**conflicts with `--net off`** and Raincoat refuses that combination with an actionable error rather
than silently disabling the policy.

### Audit
When active, the audit records (text and JSON): `Network policy: enabled (default <action>)`, the
`Guarded proxy: http://127.0.0.1:<port>` endpoint, `allow hosts` / `block hosts` **counts** (never
the host names), and whether metadata blocking is on. If an external proxy was also configured, the
audit notes that the guarded proxy **overrode** it (the external URL is never logged). Host names and
request bodies are never written.

## Limitations to document (honestly)
- The bridge hides the real upstream **hostname/URL** from the child's **environment/config** — the
  child is only handed `child_endpoint` via the injected env var, and a `--profile` reachable inside
  the sandbox is masked (shadowed with an empty file) so the upstream cannot be read out of it.
- **In shared-loopback mode, the upstream's resolved IP:port is observable to the child.** When the
  bridge runs WITHOUT the pasta jail (`isolate_netns = "off"`, or pasta not installed) the sandbox
  SHARES the host network namespace (no `--unshare-net`), so the child can read raincoat's live
  connection to the upstream out of `/proc/net/tcp` (e.g. a `127.0.0.1:19191` upstream appears there
  as `0100007F:4AF7`). The bridge hides the upstream *URL* from the child's env/config; in this mode
  it does NOT hide the upstream *IP:port* from a child that inspects shared `/proc/net`. The audit
  line discloses this shared-net model explicitly so it is never a silent leak.
  **The isolated-netns (pasta) mode FIXES this specific leak** — see the isolated-netns section
  above — because the bridge's upstream socket then lives in the host netns, invisible to the child.
- The child retains **general outbound network access** in the shared-loopback and the `auto`/`on`
  NAT'd-via-pasta modes — there the bridge is URL-indirection, not a per-destination network
  firewall. **The exception is `isolate_netns = "strict"`** (pasta required), which binds pasta's
  outbound to loopback (`-o 127.0.0.1`) and so **blocks** general outbound: in strict mode the child
  reaches only the forwarded bridge port(s) — that mode *is* a per-destination (bridge-only) firewall.
- It does NOT necessarily hide the fact that the child is using a custom/local endpoint.
- Full HTTPS hostname rewriting without exposing a custom endpoint may require MITM, control of the
  original certificate, or transparent network-level routing.
- **The guarded proxy (`[network_policy]`) is a real domain-level egress firewall ONLY with the
  strict netns jail.** Without `isolate_netns = "strict"` (pasta required) — i.e. on the shared
  network or under the `auto`/`on` NAT jail — it only constrains **proxy-aware** clients: a client
  that ignores `http_proxy`/`https_proxy` or dials a **raw IP** bypasses the policy entirely. There
  is **no transparent interception** of non-proxy-aware clients without the jail; the audit + a
  stderr note disclose which case is in effect every run.
- **The guarded proxy does not MITM TLS.** HTTPS is handled via `CONNECT` blind-tunnel, so only the
  connect-target hostname is policy-checked; the inner request/SNI is not inspected. Name-based
  block-lists are also subject to the NAME-vs-IP asymmetry (a name blocked purely by name is still
  reachable by its IP unless the IP is also listed / `default_action = "deny"` is used).
- **DNS policy (`[dns]`) is not enforced** — reserved for future work.
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
- **Implemented — isolated netns (default when pasta present):** when `[egress] mode = "bridge"` is
  active and pasta is available and `isolate_netns != "off"`, the runner wraps bwrap with
  `pasta --config-net -t none -T <bridge-ports>`. bwrap does NOT `--unshare-net` (it joins pasta's
  netns). The child reaches `127.0.0.1:<port>` because pasta's `-T` forwards that ns-loopback port
  to the host-side bridge; the upstream socket stays in the host netns (fixing the `/proc/net/tcp`
  leak); `-t none` exposes only the bridge port(s); pasta NATs general internet (not a firewall).
  pasta runs as raincoat's direct child and propagates the child's exit code; it is reaped/torn
  down on every exit path (normal, error, signal) with no orphans.
  **With `isolate_netns = "strict"`** the runner additionally passes `-o 127.0.0.1`
  (`pasta --config-net -t none -o 127.0.0.1 -T <bridge-ports>`), binding pasta's outbound to
  loopback so general internet is blocked and ONLY the forwarded bridge port(s) remain reachable — a
  real per-destination (bridge-only) firewall. Strict requires pasta; with pasta absent it fails
  CLOSED (refused) rather than sharing the host loopback.
- **Implemented — shared loopback (fallback):** when pasta is absent or `isolate_netns = "off"`, the
  runner does NOT unshare the net namespace, so the child shares the host loopback and reaches the
  bridge. Tradeoff: the child retains general host network access and the upstream IP:port is
  visible via shared `/proc/net/tcp` (see Limitations). The audit + a stderr warning disclose the
  active model in both cases so behavior is never a silent surprise.

## Suggested module shape (for the implementation phase)
- New `egress` module: parse `[egress]` + `[[egress.bridge]]` from the profile (via the `toml`
  module — extend it for array-of-tables `[[...]]` if not already supported), start/stop host-side
  listeners, forward HTTP with streaming, and expose the injected env pairs + audit lines.
- `net_guard`/`runner` interplay for loopback reachability (see above).
- Env injection: the bridge's `env=child_endpoint` pairs feed into the child env like `--set-env`,
  but are sourced from the egress config, not the CLI.
- Audit: `egress` provides redacted audit lines (upstream hidden by default).
- Keep it generic: nothing provider-specific anywhere.
