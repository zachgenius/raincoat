# Raincoat — macOS GUI (menu-bar tray + Spotlight-style launcher)

**Status:** design + in progress on the `macos-gui` branch. GUI-only; the sandbox mechanism is
unchanged. Nothing here is a daemon — the CLI stays the single source of sandbox truth.

## Goals

macOS/Windows users live in a GUI, where a CLI-per-invocation sandbox is invisible. Two additions,
both **thin layers over the existing `raincoat` CLI**:

1. **Menu-bar tray** — a read-only `NSStatusItem` that shows what is currently running under Raincoat,
   with per-capability honesty (never one green check), a link to each run's audit log, and a Kill button.
2. **Spotlight-style launcher** — a global hotkey (default **⌥Space**, configurable — deliberately not
   Spotlight's ⌘Space) pops a floating search panel; type an app/command, Enter launches it under Raincoat.

**Non-goals:** a daemon or background service that *owns* sandboxes; a policy engine; per-glyph
anti-fingerprinting. The tray is an aggregator/reader; the launcher shells out to `raincoat`.

## Architecture — three pieces, one contract

```
  raincoat CLI (C++)                 run-status files                GUI app (Swift/AppKit)
  ─────────────────                  ───────────────                 ──────────────────────
  on launch:  write <pid>.json  ───▶ ~/Library/Application    ◀────  menu-bar: read the dir,
  on teardown: remove <pid>.json     Support/Raincoat/run/            one row per live run
                                                                      launcher: spawn `raincoat -- …`
```

The **run-status file** is the entire C↔Swift contract. The GUI never links the C++ core, never
applies a sandbox itself, and holds none of a sandbox's trust. A future Windows tray reuses the same
schema.

### 1. Run-status protocol (C++, `src/run_status.{hpp,cpp}`)

Each real sandbox run writes one JSON file, `<runtime_dir>/run/<supervisor_pid>.json`, right after the
child is forked (`runner.cpp`, once `g_child_pid` is set), and removes it in `cleanup_root()` (the same
teardown that already survives SIGINT/SIGTERM). **Best-effort:** any write/remove error is ignored — the
status file is purely informational and must never affect a run.

`<runtime_dir>`:
- macOS: `~/Library/Application Support/Raincoat`
- Linux: `$XDG_RUNTIME_DIR/raincoat` else `${TMPDIR:-/tmp}/raincoat-$UID`

Schema (`"schema": 1`):

```json
{
  "schema": 1,
  "supervisor_pid": 12345,        // the raincoat process (owns the file, forwards signals)
  "child_pid": 12346,             // the sandboxed process
  "command": "node build.js",     // display-safe (secret env values already redacted)
  "audit_log": "/Users/me/proj/.raincoat/audit.log",
  "backend": "Seatbelt (sandbox-exec, best-effort)",   // caps.label
  "net_mode": "off|open|proxied|egress-bridge",
  "started_at": 1720190940,       // unix seconds (time(NULL))
  "capabilities": {               // per-capability honesty, NOT a single verdict
    "filesystem": "confined",
    "network": "blocked|open|proxied",
    "identity": "faked|partial|off"
  },
  "notes": ["…selected active_policy_notes…"]
}
```

Liveness: the tray treats a file as stale if `kill(supervisor_pid, 0)` fails (ESRCH) — covers a
`SIGKILL`ed raincoat that never ran `cleanup_root()` (the same orphan gap disclosed for `die_with_parent`).
The tray may unlink stale files opportunistically.

### 2. Menu-bar tray (Swift/AppKit)

- `NSStatusItem` with a Raincoat glyph; badge = live run count.
- Menu lists one item per live run: `command` + a compact capability line
  (`fs ✓ · net proxied · identity faked` — or `identity N/A (hardened)`), submenu with **Reveal audit
  log**, **Copy command**, **Kill** (`kill(child_pid)` then the supervisor).
- Watches the run dir with a `DispatchSource` FS-event (fallback: 1 s poll). Pure reader.

### 3. Spotlight-style launcher (Swift/AppKit)

- **Global hotkey** via Carbon `RegisterEventHotKey` — reliable and needs **no Accessibility
  permission** (unlike an `NSEvent` global monitor). Default ⌥Space, stored in `UserDefaults`.
- **Panel**: a borderless, non-activating `NSPanel` (floating, centered), single search field + results
  list, `↑/↓/Enter/Esc`. Fuzzy-matches: installed apps (`/Applications`, `~/Applications`,
  `NSMetadataQuery`/LaunchServices) + recent commands (persisted).
- **Launch**: spawn `raincoat -- <resolved>`; raincoat writes its own status file, so the new run
  appears in the tray. No IPC needed beyond the status dir.

## The honest GUI-app caveats (surface, don't hide)

The launcher must resolve and disclose these — they are OS facts, not Raincoat bugs:

1. **`open -a` re-parents to `launchd`** → the app escapes the sandbox. The launcher must exec the
   bundle's real binary directly: `<App>.app/Contents/MacOS/<exe>` (from the bundle `Info.plist`
   `CFBundleExecutable`). Some apps misbehave when not launched via LaunchServices — disclosed.
2. **Hardened-runtime apps ignore `DYLD_INSERT_LIBRARIES`** → no identity faking for most commercial
   GUI apps (Chrome/Slack/…). Seatbelt **fs/net confinement still applies** (inherited across exec).
   The launcher tags such apps `identity: N/A (hardened)` so the tray never overclaims.
3. **Multi-process apps** (Chrome helpers, XPC services spawned via launchd) escape a per-process
   sandbox. Best for CLI tools + single-binary apps; disclosed for the rest.

## Build & packaging

- Separate **SwiftPM** target under `macos-app/` (Swift 6, AppKit). Not part of the CMake build.
- A menu-bar-only app: `Info.plist` `LSUIElement = true`. A small bundling step wraps the SwiftPM
  executable into `Raincoat.app` (Info.plist + icon); optional `LaunchAgent` for start-at-login.
- **Signing:** dev builds run unsigned (hotkey + login-item are flaky unsigned but functional);
  distribution needs Developer ID signing + notarization. Documented, not required to build.
- The app finds the `raincoat` binary via `$PATH`, common install dirs, a configured path, then the
  copy **bundled inside the app** (see below).

## Bundled CLI & install

The app is **self-contained**: `scripts/embed-raincoat.sh` builds the `raincoat` C++ CLI and drops it
into `Raincoat.app/Contents/Helpers/raincoat`, code-signed. It runs from both packaging paths — the
SwiftPM `scripts/make-app-bundle.sh` (before the ad-hoc outer signature) and the Xcode target (a
`postCompileScripts` "Embed raincoat CLI" phase in `project.yml`, before Xcode's final signing). It is
**non-fatal without cmake**: a machine with no C++ toolchain builds the app *without* the CLI, and the
app degrades to reporting "not found".

`RaincoatLocator` resolution order (`find()`): `$PATH` → `/usr/local/bin`, `/opt/homebrew/bin` →
`UserDefaults` override → **bundled copy**. The bundled fallback is why the GUI works with no prior
install. `findOnPath()` is the same minus the bundled copy — `RaincoatInstaller` uses it to decide
whether `raincoat` is actually reachable from a shell.

**Install (expose on `$PATH`).** `RaincoatInstaller` manages exactly one symlink,
`/usr/local/bin/raincoat -> <app>/Contents/Helpers/raincoat` (`/usr/local/bin` is on the default
shell PATH via `/etc/paths`). It tries an **unprivileged** symlink first (a Homebrew-style user-owned
`/usr/local/bin` needs no auth) and only escalates to a native admin prompt (`osascript … with
administrator privileges`) when the write is denied. `Status` distinguishes `installedManaged` (our
symlink), `installedExternal` (the user's own raincoat — never touched), `bundledOnly` (present but not
on PATH), and `missing`. Uninstall removes **only** the managed symlink.

- **First-run prompt** (`AppDelegate.maybePromptCLIInstall`): on launch, if status is `bundledOnly`,
  offer to install with `Install… / Not Now / Don't Ask Again` (the last sets a `UserDefaults` flag).
  Never shown when raincoat is already on PATH, or for un-bundled dev builds.
- **Preferences → "Command-line tool"** row: contextual `Install / Reinstall / Uninstall / Reveal`
  buttons plus a status line reflecting the same four states.
- Headless check: `RaincoatMenuBar --selftest-install` prints bundled path, PATH resolution, and the
  resulting `Status` (no auth, no writes).

**Hardened Runtime note.** The bundled CLI is signed with Hardened Runtime + the
`com.apple.security.cs.disable-library-validation` entitlement (`scripts/raincoat-helper.entitlements`).
Without it a hardened raincoat **SIGABRTs at launch**: it dynamically links third-party dylibs (Homebrew
OpenSSL) whose Team IDs differ, and library validation refuses to load them.

> **⚠ Distribution blockers (not yet solved).** The embedded binary here still links **Homebrew
> OpenSSL at absolute paths** (`/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib`, `…/libcrypto.3.dylib`)
> and is built **arm64-only**. A shippable app must (1) make OpenSSL resolvable on machines without
> Homebrew — statically link it, or bundle the dylibs and rewrite install names to `@loader_path` — and
> (2) build a **universal** binary (`RAINCOAT_UNIVERSAL=1` sets `-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"`,
> which also requires universal OpenSSL). Until then the bundled CLI is dev-only.

## Phasing

1. **Run-status protocol** (C++) + tests — the contract. *(this branch, first)*
2. **Menu-bar tray** — read-only viewer over the status dir.
3. **Launcher** — global hotkey + panel + app resolution with the caveats above.
4. Polish: preferences (hotkey, raincoat path, default profile), start-at-login, icon.
