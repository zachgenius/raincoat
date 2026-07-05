# Raincoat — macOS menu-bar GUI

A menu-bar-only agent app that adds two thin, GUI-native layers over the existing
`raincoat` CLI. It is **read-only** with respect to sandboxes: it never links the C++
core, never applies a policy, and holds none of a sandbox's trust. See
[`docs/GUI-MACOS.md`](../docs/GUI-MACOS.md) for the architecture and the run-status
schema, which is the entire contract between the CLI and this app.

Two features:

1. **Menu-bar tray** — an `NSStatusItem` (badge = live-run count) that aggregates every
   `*.json` in `~/Library/Application Support/Raincoat/run/`. One row per **live** run
   shows the `command` plus an honest per-capability line
   (`fs ✓ · net proxied · identity faked`) — `identity` (`faked`/`partial`/`off`) and
   `network` (`blocked`/`open`/`proxied`) are rendered verbatim, never collapsed into a
   single green check. Each row's submenu has **Reveal Audit Log**, **Copy Command**, and
   **Kill** (SIGTERM the child, then the supervisor). The directory is watched with a
   `DispatchSource` vnode event plus a 1 s poll fallback.

2. **Spotlight-style launcher** — a global hotkey (default **⌥Space**) pops a borderless,
   floating search panel. Fuzzy-match over installed apps + recent commands; `↑/↓` move,
   `Enter` launches under `raincoat`, `Esc`/click-away dismisses. Launching an app execs
   its **real** binary (`…/Contents/MacOS/<CFBundleExecutable>`) directly rather than
   `open -a`, which would re-parent to `launchd` and escape the sandbox.

3. **Preferences + start-at-login** — a `⌘,` window (from the status menu) to rebind the
   global hotkey (a click-to-record control), point at a specific `raincoat` binary, set a
   default profile passed as `raincoat --profile <p> -- …`, and toggle **Start at Login**
   via `SMAppService`.

## Requirements

- macOS 14+ (deployment target; the honest liveness/`assumeIsolated` paths use it).
- Swift 6.x toolchain (developed against Swift 6.2 / Xcode 26). Swift 6 language mode.

## Build

```sh
cd macos-app
swift build            # debug
swift build -c release # release
```

The `Info.plist` (with `LSUIElement = true`) is embedded into the executable's
`__TEXT,__info_plist` section by a linker flag in `Package.swift`, so even the bare
binary runs as a Dock-less agent. The app additionally calls
`NSApp.setActivationPolicy(.accessory)` at launch.

## Run

```sh
# Run the bare executable (menu-bar item appears; no Dock icon):
.build/debug/RaincoatMenuBar

# Headless smoke test of the read-only tray pipeline (parse + liveness), no GUI:
.build/debug/RaincoatMenuBar --selftest

# Headless construction of the Preferences window (no event loop) — verifies the
# window builds and LoginItem / RaincoatLocator / KeyCombo resolve without throwing:
.build/debug/RaincoatMenuBar --selftest-prefs
```

`--selftest` reads the run directory and prints the live runs it would show — the same
code path the menu uses — then exits.

## Package into `Raincoat.app`

```sh
scripts/make-app-bundle.sh          # release (default)
scripts/make-app-bundle.sh debug
open Raincoat.app
```

The script wraps the built executable + `Info.plist` into
`Raincoat.app/Contents/{MacOS,Info.plist}` and applies an **ad-hoc** signature for local
use. The `Info.plist` sets `CFBundleIdentifier = dev.raincoat.menubar`, which
`SMAppService` requires for the login item.

## Preferences (`⌘,`)

Opened from the status menu. Since the app is `LSUIElement`/`.accessory`, it briefly flips
to `.regular` (so the window can take keyboard focus) while Preferences is open and reverts
to `.accessory` on close. A single shared window instance is reused.

- **Global hotkey** — a click-to-record control. Click it, press a combo; it captures on
  `keyDown` + `modifierFlags`, **live-rebinds** the Carbon hotkey (unregister old + register
  new via `HotKeyManager`), and persists the keycode/modifiers. A bare key with no
  `⌘`/`⌥`/`⌃` is rejected (inline hint); `Esc` cancels recording. If re-registration fails
  (e.g. the combo is already claimed), the previous binding is restored and a brief message
  is shown. "Use ⌥Space" resets to the default.
- **raincoat binary** — a path field + **Browse…**; empty means auto-discovery. A live
  `found ✓ <path>` / `not found ✗` indicator is computed via `RaincoatLocator`.
- **Default profile** — a path field + **Browse…**; when set, launches become
  `raincoat --profile <path> -- <target>`. Empty omits it.
- **Start at Login** — a checkbox backed by `SMAppService.mainApp`. On open it reflects
  `.status`; `.requiresApproval` shows a hint to enable it in **System Settings › General ›
  Login Items**. There is also a mirror **Launch at Login** checkbox in the status menu.

### Start-at-login: bundling requirement & degradation

`SMAppService.mainApp` resolves against the **main app bundle**, so it only works from a
real `Raincoat.app` — not `swift run` or a bare `.build/**` binary. Run un-bundled, the app
does **not** crash: `LoginItem.isBundled` is false, so the checkbox is disabled with an
"only available from the bundled app" hint (and `register()`/`unregister()` are never
called). Once bundled, register/unregister work; an **unsigned/ad-hoc** build typically
needs a **one-time approval** in System Settings › General › Login Items (and is happiest
when the app lives in `/Applications`). A Developer ID-signed build enables it cleanly.

### Signing: unsigned dev vs signed distribution

- **Dev (this machine):** the ad-hoc signature (`codesign --sign -`) is enough to launch
  locally. Running fully unsigned also works, though the global hotkey and any future
  login-item can be flaky unsigned.
- **Distribution:** sign with a Developer ID and notarize, e.g.

  ```sh
  codesign --deep --force --options runtime \
    --sign "Developer ID Application: Your Name (TEAMID)" Raincoat.app
  xcrun notarytool submit Raincoat.app.zip --keychain-profile "AC" --wait
  xcrun stapler staple Raincoat.app
  ```

The global hotkey uses Carbon `RegisterEventHotKey`, which needs **no** Accessibility
permission (unlike an `NSEvent` global monitor).

## Configuration (UserDefaults, domain `dev.raincoat.menubar`)

| Key                       | Meaning                                     | Default            |
| ------------------------- | ------------------------------------------- | ------------------ |
| `hotkey.keyCode`          | Carbon virtual key code                     | `49` (Space)       |
| `hotkey.modifiers`        | Carbon modifier mask                        | `2048` (option)    |
| `raincoat.binaryPath`     | Explicit path to `raincoat` (fallback)      | unset              |
| `raincoat.defaultProfile` | Profile passed as `--profile <p>`           | unset              |
| `launcher.recents`        | Recent command lines (managed by the app)   | `[]`               |

All of these are editable in the Preferences window; the table documents the raw keys.

`raincoat` is resolved via `$PATH`, then `/usr/local/bin` and `/opt/homebrew/bin`, then
`raincoat.binaryPath`. Example override:

```sh
defaults write dev.raincoat.menubar raincoat.binaryPath /full/path/to/raincoat
```

## Honest OS caveats (surfaced, not hidden)

These are OS facts, not Raincoat bugs (see `docs/GUI-MACOS.md`):

- `open -a` re-parents to `launchd` → the launcher execs the bundle's real binary instead.
- Hardened-runtime apps ignore `DYLD_INSERT_LIBRARIES` → no identity faking for most
  commercial GUI apps; Seatbelt fs/net confinement still applies. The tray shows whatever
  the CLI reports (`identity: off` for such runs) — it never overclaims.
- Multi-process apps (browser helpers, launchd-spawned XPC) escape a per-process sandbox.
  Best for CLI tools and single-binary apps.

## Source layout

```
macos-app/
  Package.swift                    executable target + embedded Info.plist (linker flags)
  scripts/make-app-bundle.sh       wrap the binary into Raincoat.app
  Sources/RaincoatMenuBar/
    main.swift                     entry point (+ --selftest, --selftest-prefs)
    Info.plist                     LSUIElement agent plist (embedded, not compiled)
    App/         AppDelegate.swift, SelfTest.swift
    Model/       RunStatus.swift, Capabilities.swift       (Codable mirror of schema 1)
    Runtime/     RunPaths, Liveness, RunStore, DirectoryWatcher
    Tray/        TrayController.swift
    Launcher/    HotKeyManager, LauncherController, LauncherPanel, AppIndex,
                 FuzzyMatcher, Recents, RaincoatLocator, LaunchService, SearchItem
    Preferences/ PreferencesWindowController, HotKeyRecorderView, KeyCombo, LoginItem
    Support/     Defaults.swift, Log.swift
```
