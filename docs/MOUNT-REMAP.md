# Spec: Neutral working-directory mount (path de-identification)

**Status:** Phase 1 (cwd-only, opt-in `[filesystem].remap_cwd`) **implemented**. This doc is the
design record; the honest limitations below still hold (partial mountinfo fix; opt-in because it
breaks absolute-path argv).

## Problem

Raincoat mounts the working directory (and every `--allow-read`/`--allow-write` path) into the
sandbox at the **same absolute path** it has on the host (`fs_guard.cpp make_mount`:
`m.sandbox_path = m.host_path`; SPEC §Filesystem "mount … at the SAME absolute path"). So a
project at `/home/zach/Develop/Raincoat` is visible to the child at that exact path. The child
therefore learns the **host username and directory layout** through many everyday channels:

- `getcwd()` / `pwd` and `$PWD`
- `realpath()` on any project file (resolves inside the namespace to the host path)
- `/proc/self/cwd`, `/proc/self/exe` (if invoked by absolute path)
- compiler debug info / `__FILE__`, build-system absolute paths baked into artifacts
- error messages, logs, stack traces, core dumps that print absolute paths
- `/proc/self/mountinfo` (mount point **and** source columns)

The fake HOME (`/tmp/raincoat-XXXX/home/user`) does *not* leak the username, and env `USER`/
`HOME` are already genericized — but the **cwd path defeats all of that**: one `pwd` reveals
`zach`. This is the single most pervasive identity leak left.

## Goal

Optionally mount the working directory at a **neutral path** (default `/work`) and run the child
there, so the common exposure channels above show `/work` instead of the host path.

## What this does and does NOT fix (verified)

Mounting cwd at `/work` and `chdir`-ing there was tested against bwrap directly:

| Channel | After remap |
|---|---|
| `pwd`, `$PWD`, `getcwd()` | ✅ `/work` |
| `realpath .` / file realpaths | ✅ `/work/...` |
| `/proc/self/cwd` | ✅ `/work` |
| compiler `__FILE__`, logs, error paths (relative-based) | ✅ `/work/...` |
| `/proc/self/mountinfo` **mount point** (field 5) | ✅ `/work` |
| **`/proc/self/mountinfo` mount *source*** (field 4) | ❌ **still `/home/zach/Develop/Raincoat`** |

The last row is a hard limit: a bind mount **always records its source subtree** in mountinfo
field 4, e.g. `259:3 /home/zach/Develop/Raincoat /work rw …`. There is no bind-mount flag that
hides it, and `/proc/self/mountinfo` itself cannot be overlaid (per-reader `self` indirection —
see `FINGERPRINT-SYSCALLS.md`). Hiding the source too would need a different fs (overlayfs with a
neutral lowerdir, or copying into a tmpfs), which breaks the "same live rw project dir" contract.

**Honest framing:** this closes the *pervasive, practical* leaks (pwd/realpath/logs/compiler
paths) that actually deanonymize in normal use. It does **not** fully sanitize `mountinfo`; a
reader who parses field 4 still recovers the host path. `mountinfo` stays a documented hard gap.

## The core tradeoff: absolute-path command arguments break

With identity mapping, `raincoat -- mytool /home/zach/proj/x` works because `/home/zach/proj/x`
is the same path inside. With remapping, that path no longer exists in the child (it's now
`/work/x`), so the command fails with ENOENT. **Remapping breaks any command that references host
absolute paths in its arguments.**

Relative-path workflows are unaffected — `mytool ./x`, `make`, `cargo build`, `npm run`, and most
AI-agent/build activity operate relative to cwd, which is `chdir`-ed to `/work`. Those are the
overwhelming common case and the target of this feature.

Because it breaks absolute-path argv, remapping **must be opt-in**; the default stays identity
mapping (backward compatible, SPEC contract preserved).

## Config surface (value-driven, matching the fingerprint knobs)

```toml
[filesystem]
# Mount the working directory at this neutral path instead of its real host path, and chdir
# there (PWD=/work). UNSET (default) => identity mapping, i.e. the current same-path behavior.
# Presence is the switch; the value is the mountpoint.
remap_cwd = "/work"
```

Scope decision (recommended): **Phase 1 remaps only the cwd.** `--allow-read`/`--allow-write`
paths stay identity-mapped, because (a) they are frequently referenced by absolute path in the
command, and (b) the user named them explicitly. A later Phase 2 can add an explicit per-mount
remap for allow paths (e.g. a `[[filesystem.mount]]` table with `host`/`sandbox`/`mode`) for
users who want those de-identified too and are willing to rewrite their argv.

## Implementation plan (grounded in current code)

1. **Config** (`config.hpp`): add `std::optional<std::string> remap_cwd;` to the filesystem
   policy struct (alongside the existing `[filesystem]` fields). Parse in `profile.cpp`
   (`set_opt_str("filesystem.remap_cwd", …)`), and optionally a `--remap-cwd <path>` CLI flag.

2. **Mount planning** (`fs_guard.cpp`): in `plan_mounts`, when `remap_cwd` is set and the auto-cwd
   mount is being added, set that Mount's `sandbox_path = *remap_cwd` (instead of `host_path`).
   `make_mount` already keeps `host_path`/`sandbox_path` as independent fields — only the auto-cwd
   branch changes. Validate `remap_cwd` is absolute and not a path bwrap reserves (`/`, `/usr`,
   `/proc`, `/dev`, `/etc`, `/tmp`, the fake-home root).

3. **Workdir / chdir** (`runner.cpp` ~884–906): today `effective_workdir` is `workdir_canon` (a
   host path) when it's inside a mount. When cwd is remapped, translate: if the real workdir is
   within the cwd mount's `host_path`, `effective_workdir = remap_cwd + (workdir_canon −
   host_path)`. `cfg_copy.workdir` (→ bwrap `--chdir`) uses the translated path.

4. **PWD** (`runner.cpp` env): export `PWD = effective_workdir` so shells/tools that read `$PWD`
   instead of calling `getcwd()` also see `/work`. (Confirm we don't currently set PWD; add it.)

5. **Translate the host→sandbox path checks** that currently assume `host_path == sandbox_path`:
   - **Egress profile-leak guard** (`runner.cpp` ~1106–1174): it finds whether the `--profile`
     file is reachable inside a mount and masks it. Change the reachability test to compare the
     profile's host path against `m.host_path`, and push the **translated sandbox path**
     (`m.sandbox_path + tail`) into `mask_files` (the empty-file bind targets a sandbox path).
   - **Audit-log mask dir** (`runner.cpp` audit-mask): the child-side audit dir path must be the
     translated sandbox path when the audit log lives under the remapped cwd.
   - **`workdir_mounted` / `path_within(workdir_canon, m.sandbox_path)`**: compare against
     `m.host_path` for the "is it mounted" decision; use `m.sandbox_path` for the child-visible
     path.

6. **Audit record** (`runner.cpp`): `rec.workdir = effective_workdir` (already set) will now show
   `/work`; add an `active_policy_notes` entry disclosing the remap and its honest limit
   ("working directory presented at /work; the host path is still visible in
   /proc/self/mountinfo's mount-source field").

7. **Browser / tripwire / fake-home**: no change — those live under the temp root
   (`/tmp/raincoat-XXXX/...`), which contains no username.

## Edge cases

- **cwd is a subdir under a remapped root**: `--workdir sub` → child cwd `/work/sub`. Handled by
  the tail-translation in step 3.
- **Relative `--allow-read`/`--allow-write`**: absolutized against cwd today; unchanged (Phase 1
  leaves them identity-mapped).
- **cwd == HOME or ancestor of HOME**: already refused (`cwd_is_home`); remap doesn't relax that.
- **A tool that itself reads `/proc/self/mountinfo`** to find its cwd: sees `/work` as the mount
  point but the host path in field 4 — documented limit.
- **Symlinks inside the project pointing outside**: resolve to their real targets (unchanged);
  only the cwd subtree is remapped.
- **`remap_cwd` collides with a base mount** (`/usr`, `/proc`, …): reject at config-validation
  time with a clear error.

## Testing plan

- `fs_guard` unit: `plan_mounts` with `remap_cwd` set → the cwd Mount has `host_path` = real,
  `sandbox_path` = `/work`; allow paths unchanged; invalid `remap_cwd` rejected.
- `runner`/integration (bwrap-gated, GTEST_SKIP without bwrap): `pwd`, `realpath .`, and `$PWD`
  inside the sandbox all report `/work`; a relative-path command (`cat ./file`) still works; the
  audit shows `workdir=/work` and the disclosure note.
- Regression: with `remap_cwd` unset, argv and mounts are byte-identical to today (identity map).
- Honesty test: assert mountinfo still contains the host source path (documents the known limit,
  so a future "fix" that claims otherwise must update this test).

## Limitations / non-goals

- **Not a mountinfo cure.** Field 4 (mount source) still shows the host path; see above.
- **`uid=`, block device, and the `/tmp/raincoat-XXXX` temp paths** in mountinfo are unaffected by
  this change (they'd need uid-mapping via `--unshare-user` and a different temp-root strategy).
- **Absolute-path argv** referencing host paths is the user's responsibility to convert to
  `/work`-relative; that's why the feature is opt-in.

## Recommendation

Ship **Phase 1 (cwd-only, opt-in `[filesystem].remap_cwd`)**. It removes the single most common
username leak (`pwd`/`realpath`/logs/compiler paths) for the normal relative-path workflow, at
the cost of breaking absolute-host-path arguments — which is why it's opt-in and off by default.
Be explicit in the README and audit that it does **not** fully sanitize `/proc/self/mountinfo`.
Defer allow-path remapping (Phase 2) until there's demand, since it collides most with argv usage.
