import Foundation
import Security

// Detects whether an .app declares Apple's App Sandbox (`com.apple.security.app-sandbox`).
//
// Such apps (most Mac App Store apps — WeChat, etc.) CANNOT be launched under Raincoat's macOS
// backend: raincoat applies a Seatbelt profile via sandbox_init(), then the app's own libsecinit
// tries to install its container profile at launch (SET_USERLAND_PROFILE) — macOS refuses to
// sandbox an already-sandboxed process, so the app traps (SIGTRAP) in _libsecinit_appsandbox
// before it runs. We check up-front and refuse with a clear message rather than crash.
enum AppSandboxProbe {
    static func isSandboxed(_ appURL: URL) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(appURL as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }

        var infoCF: CFDictionary?
        // kSecCSRequirementInformation makes the entitlements dictionary available in the result.
        let flags = SecCSFlags(rawValue: kSecCSRequirementInformation)
        guard SecCodeCopySigningInformation(code, flags, &infoCF) == errSecSuccess,
              let info = infoCF as? [String: Any],
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        else { return false }

        return (entitlements["com.apple.security.app-sandbox"] as? Bool) == true
    }
}
