import Foundation
import ServiceManagement

// Thin wrapper over SMAppService.mainApp (macOS 13+) for start-at-login.
//
// Degradation when run UN-bundled (e.g. `.build/debug/RaincoatMenuBar` or `swift run`):
// SMAppService.mainApp resolves against the main bundle, which for a bare executable is
// not a real `.app`. `register()` then throws (rather than crashing) and `status` reports
// `.notFound`. Callers check `isBundled` first and disable the control with a hint, so the
// feature simply reads "unavailable" instead of failing. It works once packaged into
// Raincoat.app (see scripts/make-app-bundle.sh).
@MainActor
enum LoginItem {
    static var service: SMAppService { .mainApp }

    static var status: SMAppService.Status { service.status }

    static var isEnabled: Bool { status == .enabled }

    /// True only when running from a real `.app` bundle, which SMAppService requires.
    static var isBundled: Bool { Bundle.main.bundleURL.pathExtension == "app" }

    /// Register or unregister the app as a login item. Throws on failure (e.g. un-bundled);
    /// returns the resulting status so callers can reflect `.requiresApproval` etc.
    @discardableResult
    static func setEnabled(_ enabled: Bool) throws -> SMAppService.Status {
        if enabled {
            try service.register()
        } else {
            try service.unregister()
        }
        return service.status
    }
}
