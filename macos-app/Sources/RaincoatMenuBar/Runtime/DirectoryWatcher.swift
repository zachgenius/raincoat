import Darwin
import Foundation

// Watches the run directory for changes with a DispatchSource vnode event on the
// directory fd, and ALWAYS also runs a 1 s poll timer as a belt-and-suspenders
// fallback (the vnode source can miss events if the dir is recreated, or never
// attach if the dir does not exist yet). Pure reader — it opens the dir O_EVTONLY.
@MainActor
final class DirectoryWatcher {
    private let url: URL
    private let onChange: () -> Void

    private var source: DispatchSourceFileSystemObject?
    private var fileDescriptor: Int32 = -1
    private var timer: Timer?

    init(url: URL, onChange: @escaping () -> Void) {
        self.url = url
        self.onChange = onChange
    }

    func start() {
        attachVnodeSourceIfPossible()

        // Poll fallback. Fires on the main run loop, so hopping is trivial.
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                // Re-attach the vnode source if the directory only appeared after launch.
                if self.source == nil { self.attachVnodeSourceIfPossible() }
                self.onChange()
            }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        source?.cancel()   // cancel handler closes the fd
        source = nil
    }

    private func attachVnodeSourceIfPossible() {
        guard source == nil else { return }
        let fd = open(url.path, O_EVTONLY)
        guard fd >= 0 else { return }
        fileDescriptor = fd

        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .extend, .attrib, .link, .revoke],
            queue: .main
        )
        src.setEventHandler { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                // If the directory itself was replaced/removed, drop the source so the
                // poll timer can re-attach against the new inode.
                let flags = self.source?.data ?? []
                if flags.contains(.delete) || flags.contains(.revoke) || flags.contains(.rename) {
                    self.source?.cancel()
                    self.source = nil
                }
                self.onChange()
            }
        }
        src.setCancelHandler { [fd] in
            close(fd)
        }
        source = src
        src.resume()
    }
}
