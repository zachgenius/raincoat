// Raincoat — net_guard: network mode flags.
//
// MVP implements only Full and Off. Allowlist and Ask are reserved enum values;
// conceptually they permit some/prompted network, so they must NEVER emit
// "--unshare-net" (that would silently turn an allow/ask request into a hard
// network-off, the opposite intent). For the MVP they behave like Full for flag
// emission (empty) and do not get a resolver view (binds_resolv_conf == false).
#include "net_guard.hpp"

namespace raincoat {

std::vector<std::string> net_flags(NetMode m) {
    switch (m) {
        case NetMode::Off:
            return {"--unshare-net"};
        case NetMode::Full:
        case NetMode::Allowlist:  // reserved: permits some network -> do not unshare
        case NetMode::Ask:        // reserved: prompts -> do not unshare
            return {};
    }
    return {};
}

bool binds_resolv_conf(NetMode m) {
    // resolv.conf is bound true ONLY for Full.
    return m == NetMode::Full;
}

}  // namespace raincoat
