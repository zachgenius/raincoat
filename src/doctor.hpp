// Raincoat — doctor: host capability checks. DoctorReport lives here.
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace raincoat {

struct DoctorReport {
    bool bwrap_found = false;
    std::string bwrap_path;
    std::string bwrap_version;
    bool userns_ok = false;
    bool smoke_ok = false;

    // Optional egress-network-jail helpers. Absence is NOT a failure; these
    // upgrade the egress bridge from shared-loopback to a dedicated netns.
    bool pasta_found = false;
    std::string pasta_path;
    std::string pasta_version;
    bool slirp4netns_found = false;
    std::string slirp4netns_path;
    std::string slirp4netns_version;

    std::vector<std::string> notes;
    bool usable() const { return bwrap_found && smoke_ok; }

    // True when some netns-based egress backend is available (pasta preferred).
    bool egress_jail_available() const { return pasta_found || slirp4netns_found; }
};

std::optional<std::string> find_bwrap();
std::optional<std::string> find_pasta();
std::optional<std::string> find_slirp4netns();
DoctorReport run_doctor();
std::string format_doctor(const DoctorReport& r);

}  // namespace raincoat
