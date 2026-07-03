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
    std::vector<std::string> notes;
    bool usable() const { return bwrap_found && smoke_ok; }
};

std::optional<std::string> find_bwrap();
DoctorReport run_doctor();
std::string format_doctor(const DoctorReport& r);

}  // namespace raincoat
