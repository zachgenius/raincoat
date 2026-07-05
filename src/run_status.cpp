// Raincoat — run_status: see run_status.hpp.
#include "run_status.hpp"

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>

#include <unistd.h>

#include "util.hpp"  // make_dirs

namespace raincoat {

namespace {

// Minimal JSON string escaper (self-contained; audit.cpp's is file-local). Escapes the two
// mandatory bytes plus control chars as \uXXXX so the output is always valid JSON.
std::string esc(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o << buf;
                } else {
                    o << static_cast<char>(c);
                }
        }
    }
    return o.str();
}

}  // namespace

std::string run_status_dir() {
#ifdef __APPLE__
    const char* home = std::getenv("HOME");
    if (home == nullptr || *home == '\0') return std::string();
    return std::string(home) + "/Library/Application Support/Raincoat";
#else
    const char* xdg = std::getenv("XDG_RUNTIME_DIR");
    if (xdg != nullptr && *xdg != '\0') return std::string(xdg) + "/raincoat";
    const char* tmp = std::getenv("TMPDIR");
    std::string base = (tmp != nullptr && *tmp != '\0') ? std::string(tmp) : "/tmp";
    if (!base.empty() && base.back() == '/') base.pop_back();
    return base + "/raincoat-" + std::to_string(static_cast<long>(::getuid()));
#endif
}

std::string run_status_to_json(const RunStatus& s) {
    std::ostringstream o;
    o << "{";
    o << "\"schema\":1";
    o << ",\"supervisor_pid\":" << s.supervisor_pid;
    o << ",\"child_pid\":" << s.child_pid;
    o << ",\"command\":\"" << esc(s.command) << "\"";
    o << ",\"audit_log\":\"" << esc(s.audit_log) << "\"";
    o << ",\"backend\":\"" << esc(s.backend) << "\"";
    o << ",\"net_mode\":\"" << esc(s.net_mode) << "\"";
    o << ",\"started_at\":" << s.started_at;
    o << ",\"capabilities\":{";
    bool first = true;
    for (const auto& kv : s.capabilities) {
        if (!first) o << ",";
        first = false;
        o << "\"" << esc(kv.first) << "\":\"" << esc(kv.second) << "\"";
    }
    o << "}";
    o << ",\"notes\":[";
    for (std::size_t i = 0; i < s.notes.size(); ++i) {
        if (i) o << ",";
        o << "\"" << esc(s.notes[i]) << "\"";
    }
    o << "]";
    o << "}";
    return o.str();
}

bool run_status_write(const RunStatus& s) {
    std::string dir = run_status_dir();
    if (dir.empty()) return false;
    std::string run_dir = dir + "/run";
    std::string err;
    if (!make_dirs(run_dir, err)) return false;

    const std::string path = run_dir + "/" + std::to_string(s.supervisor_pid) + ".json";
    // Write to a temp file then rename, so a reader never sees a half-written file.
    const std::string tmp = path + ".tmp";
    std::FILE* f = std::fopen(tmp.c_str(), "w");
    if (f == nullptr) return false;
    const std::string json = run_status_to_json(s);
    bool ok = std::fwrite(json.data(), 1, json.size(), f) == json.size();
    if (std::fclose(f) != 0) ok = false;
    if (!ok) {
        std::remove(tmp.c_str());
        return false;
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

void run_status_remove(long supervisor_pid) {
    std::string dir = run_status_dir();
    if (dir.empty()) return;
    const std::string path = dir + "/run/" + std::to_string(supervisor_pid) + ".json";
    std::remove(path.c_str());
}

}  // namespace raincoat
