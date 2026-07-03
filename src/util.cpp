// Raincoat — util: leaf helpers with no raincoat-specific types.
#include "util.hpp"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include <sys/stat.h>
#include <sys/types.h>

namespace raincoat {

std::optional<std::string> canonicalize(const std::string& path) {
    if (path.empty()) return std::nullopt;
    char buf[PATH_MAX];
    if (::realpath(path.c_str(), buf) == nullptr) {
        return std::nullopt;
    }
    return std::string(buf);
}

std::string absolutize(const std::string& path, const std::string& base_cwd) {
    // Purely lexical: make absolute against base, then normalize . and .. and
    // collapse duplicate/trailing slashes. No filesystem access.
    std::string combined;
    if (!path.empty() && path.front() == '/') {
        combined = path;
    } else {
        combined = base_cwd;
        combined.push_back('/');
        combined += path;
    }

    std::vector<std::string> stack;
    std::string comp;
    std::istringstream iss(combined);
    while (std::getline(iss, comp, '/')) {
        if (comp.empty() || comp == ".") continue;
        if (comp == "..") {
            if (!stack.empty()) stack.pop_back();
            continue;
        }
        stack.push_back(comp);
    }

    std::string out;
    for (const auto& c : stack) {
        out.push_back('/');
        out += c;
    }
    if (out.empty()) out = "/";
    return out;
}

bool path_exists(const std::string& path) {
    if (path.empty()) return false;
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

bool is_dir(const std::string& path) {
    if (path.empty()) return false;
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

bool make_dirs(const std::string& path, std::string& err) {
    if (path.empty()) {
        err = "make_dirs: empty path";
        return false;
    }

    // Build up the path component by component (mkdir -p).
    std::string comp;
    std::istringstream iss(path);
    std::vector<std::string> comps;
    while (std::getline(iss, comp, '/')) {
        if (comp.empty()) continue;
        comps.push_back(comp);
    }

    std::string acc = (path.front() == '/') ? "/" : "";

    for (const auto& c : comps) {
        if (acc.empty()) {
            acc = c;
        } else if (acc == "/") {
            acc += c;
        } else {
            acc += "/";
            acc += c;
        }
        if (::mkdir(acc.c_str(), 0777) != 0) {
            if (errno == EEXIST) {
                struct stat st;
                if (::stat(acc.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    continue;  // already a directory: fine
                }
                err = "make_dirs: not a directory: " + acc;
                return false;
            }
            err = "make_dirs: failed to create " + acc + ": " +
                  std::string(std::strerror(errno));
            return false;
        }
    }

    err.clear();
    return true;
}

std::map<std::string, std::string> environ_to_map(char** envp) {
    std::map<std::string, std::string> m;
    if (envp == nullptr) return m;
    for (char** e = envp; *e != nullptr; ++e) {
        std::string entry(*e);
        auto pos = entry.find('=');
        if (pos == std::string::npos) continue;  // ignore malformed entries
        m[entry.substr(0, pos)] = entry.substr(pos + 1);
    }
    return m;
}

std::string to_upper(std::string s) {
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    if (prefix.size() > s.size()) return false;
    return s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

std::string trim(const std::string& s) {
    auto is_ws = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
               c == '\v';
    };
    size_t b = 0;
    size_t e = s.size();
    while (b < e && is_ws(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && is_ws(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

}  // namespace raincoat
