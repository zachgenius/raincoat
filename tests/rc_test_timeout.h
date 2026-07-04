// Raincoat tests — portable wall-clock timeout prefix for a shell command string.
//
// The browser-shim tests wrap shim execution in a hard timeout so a regressed (infinitely
// self-exec'ing) shim can't hang the suite. GNU coreutils `timeout` provides that on Linux,
// but macOS ships no `timeout`. This header returns a drop-in prefix: real `timeout` on
// Linux, a perl fork+alarm equivalent on macOS (perl is always present). Like `timeout`,
// both run the command via execvp (no shell), SIGKILL the child on expiry, and otherwise
// propagate the child's exit status — so the exit-code checks in the recursion-guard tests
// behave identically on both platforms.
#pragma once

#include <string>

inline std::string rc_timeout(int secs, bool kill_sig = false) {
#ifdef __APPLE__
    (void)kill_sig;  // the perl equivalent always SIGKILLs on expiry
    return "perl -e 'my $s=shift;my $p=fork//exit(127);if($p==0){exec @ARGV;exit(127)}"
           "$SIG{ALRM}=sub{kill(9,$p);exit(124)};alarm $s;waitpid($p,0);"
           "exit($? & 127 ? 128+($? & 127) : $? >> 8)' " +
           std::to_string(secs) + " ";
#else
    return kill_sig ? ("timeout -s KILL " + std::to_string(secs) + " ")
                    : ("timeout " + std::to_string(secs) + " ");
#endif
}
