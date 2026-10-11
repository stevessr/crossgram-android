#pragma once
#include <string>

// Shared with host tests; caller blocks all sockets and preserves the key file.
inline bool crossgramWssBindingBlocked(const std::string &selected, std::string &saved,
                                      bool hasKeys, bool corrupt) {
    if (selected == "wss:invalid") return true;
    bool wss = selected.compare(0, 4, "wss:") == 0;
    bool wasWss = saved.compare(0, 4, "wss:") == 0;
    if (wss || wasWss) {
        if (saved.empty() && !hasKeys && !corrupt) saved = selected;
        if (saved != selected) return true;
    }
    return corrupt;
}
