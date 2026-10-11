#include "wss-binding.h"
#include <cassert>
int main() {
    std::string saved;
    assert(!crossgramWssBindingBlocked("", saved, true, false)); // Legacy official unchanged.
    assert(!crossgramWssBindingBlocked("old-tcp-id", saved, true, false));
    assert(crossgramWssBindingBlocked("wss:a", saved, true, false)); // Never adopt old keys.
    assert(saved.empty());
    assert(!crossgramWssBindingBlocked("wss:a", saved, false, false));
    assert(saved == "wss:a");
    assert(!crossgramWssBindingBlocked("wss:a", saved, true, false));
    assert(crossgramWssBindingBlocked("wss:b", saved, true, false)); // URL/RSA/DC change.
    assert(crossgramWssBindingBlocked("", saved, true, false)); // No official fallback.
    assert(crossgramWssBindingBlocked("tcp", saved, true, false));
    assert(crossgramWssBindingBlocked("wss:a", saved, true, true));
    assert(crossgramWssBindingBlocked("wss:invalid", saved, false, false));
    saved.clear();
    assert(crossgramWssBindingBlocked("wss:a", saved, false, true));
    assert(saved.empty());
}
