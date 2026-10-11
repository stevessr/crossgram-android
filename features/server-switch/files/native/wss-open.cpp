    // crossgram-wss-socketpair: no TCP listener, proxy, or fixed CDN IP.
    if (ConnectionsManager::getInstance(instanceNum).isWssServer()) {
        proxyAuthState = 0;
        currentSecret.clear(); currentSecretDomain.clear();
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
            closeSocket(1, -1); return;
        }
        socketFd = pair[0];
        int limit = 64 * 1024;
        setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &limit, sizeof(limit));
        setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &limit, sizeof(limit));
        extern bool crossgramOpenWss(int32_t, int32_t, int);
        int dc = 0;
        if (address.compare(0, 4, "wss:") == 0) dc = atoi(address.c_str() + 4);
        // The JNI bridge always takes ownership of pair[1], including failure.
        if (!crossgramOpenWss(instanceNum, dc, pair[1]) ||
                fcntl(socketFd, F_SETFL, O_NONBLOCK) == -1) {
            closeSocket(1, -1); return;
        }
        eventMask.events = EPOLLOUT | EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET;
        eventMask.data.ptr = eventObject;
        if (epoll_ctl(ConnectionsManager::getInstance(instanceNum).epolFd,
                      EPOLL_CTL_ADD, socketFd, &eventMask) != 0) closeSocket(1, -1);
        return;
    }
