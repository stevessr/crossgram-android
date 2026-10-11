package org.telegram.messenger.server_switch;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/** Deliberately accepts DNS names only, with an explicit path. */
public final class WssUrl {
    public final String host, authority, resource;
    public final int port;
    public final String value;
    public WssUrl(String value) {
        try {
            if (value == null || value.length() > 4096 || !value.startsWith("wss://")
                    || value.matches(".*[\\s\\\\\\p{Cntrl}].*")) throw new IllegalArgumentException();
            URI u = new URI(value);
            String h = u.getHost();
            if (h == null || h.length() > 253 || h.indexOf('.') < 0 || h.matches("[0-9.]+")
                    || u.getRawUserInfo() != null || u.getRawFragment() != null
                    || u.getRawPath() == null || !u.getRawPath().startsWith("/")
                    || u.getRawPath().isEmpty() || u.getPort() == 0 || u.getPort() > 65535
                    || u.getRawAuthority().endsWith(":")) throw new IllegalArgumentException();
            for (String label : h.split("\\.", -1)) {
                if (!label.matches("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"))
                    throw new IllegalArgumentException();
            }
            host = h.toLowerCase(Locale.ROOT);
            port = u.getPort() < 0 ? 443 : u.getPort();
            authority = host + (port == 443 ? "" : ":" + port);
            resource = u.getRawPath() + (u.getRawQuery() == null ? "" : "?" + u.getRawQuery());
            // HTTP request targets must be ASCII; percent-encode non-ASCII yourself.
            for (int i = 0; i < resource.length(); i++) if (resource.charAt(i) > 126) throw new IllegalArgumentException();
            this.value = "wss://" + authority + resource;
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid WSS URL (DNS name, explicit path, no credentials/fragment required)");
        }
    }
}
