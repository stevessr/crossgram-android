package org.telegram.messenger.server_switch;

import java.io.IOException;
import java.net.Socket;
import java.util.*;
import javax.net.ssl.*;

/** Uses the platform trust store; no permissive trust manager or verifier. */
public final class WssTls {
    public static SSLSocket create(Socket tcp, WssUrl url) throws IOException {
        SSLSocket tls = (SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(tcp, url.host, url.port, true);
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(Collections.singletonList(new SNIHostName(url.host)));
        tls.setSSLParameters(parameters);
        ArrayList<String> protocols = new ArrayList<>();
        for (String p : tls.getSupportedProtocols()) if (p.equals("TLSv1.2") || p.equals("TLSv1.3")) protocols.add(p);
        tls.setEnabledProtocols(protocols.toArray(new String[0]));
        return tls;
    }
}
