package org.telegram.messenger.server_switch;

import android.os.ParcelFileDescriptor;
import org.telegram.messenger.FileLog;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.*;

/** Owns one end of a private AF_UNIX socketpair, never a listening TCP proxy. */
public final class WssBridge {
    private static final Semaphore SLOTS = new Semaphore(32);
    private static final ScheduledExecutorService WATCH = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "crossgram-wss-watch"); t.setDaemon(true); return t;
    });
    public static boolean open(int account, int dc, int fd) {
        ParcelFileDescriptor local = ParcelFileDescriptor.adoptFd(fd);
        boolean acquired = false;
        try {
            if (android.os.Build.VERSION.SDK_INT < 24) throw new IOException("wss_requires_android_7");
            WssUrl url = ServerSwitchConfig.wssUrl(account, dc);
            if (!SLOTS.tryAcquire()) throw new IOException("wss_connection_limit");
            acquired = true;
            Tunnel tunnel = new Tunnel(local, url);
            new Thread(tunnel::run, "crossgram-wss-open").start();
            return true;
        } catch (Exception e) {
            if (acquired) SLOTS.release();
            try { local.close(); } catch (IOException ignored) { }
            FileLog.e("crossgram_wss=config_or_capacity");
            return false;
        }
    }
    private static final class Tunnel {
        final ParcelFileDescriptor local;
        final WssUrl url;
        final AtomicBoolean closed = new AtomicBoolean();
        volatile Socket tcp;
        volatile SSLSocket tls;
        volatile long opening = System.nanoTime(), writing, delivering;
        Tunnel(ParcelFileDescriptor local, WssUrl url) { this.local = local; this.url = url; }
        void close(String reason) {
            if (!closed.compareAndSet(false, true)) return;
            FileLog.e("crossgram_wss=" + reason); // Never log URL/query, key, or payload.
            try { if (tcp != null) tcp.close(); } catch (IOException ignored) { }
            try { local.close(); } catch (IOException ignored) { }
            try { if (tls != null) tls.close(); } catch (IOException ignored) { }
        }
        void run() {
            ScheduledFuture<?> timer = WATCH.scheduleAtFixedRate(() -> {
                long now = System.nanoTime();
                if (opening != 0 && now-opening > TimeUnit.SECONDS.toNanos(15)) close("open_timeout");
                if (writing != 0 && now-writing > TimeUnit.SECONDS.toNanos(30)) close("write_timeout");
                if (delivering != 0 && now-delivering > TimeUnit.SECONDS.toNanos(30)) close("backpressure_timeout");
            }, 1, 1, TimeUnit.SECONDS);
            Thread writer = null;
            String stage = "dns_or_connect";
            try {
                tcp = new Socket(Proxy.NO_PROXY);
                tcp.connect(new InetSocketAddress(url.host, url.port), 15000);
                if (closed.get()) return;
                stage = "tls_validation";
                tls = WssTls.create(tcp, url);
                tls.setSoTimeout(15000);
                tls.startHandshake();
                stage = "upgrade";
                final OutputStream network = tls.getOutputStream();
                WssWire wire = new WssWire(tls.getInputStream(), new OutputStream() {
                    @Override public void write(int b) throws IOException { write(new byte[]{(byte)b}, 0, 1); }
                    @Override public void write(byte[] b, int off, int len) throws IOException {
                        writing = System.nanoTime(); network.write(b, off, len); writing = 0;
                    }
                    @Override public void flush() throws IOException {
                        writing = System.nanoTime(); network.flush(); writing = 0;
                    }
                });
                wire.handshake(url);
                if (closed.get()) return;
                opening = 0; tls.setSoTimeout(120000);
                final InputStream input = new FileInputStream(local.getFileDescriptor());
                final OutputStream output = new FileOutputStream(local.getFileDescriptor());
                writer = new Thread(() -> {
                    try {
                        byte[] bytes = new byte[16384]; int n;
                        while (!closed.get() && (n = input.read(bytes)) >= 0) {
                            wire.send(2, bytes, n);
                        }
                        close("native_close");
                    } catch (IOException e) { close("write_or_native_close"); }
                }, "crossgram-wss-send");
                writer.start();
                stage = "receive_or_protocol";
                wire.receive(new OutputStream() {
                    @Override public void write(int b) throws IOException { write(new byte[]{(byte)b}, 0, 1); }
                    @Override public void write(byte[] b, int off, int len) throws IOException {
                        delivering = System.nanoTime(); output.write(b, off, len); delivering = 0;
                    }
                });
            } catch (Exception e) {
                String detail = e.getMessage();
                close(detail != null && detail.matches("wss_[a-z_]+") ? detail : stage);
            }
            finally {
                close("closed"); timer.cancel(false);
                // Slot stays occupied until the writer really exits: no unbounded zombie workers.
                if (writer != null) {
                    boolean interrupted = false;
                    for (;;) { try { writer.join(); break; } catch (InterruptedException e) { interrupted = true; } }
                    if (interrupted) Thread.currentThread().interrupt();
                }
                SLOTS.release();
            }
        }
    }
}
