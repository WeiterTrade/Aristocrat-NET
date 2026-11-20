package org.obhod.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Адреса в домашней сети: телефон раздаёт (точка доступа), второе устройство принимает. */
final class LanInfo {
    private LanInfo() {
    }

    /** Адреса этого устройства в локальных сетях (точка доступа, Wi-Fi, USB) — по ним подключаются устройства. */
    static List<String> addresses() {
        List<String> out = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                String n = ni.getName().toLowerCase(Locale.ROOT);
                // мобильная сеть, VPN и служебные интерфейсы
                if (n.startsWith("rmnet") || n.startsWith("ccmni") || n.startsWith("tun") || n.startsWith("dummy")
                        || n.startsWith("v4-") || n.startsWith("clat") || n.startsWith("seth") || n.startsWith("pdp")) {
                    continue;
                }
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address && a.isSiteLocalAddress()) out.add(a.getHostAddress());
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    /** Сеть Wi-Fi, к которой подключено устройство (null — не подключено). */
    static Network wifiNetwork(Context c) {
        ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return null;
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(n);
            if (nc != null && (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))) {
                return n;
            }
        }
        return null;
    }

    /** Адрес роутера этой сети Wi-Fi — в точке доступа это и есть телефон. */
    static String gateway(Context c, Network n) {
        ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null || n == null) return null;
        LinkProperties lp = cm.getLinkProperties(n);
        if (lp == null) return null;
        for (RouteInfo r : lp.getRoutes()) {
            InetAddress g = r.getGateway();
            if (r.isDefaultRoute() && g instanceof Inet4Address && !g.isAnyLocalAddress()) return g.getHostAddress();
        }
        return null;
    }

    /**
     * Найти раздачу Aristocrat NET в сети Wi-Fi: сначала роутер (точка доступа телефона — это он сам),
     * потом все адреса сети (раздача с компьютера в домашней сети). null — не найдено.
     */
    static String find(Context c, Network n, int port) {
        String gw = gateway(c, n);
        if (gw != null && probe(n, gw, port, 2500)) return gw;
        ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
        LinkProperties lp = cm == null ? null : cm.getLinkProperties(n);
        if (lp == null) return null;
        List<String> cands = new ArrayList<>();
        for (android.net.LinkAddress la : lp.getLinkAddresses()) {
            InetAddress a = la.getAddress();
            if (!(a instanceof Inet4Address) || la.getPrefixLength() < 24) continue;
            byte[] b = a.getAddress();
            for (int i = 1; i < 255; i++) {
                if ((b[3] & 0xff) == i) continue;
                cands.add((b[0] & 0xff) + "." + (b[1] & 0xff) + "." + (b[2] & 0xff) + "." + i);
            }
        }
        if (cands.isEmpty()) return null;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(48);
        java.util.concurrent.ExecutorCompletionService<String> done = new java.util.concurrent.ExecutorCompletionService<>(pool);
        for (String h : cands) done.submit(() -> probe(n, h, port, 800) ? h : null);
        try {
            for (int i = 0; i < cands.size(); i++) {
                String h = done.take().get();
                if (h != null) return h;
            }
        } catch (Exception ignored) {
        } finally {
            pool.shutdownNow();
        }
        return null;
    }

    /** На этом адресе работает раздача Aristocrat NET? */
    static boolean probe(Network n, String host, int port) {
        return probe(n, host, port, 3000);
    }

    static boolean probe(Network n, String host, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            if (n != null) n.bindSocket(s);
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            OutputStream o = s.getOutputStream();
            o.write(("GET / HTTP/1.0\r\nHost: " + host + ":" + port + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            o.flush();
            InputStream in = s.getInputStream();
            byte[] buf = new byte[4096];
            StringBuilder sb = new StringBuilder();
            int k;
            while (sb.length() < 8192 && (k = in.read(buf)) > 0) sb.append(new String(buf, 0, k, StandardCharsets.UTF_8));
            return sb.indexOf("Aristocrat NET") >= 0;
        } catch (Exception e) {
            return false;
        }
    }
}
