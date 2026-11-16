package org.obhod.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Передача своих мостов на соседнее устройство в той же сети Wi-Fi (например, на телевизор,
 * где нет Telegram). Пока на устройстве открыт любой экран Aristocrat NET, оно отвечает на
 * поиск и принимает мосты (с подтверждением). Отправитель ищет устройства широковещательным
 * UDP-запросом, затем отправляет мосты по TCP.
 *
 * Само приложение исключено из VPN, поэтому обмен идёт напрямую по локальной сети.
 */
final class BridgeShare {
    private static final int UDP_PORT = 47811;
    private static final int TCP_PORT = 47812;
    private static final String PROBE = "ARISTONET?1|";
    private static final String HERE = "ARISTONET!1|";
    private static final String HEADER = "ARISTONET-BRIDGES 1";
    private static final String NONCE = Long.toHexString(new Random().nextLong()); // чтобы не находить самого себя

    private static final Handler ui = new Handler(Looper.getMainLooper());
    private static WeakReference<Activity> current = new WeakReference<>(null);
    private static volatile boolean running;
    private static DatagramSocket udp;
    private static ServerSocket tcp;
    private static WifiManager.MulticastLock lock;
    private static final Runnable stopLater = BridgeShare::stopReceiver;

    private BridgeShare() {
    }

    // ---- Приём ---------------------------------------------------------------

    static void resume(Activity a) {
        current = new WeakReference<>(a);
        ui.removeCallbacks(stopLater);
        if (!running) startReceiver(a.getApplicationContext());
    }

    static void pause(Activity a) {
        if (current.get() == a) current = new WeakReference<>(null);
        // Переход между экранами: сначала pause старого, потом resume нового — не останавливаемся сразу.
        ui.removeCallbacks(stopLater);
        ui.postDelayed(stopLater, 2000);
    }

    private static synchronized void startReceiver(Context ctx) {
        if (running) return;
        running = true;
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                lock = wm.createMulticastLock("aristonet-share");
                lock.setReferenceCounted(false);
                lock.acquire();
            }
        } catch (Exception ignored) {
        }
        final String name = deviceName(ctx);
        new Thread(() -> {
            try {
                DatagramSocket s = new DatagramSocket(null);
                s.setReuseAddress(true);
                s.setBroadcast(true);
                s.bind(new InetSocketAddress(UDP_PORT));
                udp = s;
                byte[] buf = new byte[512];
                while (running) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    s.receive(p);
                    String m = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8);
                    if (!m.startsWith(PROBE) || m.substring(PROBE.length()).equals(NONCE)) continue;
                    byte[] r = (HERE + name).getBytes(StandardCharsets.UTF_8);
                    s.send(new DatagramPacket(r, r.length, p.getAddress(), p.getPort()));
                }
            } catch (Exception ignored) {
            }
        }, "aristonet-share-udp").start();
        new Thread(() -> {
            try {
                ServerSocket ss = new ServerSocket();
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress(TCP_PORT));
                tcp = ss;
                while (running) {
                    try (Socket c = ss.accept()) {
                        c.setSoTimeout(5000);
                        String msg = readAll(c.getInputStream(), 64 * 1024);
                        int nl = msg.indexOf('\n');
                        if (nl < 0 || !msg.substring(0, nl).trim().equals(HEADER)) continue;
                        String rest = msg.substring(nl + 1);
                        int nl2 = rest.indexOf('\n');
                        String from = nl2 < 0 ? "?" : rest.substring(0, nl2).trim();
                        String text = nl2 < 0 ? "" : rest.substring(nl2 + 1).trim();
                        if (BridgesActivity.count(text) == 0) continue;
                        OutputStream o = c.getOutputStream();
                        o.write("OK\n".getBytes(StandardCharsets.UTF_8));
                        o.flush();
                        ui.post(() -> offer(from, text));
                    } catch (Exception ignored) {
                        if (!running) break;
                    }
                }
            } catch (Exception ignored) {
            }
        }, "aristonet-share-tcp").start();
    }

    private static synchronized void stopReceiver() {
        running = false;
        if (udp != null) {
            udp.close();
            udp = null;
        }
        if (tcp != null) {
            try {
                tcp.close();
            } catch (Exception ignored) {
            }
            tcp = null;
        }
        if (lock != null) {
            try {
                lock.release();
            } catch (Exception ignored) {
            }
            lock = null;
        }
    }

    /** Пришли мосты: спрашиваем, принять ли их (чтобы никто в сети не подменил мосты незаметно). */
    private static void offer(String from, String text) {
        final Activity a = current.get();
        if (a == null || a.isFinishing()) return;
        int n = BridgesActivity.count(text);
        new AlertDialog.Builder(a)
                .setTitle(R.string.recv_title)
                .setMessage("Устройство «" + from + "» прислало мостов: " + n
                        + ".\nПринять? Ваши свои мосты будут заменены.")
                .setPositiveButton(R.string.recv_accept, (d, w) -> {
                    android.content.SharedPreferences.Editor e = Prefs.get(a).edit().putString("custom", text);
                    String br = Prefs.bridges(a);
                    if (!"auto".equals(br) && !"custom".equals(br)) e.putString("bridges", "custom");
                    e.apply();
                    ObhodVpnService.restartIfRunning(a);
                    Toast.makeText(a, R.string.bridges_saved, Toast.LENGTH_SHORT).show();
                    if (a instanceof SettingsActivity || a instanceof BridgesActivity) a.recreate();
                })
                .setNegativeButton(R.string.recv_cancel, null)
                .show();
    }

    // ---- Отправка ------------------------------------------------------------

    static void send(final Activity a) {
        final String text = Prefs.custom(a).trim();
        if (BridgesActivity.count(text) == 0) {
            Toast.makeText(a, R.string.send_no_bridges, Toast.LENGTH_SHORT).show();
            return;
        }
        final AlertDialog wait = new AlertDialog.Builder(a).setMessage(R.string.send_searching).setCancelable(true).show();
        final String me = deviceName(a);
        new Thread(() -> {
            final Map<String, String> found = discover(); // адрес → имя
            ui.post(() -> {
                if (wait.isShowing()) wait.dismiss();
                if (a.isFinishing()) return;
                if (found.isEmpty()) {
                    new AlertDialog.Builder(a).setMessage(R.string.send_none).setPositiveButton(android.R.string.ok, null).show();
                    return;
                }
                final List<String> ips = new ArrayList<>(found.keySet());
                String[] names = new String[ips.size()];
                for (int i = 0; i < ips.size(); i++) names[i] = found.get(ips.get(i)) + "  (" + ips.get(i) + ")";
                new AlertDialog.Builder(a)
                        .setTitle(R.string.send_pick)
                        .setItems(names, (d, which) -> new Thread(() -> {
                            final boolean ok = push(ips.get(which), me, text);
                            ui.post(() -> Toast.makeText(a, ok ? R.string.send_ok : R.string.send_fail, Toast.LENGTH_LONG).show());
                        }, "aristonet-share-send").start())
                        .setNegativeButton(R.string.recv_cancel, null)
                        .show();
            });
        }, "aristonet-share-find").start();
    }

    private static Map<String, String> discover() {
        Map<String, String> found = new LinkedHashMap<>();
        List<String> mine = new ArrayList<>();
        List<InetAddress> targets = new ArrayList<>();
        try {
            targets.add(InetAddress.getByName("255.255.255.255"));
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    if (ia.getAddress() != null) mine.add(ia.getAddress().getHostAddress());
                    if (ia.getBroadcast() != null && !targets.contains(ia.getBroadcast())) targets.add(ia.getBroadcast());
                }
            }
        } catch (Exception ignored) {
        }
        try (DatagramSocket s = new DatagramSocket()) {
            s.setBroadcast(true);
            s.setSoTimeout(300);
            byte[] probe = (PROBE + NONCE).getBytes(StandardCharsets.UTF_8);
            byte[] buf = new byte[512];
            long end = System.currentTimeMillis() + 2500;
            long nextProbe = 0;
            while (System.currentTimeMillis() < end) {
                if (System.currentTimeMillis() >= nextProbe) {
                    for (InetAddress t : targets) {
                        try {
                            s.send(new DatagramPacket(probe, probe.length, t, UDP_PORT));
                        } catch (Exception ignored) {
                        }
                    }
                    nextProbe = System.currentTimeMillis() + 800;
                }
                try {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    s.receive(p);
                    String m = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8);
                    String ip = p.getAddress().getHostAddress();
                    if (m.startsWith(HERE) && !mine.contains(ip)) found.put(ip, m.substring(HERE.length()));
                } catch (SocketTimeoutException ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return found;
    }

    private static boolean push(String ip, String me, String text) {
        try (Socket c = new Socket()) {
            c.connect(new InetSocketAddress(ip, TCP_PORT), 4000);
            c.setSoTimeout(5000);
            OutputStream o = c.getOutputStream();
            o.write((HEADER + "\n" + me + "\n" + text + "\n").getBytes(StandardCharsets.UTF_8));
            o.flush();
            c.shutdownOutput();
            return readAll(c.getInputStream(), 64).startsWith("OK");
        } catch (Exception e) {
            return false;
        }
    }

    // ---- Вспомогательное -----------------------------------------------------

    private static String readAll(InputStream in, int max) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while (b.size() < max && (n = in.read(buf)) > 0) b.write(buf, 0, n);
        return new String(b.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String deviceName(Context c) {
        try {
            String n = Settings.Global.getString(c.getContentResolver(), "device_name");
            if (n != null && !n.trim().isEmpty()) return n.trim();
        } catch (Exception ignored) {
        }
        String m = Build.MODEL == null ? "Android" : Build.MODEL;
        String v = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER;
        return m.toLowerCase().startsWith(v.toLowerCase()) ? m : (v + " " + m).trim();
    }
}
