package org.obhod.app;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pGroup;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;

/**
 * Раздача по Wi-Fi без «раздачи» оператора: телефон создаёт свою сеть Wi-Fi (Wi-Fi Direct),
 * устройства подключаются к ней и указывают прокси телефона. Все соединения в интернет
 * открывает сам телефон — для оператора это обычный трафик телефона, а не точка доступа.
 * Мобильный интернет при этом не отключается; к другой сети Wi-Fi телефон подключаться не обязан.
 */
final class WifiShare {
    /** Имя сети: Wi-Fi Direct требует начало «DIRECT-xy-». */
    static final String SSID = "DIRECT-AN-AristocratNET";
    static final String HOST_FALLBACK = "192.168.49.1"; // адрес телефона в сети Wi-Fi Direct

    interface Callback {
        void ready(String ssid, String pass, String host);

        void failed(String why);
    }

    private final Context ctx;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private WifiP2pManager mgr;
    private WifiP2pManager.Channel ch;
    private volatile boolean stopped;

    WifiShare(Context c) {
        ctx = c.getApplicationContext();
    }

    /** Какого разрешения не хватает для Wi-Fi Direct (null — всё есть). */
    static String missingPermission(Context c) {
        String p = Build.VERSION.SDK_INT >= 33 ? Manifest.permission.NEARBY_WIFI_DEVICES
                : Manifest.permission.ACCESS_FINE_LOCATION;
        return c.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED ? null : p;
    }

    static boolean wifiOn(Context c) {
        WifiManager wm = (WifiManager) c.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        return wm != null && wm.isWifiEnabled();
    }

    static boolean supported(Context c) {
        return c.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WIFI_DIRECT);
    }

    void start(final Callback cb) {
        stopped = false;
        ui.post(() -> {
            if (!supported(ctx)) {
                cb.failed("устройство не поддерживает Wi-Fi Direct");
                return;
            }
            mgr = (WifiP2pManager) ctx.getSystemService(Context.WIFI_P2P_SERVICE);
            if (mgr == null) {
                cb.failed("Wi-Fi Direct недоступен");
                return;
            }
            ch = mgr.initialize(ctx, Looper.getMainLooper(), () -> {
                if (!stopped) cb.failed("система отключила Wi-Fi Direct");
            });
            // Старая сеть (после сбоя или от другого приложения) мешает создать новую.
            mgr.removeGroup(ch, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() { ui.postDelayed(() -> create(cb, 0), 600); }
                @Override public void onFailure(int reason) { create(cb, 0); }
            });
        });
    }

    @SuppressLint("MissingPermission")
    private void create(final Callback cb, final int attempt) {
        if (stopped) return;
        WifiP2pManager.ActionListener l = new WifiP2pManager.ActionListener() {
            @Override public void onSuccess() { poll(cb, 0); }

            @Override public void onFailure(int reason) {
                if (stopped) return;
                if (attempt < 2) { // часто «занято» сразу после включения Wi-Fi — пробуем ещё раз
                    ui.postDelayed(() -> create(cb, attempt + 1), 1500);
                    return;
                }
                cb.failed(reasonText(reason));
            }
        };
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                WifiP2pConfig cfg = new WifiP2pConfig.Builder()
                        .setNetworkName(SSID)
                        .setPassphrase(Prefs.sharePass(ctx))
                        .enablePersistentMode(false)
                        .setGroupOperatingBand(WifiP2pConfig.GROUP_OWNER_BAND_AUTO)
                        .build();
                mgr.createGroup(ch, cfg, l);
            } else {
                mgr.createGroup(ch, l);
            }
        } catch (SecurityException e) {
            cb.failed("нет разрешения на Wi-Fi Direct");
        } catch (Exception e) {
            cb.failed(String.valueOf(e.getMessage()));
        }
    }

    /** Сеть создаётся не сразу — ждём, пока система сообщит её имя и пароль. */
    @SuppressLint("MissingPermission")
    private void poll(final Callback cb, final int n) {
        if (stopped) return;
        try {
            mgr.requestGroupInfo(ch, (WifiP2pGroup g) -> {
                if (stopped) return;
                if (g != null && g.isGroupOwner() && g.getNetworkName() != null) {
                    cb.ready(g.getNetworkName(), g.getPassphrase(), address(g.getInterface()));
                } else if (n < 20) {
                    ui.postDelayed(() -> poll(cb, n + 1), 700);
                } else {
                    cb.failed("сеть Wi-Fi не создалась");
                }
            });
        } catch (SecurityException e) {
            cb.failed("нет разрешения на Wi-Fi Direct");
        }
    }

    void stop() {
        stopped = true;
        ui.post(() -> {
            if (mgr == null || ch == null) return;
            try {
                mgr.removeGroup(ch, null);
            } catch (Exception ignored) {
            }
            if (Build.VERSION.SDK_INT >= 27) {
                try {
                    ch.close();
                } catch (Exception ignored) {
                }
            }
            ch = null;
        });
    }

    private static String reasonText(int reason) {
        switch (reason) {
            case WifiP2pManager.P2P_UNSUPPORTED:
                return "устройство не поддерживает Wi-Fi Direct";
            case WifiP2pManager.BUSY:
                return "Wi-Fi занят: включите Wi-Fi (подключаться к сети не нужно) и выключите точку доступа";
            default:
                return "не удалось создать сеть Wi-Fi: проверьте, что Wi-Fi включён"
                        + (Build.VERSION.SDK_INT < 33 ? ", а на Android 8–12 — и геолокация" : "");
        }
    }

    /** IPv4-адрес телефона в сети Wi-Fi Direct (обычно 192.168.49.1). */
    static String address(String iface) {
        try {
            if (iface != null) {
                NetworkInterface ni = NetworkInterface.getByName(iface);
                if (ni != null) {
                    Enumeration<InetAddress> it = ni.getInetAddresses();
                    while (it.hasMoreElements()) {
                        InetAddress a = it.nextElement();
                        if (a instanceof Inet4Address) return a.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return HOST_FALLBACK;
    }
}
