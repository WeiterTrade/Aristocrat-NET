package org.obhod.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import org.torproject.jni.TorService;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Системный VPN: весь трафик устройства → TUN → hev-socks5-tunnel → ядро «Обход» (SOCKS5 на 127.0.0.1:8881).
 * Ядро обходит DPI, а заблокированные по IP сайты отправляет в Tor (TorService, SOCKS 127.0.0.1:9077).
 * Сами ядро и Tor исключены из VPN (addDisallowedApplication), поэтому петли нет.
 */
public class ObhodVpnService extends VpnService {
    private static final String TAG = "Obhod";
    public static final String ACTION_START = "org.obhod.app.START";
    public static final String ACTION_STOP = "org.obhod.app.STOP";

    static final int CORE_PORT = 8881;
    static final String TOR_SOCKS = "127.0.0.1:9077";
    private static final String MAPDNS = "198.18.0.2";
    private static final String CHANNEL = "vpn";

    // Состояние для экрана (читается MainActivity раз в секунду).
    static volatile String state = "off"; // off | starting | on | error
    static volatile String error = "";
    static volatile String torState = "";
    private static final ArrayDeque<String> LOG = new ArrayDeque<>();

    private ParcelFileDescriptor tun;
    private Process core;
    private boolean torBound;
    private Thread worker;

    static void log(String line) {
        Log.i(TAG, line);
        synchronized (LOG) {
            LOG.addLast(line);
            while (LOG.size() > 200) LOG.removeFirst();
        }
    }

    static String logTail(int n) {
        synchronized (LOG) {
            List<String> all = new ArrayList<>(LOG);
            StringBuilder sb = new StringBuilder();
            for (int i = Math.max(0, all.size() - n); i < all.size(); i++) {
                sb.append(all.get(i)).append('\n');
            }
            return sb.toString();
        }
    }

    // ---- Tor ---------------------------------------------------------------

    private final ServiceConnection torConn = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder service) { log("TorService запущен"); }
        @Override public void onServiceDisconnected(ComponentName name) { torState = "Tor остановлен"; }
    };

    private final BroadcastReceiver torStatus = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String s = intent.getStringExtra(TorService.EXTRA_STATUS);
            if (TorService.STATUS_ON.equals(s)) {
                torState = "Tor подключён — запасной путь готов";
                log("Tor подключён");
            } else if (TorService.STATUS_STARTING.equals(s)) {
                torState = "Tor подключается… (через мосты это может занять до минуты)";
            } else if (TorService.STATUS_OFF.equals(s)) {
                torState = "Tor выключен";
            }
        }
    };

    // ---- Жизненный цикл -----------------------------------------------------

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : ACTION_START;
        if (ACTION_STOP.equals(action)) {
            stopAll();
            stopSelf();
            return START_NOT_STICKY;
        }
        startInForeground();
        if (worker == null || !worker.isAlive()) {
            worker = new Thread(this::startAll, "obhod-start");
            worker.start();
        }
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        log("VPN отключён системой");
        stopAll();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopAll();
        super.onDestroy();
    }

    private void startInForeground() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, getString(R.string.notif_channel),
                    NotificationManager.IMPORTANCE_LOW));
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
        }
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE);
        Notification n = b.setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.notif_text))
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentIntent(open)
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(1, n);
        }
    }

    private synchronized void startAll() {
        if ("on".equals(state)) return;
        state = "starting";
        error = "";
        torState = "";
        try {
            String libDir = getApplicationInfo().nativeLibraryDir;
            File coreBin = new File(libDir, "libobhod.so");
            File lyrebird = new File(libDir, "liblyrebird.so");
            File data = new File(getFilesDir(), "core");
            //noinspection ResultOfMethodCallIgnored
            data.mkdirs();
            killStaleCore(data);

            String route = Prefs.route(this);
            boolean useTor = !"dpi".equals(route);

            // 1. Tor: torrc собирает ядро (те же правила мостов, что и на ПК), запускает TorService.
            if (useTor) {
                try {
                    writeTorrc(coreBin, lyrebird, data);
                    LocalBroadcastManager.getInstance(this)
                            .registerReceiver(torStatus, new IntentFilter(TorService.ACTION_STATUS));
                    torBound = bindService(new Intent(this, TorService.class), torConn, BIND_AUTO_CREATE);
                    torState = "Tor подключается…";
                } catch (Exception e) {
                    torState = "Tor не запущен: " + e.getMessage();
                    log(torState);
                    useTor = false;
                }
            }

            // 2. Ядро.
            List<String> cmd = new ArrayList<>();
            cmd.add(coreBin.getAbsolutePath());
            cmd.add("-headless");
            cmd.add("-data");
            cmd.add(data.getAbsolutePath());
            cmd.add("-port");
            cmd.add(String.valueOf(CORE_PORT));
            cmd.add("-route");
            cmd.add(useTor ? route : "dpi");
            if (useTor) {
                cmd.add("-tor-socks");
                cmd.add(TOR_SOCKS);
            }
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true).directory(data);
            Map<String, String> env = pb.environment();
            env.put("SSL_CERT_DIR", "/system/etc/security/cacerts");
            env.put("HOME", data.getAbsolutePath());
            core = pb.start();
            pump(core.getInputStream());
            if (!waitPort(CORE_PORT, 8000)) {
                throw new IOException("ядро не запустилось — смотрите журнал");
            }

            // 3. VPN-интерфейс.
            Builder b = new Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(8500)
                    .addAddress("10.111.222.1", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(MAPDNS);
            try {
                b.addAddress("fd66:6f62:686f::1", 128).addRoute("::", 0);
            } catch (Exception e) {
                log("IPv6 недоступен: " + e.getMessage());
            }
            b.addDisallowedApplication(getPackageName()); // ядро и Tor идут мимо VPN
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                    PendingIntent.FLAG_IMMUTABLE));
            tun = b.establish();
            if (tun == null) throw new IOException("нет разрешения на VPN");

            // 4. tun2socks. DNS-запросы отвечает mapdns: домены приходят в ядро по имени.
            File conf = new File(getCacheDir(), "hev.yml");
            String yml = "tunnel:\n"
                    + "  mtu: 8500\n"
                    + "socks5:\n"
                    + "  port: " + CORE_PORT + "\n"
                    + "  address: 127.0.0.1\n"
                    + "  udp: 'udp'\n"
                    + "mapdns:\n"
                    + "  address: " + MAPDNS + "\n"
                    + "  port: 53\n"
                    + "  network: 100.64.0.0\n"
                    + "  netmask: 255.192.0.0\n"
                    + "  cache-size: 10000\n"
                    + "misc:\n"
                    + "  task-stack-size: 81920\n"
                    + "  log-level: warn\n";
            try (FileWriter w = new FileWriter(conf)) {
                w.write(yml);
            }
            TProxyService.TProxyStartService(conf.getAbsolutePath(), tun.getFd());

            state = "on";
            log("VPN включён");
        } catch (Exception e) {
            error = e.getMessage() == null ? e.toString() : e.getMessage();
            log("Ошибка: " + error);
            state = "error";
            cleanup();
        }
    }

    private void writeTorrc(File coreBin, File lyrebird, File data) throws Exception {
        File pt = new File(data, "pt_config.json");
        copyAsset("pt_config.json", pt);
        File custom = new File(data, "custom_bridges.txt");
        try (FileWriter w = new FileWriter(custom)) {
            w.write(Prefs.custom(this));
        }
        File torrc = TorService.getTorrc(this);
        //noinspection ResultOfMethodCallIgnored
        torrc.getParentFile().mkdirs();
        Process p = new ProcessBuilder(coreBin.getAbsolutePath(),
                "-write-torrc", torrc.getAbsolutePath(),
                "-data", data.getAbsolutePath(),
                "-bridges", Prefs.bridges(this),
                "-custom-bridges", custom.getAbsolutePath(),
                "-pt-config", pt.getAbsolutePath(),
                "-lyrebird", lyrebird.getAbsolutePath())
                .redirectErrorStream(true).start();
        String out = readAll(p.getInputStream());
        if (p.waitFor() != 0) {
            throw new IOException(out.trim());
        }
    }

    private void copyAsset(String name, File dst) throws IOException {
        try (InputStream in = getAssets().open(name); OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }

    /** Если приложение было убито, старое ядро могло остаться — завершаем его по pid. */
    private void killStaleCore(File data) {
        File pidFile = new File(data, "core.pid");
        try {
            String s = readAll(new java.io.FileInputStream(pidFile)).trim();
            if (!s.isEmpty()) android.os.Process.killProcess(Integer.parseInt(s));
        } catch (Exception ignored) {
        }
        //noinspection ResultOfMethodCallIgnored
        pidFile.delete();
    }

    private static String readAll(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null) sb.append(l).append('\n');
        }
        return sb.toString();
    }

    private static void pump(final InputStream in) {
        Thread t = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String l;
                while ((l = r.readLine()) != null) log(l);
            } catch (IOException ignored) {
            }
        }, "obhod-core-log");
        t.setDaemon(true);
        t.start();
    }

    private static boolean waitPort(int port, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", port), 200);
                return true;
            } catch (IOException e) {
                try {
                    Thread.sleep(150);
                } catch (InterruptedException ie) {
                    return false;
                }
            }
        }
        return false;
    }

    private synchronized void stopAll() {
        if ("off".equals(state)) return;
        cleanup();
        state = "off";
        torState = "";
        log("VPN выключен");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
    }

    private void cleanup() {
        try {
            TProxyService.TProxyStopService();
        } catch (Throwable ignored) {
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
            }
            tun = null;
        }
        if (core != null) {
            core.destroy();
            core = null;
        }
        if (torBound) {
            try {
                unbindService(torConn);
            } catch (Exception ignored) {
            }
            torBound = false;
            stopService(new Intent(this, TorService.class));
            try {
                LocalBroadcastManager.getInstance(this).unregisterReceiver(torStatus);
            } catch (Exception ignored) {
            }
        }
    }
}
