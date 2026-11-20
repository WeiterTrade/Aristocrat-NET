package org.obhod.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

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
    static final int SHARE_PORT = 8282; // прокси для устройств в сети раздачи Wi-Fi
    static final String EXTRA_VPN = "vpn";
    static final String EXTRA_SHARE = "share";
    static final String EXTRA_RECV = "recv";
    static final String TOR_SOCKS = "127.0.0.1:9077";
    // DNS устройства: запросы уходят в туннель, ядро отвечает настоящими адресами (шифрованный DNS).
    private static final String VPN_DNS = "1.1.1.1";
    private static final String CHANNEL = "vpn";

    // Состояние для экрана (читается MainActivity раз в секунду).
    static volatile String state = "off"; // off | starting | on | error
    static volatile String error = "";
    static volatile String torState = "";
    static volatile String warpState = "";
    // Режим работы: обход блокировок (VPN) и/или раздача; или приём интернета с другого телефона.
    static volatile boolean runVpn = true, runShare = false, runRecv = false;
    static volatile String recvHost = ""; // приём: адрес телефона, который раздаёт
    private static final ArrayDeque<String> LOG = new ArrayDeque<>();

    private ParcelFileDescriptor tun;
    private Process core;
    private boolean torBound;
    private Thread worker;
    private static ObhodVpnService instance; // для перезапуска Tor из потока журнала
    private Process ptProc;                  // lyrebird (транспорты мостов), запущенный приложением
    private String ptSocks = "";            // его адреса: obfs4=127.0.0.1:port,…
    private int torCrashes = 0;              // сколько раз подряд упал процесс :tor
    private int torPhase = 0;                // этап автовыбора мостов: 0 — snowflake, 1 — obfs4/meek
    private File torCoreBin, torLyrebird, torData, torLogFile;

    static boolean active() {
        return "on".equals(state) || "starting".equals(state);
    }

    /** Обход включён (VPN), а не только раздача. */
    static boolean vpnActive() { return active() && runVpn; }

    static boolean shareActive() { return active() && runShare; }

    static boolean recvActive() { return active() && runRecv; }

    private static void startWith(Context c, boolean vpn, boolean share, boolean recv) {
        Intent i = new Intent(c, ObhodVpnService.class).setAction(ACTION_START)
                .putExtra(EXTRA_VPN, vpn).putExtra(EXTRA_SHARE, share).putExtra(EXTRA_RECV, recv);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            c.startForegroundService(i);
        } else {
            c.startService(i);
        }
    }

    static void run(Context c, boolean vpn, boolean share) {
        run(c, vpn, share, false);
    }

    /**
     * Включает нужный режим: обход блокировок (vpn), раздачу (share), оба — или приём интернета
     * с телефона, который раздаёт (recv). Всё false — выключить. Разрешение на VPN должно быть
     * уже получено (см. StartActivity).
     */
    static void run(Context c, boolean vpn, boolean share, boolean recv) {
        final Context app = c.getApplicationContext();
        if (recv) {
            vpn = false;
            share = false;
        }
        final boolean v = vpn, sh = share;
        Prefs.saveModes(app, v || (!sh && !recv), sh, recv);
        if (!v && !sh && !recv) {
            if (active()) app.startService(new Intent(app, ObhodVpnService.class).setAction(ACTION_STOP));
            return;
        }
        if (active()) {
            if (v == runVpn && sh == runShare && recv == runRecv) return;
            app.startService(new Intent(app, ObhodVpnService.class).setAction(ACTION_STOP));
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> startWith(app, v, sh, recv), 1000);
            return;
        }
        startWith(app, v, sh, recv);
    }

    /** Новые настройки применяются перезапуском службы (в том же режиме). */
    static void restartIfRunning(Context c) {
        if (!active()) return;
        final Context app = c.getApplicationContext();
        final boolean vpn = runVpn, share = runShare, recv = runRecv;
        app.startService(new Intent(app, ObhodVpnService.class).setAction(ACTION_STOP));
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> startWith(app, vpn, share, recv), 1000);
    }

    /** Обновить кнопки в шторке (открытые — сразу, остальные — при следующем открытии шторки). */
    static void updateTile(Context c) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return;
        BaseTile.refreshAll();
        for (Class<?> cl : new Class<?>[]{AristocratTile.class, ShareTile.class}) {
            try {
                android.service.quicksettings.TileService.requestListeningState(c, new ComponentName(c, cl));
            } catch (Exception ignored) {
            }
        }
    }

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
        @Override public void onServiceDisconnected(ComponentName name) {
            // Процесс :tor упал. Приложение, обход DPI и WARP продолжают работать.
            dumpTorCrash();
            torCrashes++;
            if ("on".equals(state) && torCrashes <= 3) {
                torState = "Tor перезапускается…";
                log("Процесс Tor завершился — перезапуск (" + torCrashes + " из 3)");
                final int phase = torPhase;
                new Thread(() -> {
                    try { Thread.sleep(2000); } catch (InterruptedException ignored) { }
                    restartTor(phase);
                }, "obhod-tor-revive").start();
            } else {
                torState = "Tor аварийно завершился — подробности в журнале (Настройки)";
                log(torState);
            }
        }
    };

    // ---- Жизненный цикл -----------------------------------------------------

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        instance = this;
        String action = intent != null ? intent.getAction() : ACTION_START;
        if (ACTION_STOP.equals(action)) {
            stopAll();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (!active()) {
            if (intent != null && intent.hasExtra(EXTRA_VPN)) {
                runVpn = intent.getBooleanExtra(EXTRA_VPN, true);
                runShare = intent.getBooleanExtra(EXTRA_SHARE, false);
                runRecv = intent.getBooleanExtra(EXTRA_RECV, false);
            } else if (intent != null && SERVICE_INTERFACE.equals(intent.getAction())) {
                runVpn = true; // «Постоянный VPN» включает система
                runShare = false;
                runRecv = false;
            } else { // служба перезапущена системой — прежний режим
                runVpn = Prefs.lastVpn(this);
                runShare = Prefs.lastShare(this);
                runRecv = Prefs.lastRecv(this);
            }
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
        // Кнопки «Открыть» и «Отключить» видны, когда уведомление развёрнуто (потянуть его вниз).
        PendingIntent stop = PendingIntent.getService(this, 1,
                new Intent(this, ObhodVpnService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
        Notification n = b.setContentTitle(getString(R.string.app_name))
                .setContentText(notifText())
                .setStyle(new Notification.BigTextStyle().bigText(notifText()))
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentIntent(open)
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(
                        android.graphics.drawable.Icon.createWithResource(this, android.R.drawable.ic_menu_view),
                        getString(R.string.notif_open), open).build())
                .addAction(new Notification.Action.Builder(
                        android.graphics.drawable.Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel),
                        getString(R.string.notif_stop), stop).build())
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(1, n);
        }
    }

    private String notifText() {
        if (runRecv) return "Интернет через телефон " + recvHost;
        String share = "Раздача: включите точку доступа; на втором устройстве — Aristocrat NET → «Интернет с телефона»";
        if (runVpn && runShare) return getString(R.string.notif_text) + "\n" + share + " (с обходом)";
        if (runShare) return share;
        return getString(R.string.notif_text);
    }

    private synchronized void startAll() {
        if ("on".equals(state)) return;
        state = "starting";
        recvHost = "";
        updateTile(this);
        if (runRecv) {
            startRecv();
            return;
        }
        final boolean vpn = runVpn, share = runShare;
        error = "";
        torState = "";
        warpState = "";
        torCrashes = 0;
        try {
            String libDir = getApplicationInfo().nativeLibraryDir;
            File coreBin = new File(libDir, "libobhod.so");
            File lyrebird = new File(libDir, "liblyrebird.so");
            File data = new File(getFilesDir(), "core");
            //noinspection ResultOfMethodCallIgnored
            data.mkdirs();
            killStaleCore(data);

            String route = vpn ? Prefs.route(this) : "dpi";
            boolean useTor = vpn && Prefs.needTor(this);
            File torLog = new File(data, "tor.log");

            File geo = prepareGeo(data);
            torCoreBin = coreBin;
            torLyrebird = lyrebird;
            torData = data;
            torLogFile = torLog;

            // 1. Tor: torrc собирает ядро (те же правила мостов, что и на ПК), запускает TorService.
            //    Журнал tor пишет в файл — ядро читает его (прогресс подключения и причины ошибок).
            if (useTor) {
                useTor = startTor();
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
            cmd.add("tor".equals(route) && !useTor ? "dpi" : route);
            cmd.add("-heavy");
            cmd.add(Prefs.heavy(this));
            // Адрес Tor передаём всегда: в России ядро попросит запустить Tor для Spotify.
            cmd.add("-tor-socks");
            cmd.add(TOR_SOCKS);
            cmd.add("-tor-log");
            cmd.add(torLog.getAbsolutePath());
            cmd.add("-geoip-dir");
            cmd.add(geo.getAbsolutePath());
            cmd.add("-device-name");
            cmd.add((Build.MANUFACTURER + " " + Build.MODEL).trim());
            cmd.add("-adblock");
            cmd.add(Prefs.adBlock(this) ? "on" : "off");
            cmd.add("-keep-local");
            cmd.add(Prefs.keepLocal(this) ? "on" : "off");
            cmd.add("-geo-tor");
            cmd.add(vpn && Prefs.geoTor(this) ? "on" : "off");
            if (!vpn) cmd.add("-plain"); // только раздача: без обхода блокировок
            if (share) {
                cmd.add("-share-listen");
                cmd.add("0.0.0.0:" + SHARE_PORT);
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

            if (!vpn) {
                state = "on";
                log("Раздача запущена (без обхода блокировок): прокси на порту " + SHARE_PORT);
                updateTile(this);
                return;
            }

            // 3. VPN-интерфейс.
            Builder b = new Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(8500)
                    .addAddress("10.111.222.1", 32)
                    .addDnsServer(VPN_DNS);
            // Весь интернет — через туннель, а домашняя сеть (Chromecast, телевизор, принтер, роутер),
            // точка доступа и широковещательные запросы поиска устройств — мимо него, как без VPN.
            for (String[] r : publicRoutes()) b.addRoute(r[0], Integer.parseInt(r[1]));
            try {
                b.addAddress("fd66:6f62:686f::1", 128).addRoute("2000::", 3); // только глобальные IPv6
            } catch (Exception e) {
                log("IPv6 недоступен: " + e.getMessage());
            }
            b.addDisallowedApplication(getPackageName()); // ядро, Tor и WARP идут мимо VPN
            // Приложения, выбранные пользователем (банки, сервисы с привязкой к стране), — мимо «Обхода».
            for (String pkg : Prefs.excluded(this)) {
                if (pkg.equals(getPackageName())) continue;
                try {
                    b.addDisallowedApplication(pkg);
                } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {
                    // не установлено
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                    PendingIntent.FLAG_IMMUTABLE));
            tun = b.establish();
            if (tun == null) throw new IOException("нет разрешения на VPN");

            // 4. tun2socks. DNS (порт 53) отвечает ядро — настоящими адресами, поэтому работает и раздача интернета.
            File conf = new File(getCacheDir(), "hev.yml");
            String yml = "tunnel:\n"
                    + "  mtu: 8500\n"
                    + "socks5:\n"
                    + "  port: " + CORE_PORT + "\n"
                    + "  address: 127.0.0.1\n"
                    + "  udp: 'udp'\n"
                    + "misc:\n"
                    + "  task-stack-size: 81920\n"
                    + "  log-level: warn\n";
            try (FileWriter w = new FileWriter(conf)) {
                w.write(yml);
            }
            TProxyService.TProxyStartService(conf.getAbsolutePath(), tun.getFd());

            state = "on";
            log("VPN включён");
            updateTile(this);
        } catch (Exception e) {
            error = e.getMessage() == null ? e.toString() : e.getMessage();
            log("Ошибка: " + error);
            state = "error";
            cleanup();
            updateTile(this);
        }
    }

    /**
     * Приём интернета с телефона, который раздаёт (точка доступа + «Раздача» в Aristocrat NET).
     * Весь трафик этого устройства уходит в прокси телефона, а в интернет его отправляет сам телефон —
     * для оператора это трафик телефона, а не раздача.
     */
    private void startRecv() {
        try {
            android.net.Network wifi = LanInfo.wifiNetwork(this);
            if (wifi == null) throw new IOException("подключитесь к точке доступа телефона по Wi-Fi");
            String gw = LanInfo.gateway(this, wifi);
            if (gw == null) throw new IOException("не удалось узнать адрес телефона в этой сети Wi-Fi");
            if (!LanInfo.probe(wifi, gw, SHARE_PORT)) {
                throw new IOException("на телефоне " + gw + " не включена раздача: включите на нём точку доступа и «Раздача» в Aristocrat NET");
            }
            recvHost = gw;
            Builder b = new Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(8500)
                    .addAddress("10.111.222.1", 32)
                    .addDnsServer(VPN_DNS);
            // Весь интернет — через телефон; домашняя сеть (сам телефон в том числе) — напрямую.
            for (String[] r : publicRoutes()) b.addRoute(r[0], Integer.parseInt(r[1]));
            try {
                b.addAddress("fd66:6f62:686f::1", 128).addRoute("2000::", 3);
            } catch (Exception e) {
                log("IPv6 недоступен: " + e.getMessage());
            }
            for (String pkg : Prefs.excluded(this)) {
                if (pkg.equals(getPackageName())) continue;
                try {
                    b.addDisallowedApplication(pkg);
                } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                    PendingIntent.FLAG_IMMUTABLE));
            tun = b.establish();
            if (tun == null) throw new IOException("нет разрешения на VPN");
            File conf = new File(getCacheDir(), "hev.yml");
            String yml = "tunnel:\n"
                    + "  mtu: 8500\n"
                    + "socks5:\n"
                    + "  port: " + SHARE_PORT + "\n"
                    + "  address: " + gw + "\n"
                    + "  udp: 'udp'\n"
                    + "misc:\n"
                    + "  task-stack-size: 81920\n"
                    + "  log-level: warn\n";
            try (FileWriter w = new FileWriter(conf)) {
                w.write(yml);
            }
            TProxyService.TProxyStartService(conf.getAbsolutePath(), tun.getFd());
            state = "on";
            log("Интернет через телефон " + gw);
            startInForeground();
            updateTile(this);
        } catch (Exception e) {
            error = e.getMessage() == null ? e.toString() : e.getMessage();
            log("Ошибка: " + error);
            state = "error";
            cleanup();
            updateTile(this);
        }
    }

    /** Файлы GeoIP: ядру — чтобы узнавать российские и казахстанские сайты, tor — для выбора страны. */
    private File prepareGeo(File data) {
        File geo = new File(data, "geoip-data");
        //noinspection ResultOfMethodCallIgnored
        geo.mkdirs();
        for (String g : new String[]{"geoip", "geoip6"}) {
            File f = new File(geo, g);
            if (f.length() > 0) continue; // уже скопирован
            try {
                copyAsset(g, f);
            } catch (IOException e) {
                log("Нет файла " + g + " — страны определяются только по домену");
            }
        }
        return geo;
    }

    /** Запускает TorService (tor) с torrc, собранным ядром. */
    private synchronized boolean startTor() {
        try {
            //noinspection ResultOfMethodCallIgnored
            torLogFile.delete();
            torPhase = 0;
            killTorProcess(); // tor нельзя дважды запустить в одном процессе — начинаем с чистого
            writeTorrc(torCoreBin, torLyrebird, torData, torLogFile);
            torBound = bindService(new Intent(this, TorService.class), torConn, BIND_AUTO_CREATE);
            torState = "Tor подключается…";
            return true;
        } catch (Exception e) {
            torState = "Tor не запущен: " + e.getMessage();
            log(torState);
            return false;
        }
    }

    private void writeTorrc(File coreBin, File lyrebird, File data, File torLog) throws Exception {
        File pt = new File(data, "pt_config.json");
        copyAsset("pt_config.json", pt);
        File geo = new File(data, "geoip-data");
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
                "-lyrebird", lyrebird.getAbsolutePath(),
                "-tor-log", torLog.getAbsolutePath(),
                "-tor-country", Prefs.torCountry(this),
                "-tor-phase", String.valueOf(torPhase),
                "-geoip-dir", geo.getAbsolutePath(),
                "-pt-socks", startTransports(lyrebird, data))
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
                while ((l = r.readLine()) != null) {
                    log(l);
                    String mm = l.replaceFirst("^\\d\\d:\\d\\d:\\d\\d ", "");
                    if (mm.startsWith("Tor: через snowflake не подключается")) switchBridges(1);
                    else if (mm.startsWith("Страна по настоящему IP: RU")) startTorForRussia();
                    else if (mm.startsWith("Tor: запасные мосты тоже")) switchBridges(0);
                    String m = l.replaceFirst("^\\d\\d:\\d\\d:\\d\\d ", "");
                    if (m.startsWith("Tor подключён")) torState = "Tor подключён";
                    else if (m.startsWith("Tor: подключение ")) torState = "Tor подключается… " + m.substring(17);
                    else if (m.startsWith("Tor перестал отвечать")) torState = "Tor не отвечает";
                    else if (m.startsWith("Tor завершился")) torState = m;
                    else if (m.startsWith("WARP подключён")) warpState = "WARP подключён";
                    else if (m.startsWith("WARP: регистрирую")) warpState = "WARP: регистрация…";
                    else if (m.startsWith("WARP: связь")) warpState = "WARP переподключается…";
                    else if (m.startsWith("WARP: не удалось") || m.startsWith("WARP: нет связи")
                            || m.contains("блокирует WARP")) warpState = m;
                }
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
        warpState = "";
        log("VPN выключен");
        updateTile(this);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
    }

    private void cleanup() {
        recvHost = "";
        stopTransports();
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
        }
        // tor нельзя второй раз запустить в том же процессе: процесс :tor не оставляем «в запасе».
        killTorProcess();
    }

    /**
     * Tor упал: достаём из системного журнала (своего приложения — разрешение не нужно)
     * последние сообщения tor и сведения о падении, чтобы было видно причину.
     */
    private static void dumpTorCrash() {
        new Thread(() -> {
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"logcat", "-d", "-t", "600", "-v", "brief"});
                String all = readAll(p.getInputStream());
                List<String> hits = new ArrayList<>();
                for (String l : all.split("\n")) {
                    String low = l.toLowerCase(java.util.Locale.ROOT);
                    if (low.contains("tor") || low.contains("lyrebird") || low.contains("fatal signal")
                            || low.contains("androidruntime") || low.contains("abort")) {
                        hits.add(l.trim());
                    }
                }
                int from = Math.max(0, hits.size() - 25);
                if (hits.isEmpty()) {
                    log("Системный журнал: сообщений Tor нет");
                }
                for (int i = from; i < hits.size(); i++) log("[logcat] " + hits.get(i));
            } catch (Exception e) {
                log("Не удалось прочитать системный журнал: " + e.getMessage());
            }
        }, "obhod-tor-crash").start();
    }

    /** В России Tor нужен и в режиме «Авто» без Tor — для Spotify и подобных сервисов. */
    private static void startTorForRussia() {
        final ObhodVpnService s = instance;
        if (s == null || !Prefs.geoTor(s) || "dpi".equals(Prefs.route(s))) return;
        new Thread(() -> {
            synchronized (s) {
                if (!s.torBound && s.torCoreBin != null && "on".equals(state)) {
                    log("Россия: запускаю Tor для Spotify и подобных сервисов");
                    s.startTor();
                }
            }
        }, "obhod-tor-ru").start();
    }

    /** Автовыбор мостов на Android: ядро сообщает, что Tor застрял, — перезапускаем TorService с другими мостами. */
    private static void switchBridges(final int phase) {
        final ObhodVpnService s = instance;
        if (s == null) return;
        new Thread(() -> s.restartTor(phase), "obhod-tor-restart").start();
    }

    private synchronized void restartTor(int phase) {
        if (!"on".equals(state) || torCoreBin == null) return;
        torPhase = phase;
        torState = phase == 1 ? "Tor: пробую мосты obfs4 и meek…" : "Tor: снова пробую snowflake…";
        try {
            if (torBound) {
                unbindService(torConn);
                torBound = false;
            }
            stopService(new Intent(this, TorService.class));
            Thread.sleep(800);
            killTorProcess();
            Thread.sleep(700);
            //noinspection ResultOfMethodCallIgnored
            torLogFile.delete();
            writeTorrc(torCoreBin, torLyrebird, torData, torLogFile);
            torBound = bindService(new Intent(this, TorService.class), torConn, BIND_AUTO_CREATE);
        } catch (Exception e) {
            log("Не удалось перезапустить Tor: " + e.getMessage());
        }
    }

    /** Завершает процесс :tor этого приложения (если он остался от прошлого запуска). */
    private void killTorProcess() {
        android.app.ActivityManager am = (android.app.ActivityManager) getSystemService(ACTIVITY_SERVICE);
        if (am == null) return;
        boolean killed = false;
        // Ждём, пока процесс действительно исчезнет: если сразу привязаться к TorService,
        // система отдаст его ещё не умершему старому процессу, и Tor «аварийно завершится».
        for (int i = 0; i < 30; i++) {
            List<android.app.ActivityManager.RunningAppProcessInfo> list = am.getRunningAppProcesses();
            boolean alive = false;
            if (list != null) {
                for (android.app.ActivityManager.RunningAppProcessInfo p : list) {
                    if (p.processName != null && p.processName.endsWith(":tor")) {
                        alive = true;
                        android.os.Process.killProcess(p.pid);
                        killed = true;
                    }
                }
            }
            if (!alive) break;
            try { Thread.sleep(100); } catch (InterruptedException e) { break; }
        }
        if (killed) {
            try { Thread.sleep(300); } catch (InterruptedException ignored) { }
        }
    }

    /**
     * Запускает lyrebird (obfs4, webtunnel, snowflake, meek) отдельным процессом и возвращает
     * адреса его SOCKS5. Tor подключается к ним сам («ClientTransportPlugin … socks5»), как в Orbot.
     * Запускать lyrebird силами tor («exec») на Android нельзя: TorService разбирает настройки
     * дважды в одном процессе, и tor 0.4.8 падает (assert_unconfigured_count_ok).
     */
    private synchronized String startTransports(File lyrebird, File data) {
        if (alive(ptProc) && !ptSocks.isEmpty()) return ptSocks;
        stopTransports();
        if (lyrebird == null || !lyrebird.exists()) {
            log("Нет liblyrebird.so — мосты недоступны");
            return "";
        }
        File state = new File(data, "pt_state");
        //noinspection ResultOfMethodCallIgnored
        state.mkdirs();
        try {
            ProcessBuilder pb = new ProcessBuilder(lyrebird.getAbsolutePath());
            Map<String, String> env = pb.environment();
            env.put("TOR_PT_MANAGED_TRANSPORT_VER", "1");
            env.put("TOR_PT_CLIENT_TRANSPORTS", "obfs4,webtunnel,snowflake,meek_lite");
            env.put("TOR_PT_STATE_LOCATION", state.getAbsolutePath());
            env.put("TOR_PT_EXIT_ON_STDIN_CLOSE", "1");
            pb.redirectErrorStream(true);
            final Process p = pb.start();
            ptProc = p;
            final StringBuilder found = new StringBuilder();
            final java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
            new Thread(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                    String l;
                    while ((l = r.readLine()) != null) {
                        String[] f = l.trim().split("\\s+");
                        if (f.length >= 4 && "CMETHOD".equals(f[0]) && "socks5".equals(f[2])) {
                            synchronized (found) {
                                if (found.length() > 0) found.append(',');
                                found.append(f[1]).append('=').append(f[3]);
                            }
                        } else if ("CMETHODS".equals(f[0]) || "ENV-ERROR".equals(f[0]) || "VERSION-ERROR".equals(f[0])) {
                            if (!"CMETHODS".equals(f[0])) log("lyrebird: " + l);
                            done.countDown();
                        } else if (f[0].startsWith("CMETHOD-ERROR") || f[0].equals("LOG")) {
                            log("lyrebird: " + l);
                        }
                    }
                } catch (IOException ignored) {
                }
                done.countDown();
            }, "obhod-lyrebird").start();
            done.await(15, java.util.concurrent.TimeUnit.SECONDS);
            synchronized (found) {
                ptSocks = found.toString();
            }
            if (ptSocks.isEmpty()) {
                log("lyrebird не запустил транспорты");
            } else {
                log("Транспорты мостов запущены: " + ptSocks);
            }
            return ptSocks;
        } catch (Exception e) {
            log("Не удалось запустить lyrebird: " + e.getMessage());
            return "";
        }
    }

    /** Process.isAlive() есть только с Android 8, а приложение работает с Android 7. */
    private static boolean alive(Process p) {
        if (p == null) return false;
        try {
            p.exitValue();
            return false;
        } catch (IllegalThreadStateException e) {
            return true;
        }
    }

    private synchronized void stopTransports() {
        if (ptProc != null) {
            ptProc.destroy();
            ptProc = null;
        }
        ptSocks = "";
    }


    /**
     * Маршруты VPN: все адреса IPv4, кроме домашних и служебных сетей (10/8, 172.16/12, 192.168/16,
     * 169.254/16, 100.64/10, 127/8, 0/8, 224/4 — широковещательный поиск устройств, 240/4).
     * Так Chromecast, Smart TV, принтеры и устройства на точке доступа работают напрямую.
     */
    static List<String[]> publicRoutes() {
        long[][] skip = {
                {0x00000000L, 8}, {0x0A000000L, 8}, {0x64400000L, 10}, {0x7F000000L, 8}, {0xA9FE0000L, 16},
                {0xAC100000L, 12}, {0xC0A80000L, 16}, {0xE0000000L, 4}, {0xF0000000L, 4},
        };
        List<String[]> out = new ArrayList<>();
        long cur = 0, end = 1L << 32;
        java.util.Arrays.sort(skip, (x, y) -> Long.compare(x[0], y[0]));
        for (long[] sk : skip) {
            long s0 = sk[0], s1 = sk[0] + (1L << (32 - sk[1]));
            if (s0 > cur) addRange(out, cur, s0);
            cur = Math.max(cur, s1);
        }
        if (cur < end) addRange(out, cur, end);
        return out;
    }

    private static void addRange(List<String[]> out, long from, long to) {
        while (from < to) {
            int bits = 32;
            while (bits > 0) {
                long size = 1L << (32 - (bits - 1));
                if (from % size != 0 || from + size > to) break;
                bits--;
            }
            out.add(new String[]{((from >> 24) & 255) + "." + ((from >> 16) & 255) + "." + ((from >> 8) & 255) + "." + (from & 255),
                    String.valueOf(bits)});
            from += 1L << (32 - bits);
        }
    }

}
