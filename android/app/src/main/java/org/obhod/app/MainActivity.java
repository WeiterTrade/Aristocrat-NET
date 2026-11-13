package org.obhod.app;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Главный экран: большая кнопка, состояние, реальный IP.
 * «О программе» — справа сверху, настройки — шестерёнка слева снизу.
 * Работает с сенсорным экраном и с пультом Android TV.
 */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;

    private Button power;
    private TextView status, torStatus, ip;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String lastState = "";
    private long lastIpAt = 0;

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            render();
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        power = findViewById(R.id.power);
        status = findViewById(R.id.status);
        torStatus = findViewById(R.id.torStatus);
        ip = findViewById(R.id.ip);

        power.setOnClickListener(v -> toggle());
        findViewById(R.id.gear).setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        findViewById(R.id.about).setOnClickListener(v -> showAbout());
        power.requestFocus();

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
    }

    private void showAbout() {
        String ver = "";
        try {
            ver = " " + getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception ignored) {
        }
        new AlertDialog.Builder(this)
                .setTitle(getString(R.string.app_name) + ver)
                .setMessage(R.string.about_text)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    private void toggle() {
        String st = ObhodVpnService.state;
        if ("on".equals(st) || "starting".equals(st)) {
            startService(new Intent(this, ObhodVpnService.class).setAction(ObhodVpnService.ACTION_STOP));
            return;
        }
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, REQ_VPN);
        } else {
            onActivityResult(REQ_VPN, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_VPN) return;
        if (resultCode == RESULT_OK) {
            ObhodVpnService.start(this);
        } else {
            Toast.makeText(this, "Без разрешения на VPN работа невозможна", Toast.LENGTH_LONG).show();
        }
    }

    private void render() {
        String st = ObhodVpnService.state;
        boolean on = "on".equals(st);
        boolean starting = "starting".equals(st);
        if (!st.equals(lastState)) {
            power.setBackgroundResource(on ? R.drawable.power_on : R.drawable.power_off);
            lastState = st;
            loadIp();
        } else if (System.currentTimeMillis() - lastIpAt > 120_000) {
            loadIp();
        }
        power.setText(starting ? "…" : on ? getString(R.string.disconnect) : getString(R.string.connect));
        switch (st) {
            case "on":
                status.setText(R.string.status_on);
                status.setTextColor(0xFF34C77B);
                break;
            case "starting":
                status.setText(R.string.status_starting);
                status.setTextColor(0xFFFFFFFF);
                break;
            case "error":
                status.setText("Ошибка: " + ObhodVpnService.error);
                status.setTextColor(0xFFF97316);
                break;
            default:
                status.setText(R.string.status_off);
                status.setTextColor(0xFFFFFFFF);
        }
        if (on || starting) {
            String route = Prefs.route(this);
            String mode = "dpi".equals(route) ? "Обход блокировок"
                    : "tor".equals(route) ? "Весь трафик через Tor" : "Обход блокировок + Tor при необходимости";
            String t = ObhodVpnService.torState;
            torStatus.setText(t.isEmpty() || "dpi".equals(route) ? mode : mode + "\n" + t);
        } else {
            torStatus.setText(R.string.sub_off);
        }
    }

    /** Реальный внешний IP. Приложение исключено из VPN, поэтому запрос идёт напрямую. */
    private void loadIp() {
        lastIpAt = System.currentTimeMillis();
        ip.setText("Ваш IP: …");
        new Thread(() -> {
            String found = null;
            for (String u : new String[]{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"}) {
                try {
                    HttpURLConnection c = (HttpURLConnection) new URL(u).openConnection();
                    c.setConnectTimeout(6000);
                    c.setReadTimeout(6000);
                    try (BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8))) {
                        String line = r.readLine();
                        if (line != null && line.trim().matches("[0-9a-fA-F:.]{3,45}")) {
                            found = line.trim();
                            break;
                        }
                    } finally {
                        c.disconnect();
                    }
                } catch (Exception ignored) {
                }
            }
            final String res = found;
            ui.post(() -> ip.setText(res != null ? "Ваш IP: " + res : getString(R.string.ip_unknown)));
        }, "obhod-ip").start();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(tick);
    }
}
