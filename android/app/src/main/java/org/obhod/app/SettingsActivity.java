package org.obhod.app;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

/** Настройки: маршрут, запасной путь (WARP/Tor), мосты Tor, приложения мимо «Обхода», журнал. */
public class SettingsActivity extends Activity {
    private Spinner route, heavy, bridges, country;
    private View customBox, bridgesLabel, heavyLabel, countryLabel;
    private EditText custom;
    private TextView torLine;
    private String[] routeValues, heavyValues, bridgeValues, countryValues;
    private final Handler ui = new Handler(Looper.getMainLooper());

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            String st = ObhodVpnService.state;
            String line = "";
            if ("on".equals(st) || "starting".equals(st)) {
                line = ObhodVpnService.warpState;
                if (!ObhodVpnService.torState.isEmpty()) {
                    line = line.isEmpty() ? ObhodVpnService.torState : line + "\n" + ObhodVpnService.torState;
                }
            }
            torLine.setText(line);
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_settings);
        route = findViewById(R.id.route);
        bridges = findViewById(R.id.bridges);
        heavy = findViewById(R.id.heavy);
        country = findViewById(R.id.country);
        countryLabel = findViewById(R.id.countryLabel);
        heavyLabel = findViewById(R.id.heavyLabel);
        bridgesLabel = findViewById(R.id.bridgesLabel);
        customBox = findViewById(R.id.customBox);
        custom = findViewById(R.id.custom);
        findViewById(R.id.openLog).setOnClickListener(v -> startActivity(new Intent(this, LogActivity.class)));
        torLine = findViewById(R.id.torLine);
        routeValues = getResources().getStringArray(R.array.route_values);
        bridgeValues = getResources().getStringArray(R.array.bridge_values);
        heavyValues = getResources().getStringArray(R.array.heavy_values);
        countryValues = getResources().getStringArray(R.array.country_values);
        country.setSelection(Math.max(0, Arrays.asList(countryValues).indexOf(Prefs.torCountry(this))));
        heavy.setSelection(Math.max(0, Arrays.asList(heavyValues).indexOf(Prefs.heavy(this))));

        route.setSelection(Math.max(0, Arrays.asList(routeValues).indexOf(Prefs.route(this))));
        bridges.setSelection(Math.max(0, Arrays.asList(bridgeValues).indexOf(Prefs.bridges(this))));
        custom.setText(Prefs.custom(this));
        updateVisibility();

        route.setOnItemSelectedListener(new Picked() {
            @Override void picked(int pos) { save("route", routeValues[pos]); }
        });
        country.setOnItemSelectedListener(new Picked() {
            @Override void picked(int pos) { save("country", countryValues[pos]); }
        });
        heavy.setOnItemSelectedListener(new Picked() {
            @Override void picked(int pos) { save("heavy", heavyValues[pos]); }
        });
        bridges.setOnItemSelectedListener(new Picked() {
            @Override void picked(int pos) { save("bridges", bridgeValues[pos]); }
        });
        findViewById(R.id.saveCustom).setOnClickListener(v -> {
            Prefs.get(this).edit().putString("custom", custom.getText().toString()).apply();
            ObhodVpnService.restartIfRunning(this);
            Toast.makeText(this, R.string.save, Toast.LENGTH_SHORT).show();
        });
        bindCheck(R.id.keepLocal, "keep_local", Prefs.keepLocal(this));
        bindCheck(R.id.geoTor, "geo_tor", Prefs.geoTor(this));
        findViewById(R.id.apps).setOnClickListener(v -> pickApps());
        findViewById(R.id.warpReset).setOnClickListener(v -> {
            //noinspection ResultOfMethodCallIgnored
            new File(new File(getFilesDir(), "core"), "warp.json").delete();
            ObhodVpnService.restartIfRunning(this);
            Toast.makeText(this, "Будет получен новый аккаунт WARP", Toast.LENGTH_SHORT).show();
        });
        updateAppsInfo();
        route.requestFocus();
    }

    private void bindCheck(int id, String key, boolean value) {
        android.widget.CheckBox cb = findViewById(id);
        cb.setChecked(value);
        cb.setOnCheckedChangeListener((v, checked) -> {
            Prefs.get(this).edit().putBoolean(key, checked).apply();
            ObhodVpnService.restartIfRunning(this);
        });
    }

    private void updateAppsInfo() {
        int n = 0;
        PackageManager pm = getPackageManager();
        for (String p : Prefs.excluded(this)) {
            try {
                pm.getApplicationInfo(p, 0);
                n++;
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        ((TextView) findViewById(R.id.appsInfo)).setText(getString(R.string.apps_hint)
                + "\nВыбрано установленных: " + n);
    }

    /** Список приложений с галочками: отмеченные работают мимо «Обхода». */
    private void pickApps() {
        Toast.makeText(this, "Загружаю список приложений…", Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            PackageManager pm = getPackageManager();
            TreeMap<String, String> apps = new TreeMap<>(String.CASE_INSENSITIVE_ORDER); // название → пакет
            List<ResolveInfo> found = new ArrayList<>();
            found.addAll(pm.queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0));
            found.addAll(pm.queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LEANBACK_LAUNCHER), 0));
            for (ResolveInfo ri : found) {
                String pkg = ri.activityInfo.packageName;
                if (pkg.equals(getPackageName()) || apps.containsValue(pkg)) continue;
                String label = String.valueOf(ri.loadLabel(pm));
                String key = label;
                for (int i = 2; apps.containsKey(key); i++) key = label + " (" + i + ")";
                apps.put(key, pkg);
            }
            final List<String> labels = new ArrayList<>(apps.keySet());
            final List<String> pkgs = new ArrayList<>(apps.values());
            ui.post(() -> showApps(labels, pkgs));
        }, "obhod-apps").start();
    }

    private void showApps(List<String> labels, List<String> pkgs) {
        if (isFinishing()) return;
        final Set<String> sel = Prefs.excluded(this);
        // Сначала отмеченные, потом остальные (по алфавиту).
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < pkgs.size(); i++) if (sel.contains(pkgs.get(i))) order.add(i);
        for (int i = 0; i < pkgs.size(); i++) if (!sel.contains(pkgs.get(i))) order.add(i);
        final String[] items = new String[order.size()];
        final String[] itemPkgs = new String[order.size()];
        final boolean[] checked = new boolean[order.size()];
        for (int j = 0; j < order.size(); j++) {
            int i = order.get(j);
            items[j] = labels.get(i);
            itemPkgs[j] = pkgs.get(i);
            checked[j] = sel.contains(pkgs.get(i));
        }
        new AlertDialog.Builder(this)
                .setTitle(R.string.apps_title)
                .setMultiChoiceItems(items, checked, (d, which, isChecked) -> checked[which] = isChecked)
                .setPositiveButton(R.string.save, (d, w) -> {
                    // Неустановленные пакеты из прежнего списка (например, банк по умолчанию) сохраняем.
                    Set<String> out = Prefs.excluded(this);
                    for (int j = 0; j < itemPkgs.length; j++) {
                        if (checked[j]) out.add(itemPkgs[j]);
                        else out.remove(itemPkgs[j]);
                    }
                    Prefs.setExcluded(this, out);
                    updateAppsInfo();
                    ObhodVpnService.restartIfRunning(this);
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void save(String key, String value) {
        if (value.equals(Prefs.get(this).getString(key, ""))) return;
        Prefs.get(this).edit().putString(key, value).apply();
        updateVisibility();
        ObhodVpnService.restartIfRunning(this);
    }

    private void updateVisibility() {
        boolean auto = "auto".equals(Prefs.route(this));
        heavy.setVisibility(auto ? View.VISIBLE : View.GONE);
        heavyLabel.setVisibility(auto ? View.VISIBLE : View.GONE);
        boolean tor = Prefs.needTor(this);
        bridges.setVisibility(tor ? View.VISIBLE : View.GONE);
        bridgesLabel.setVisibility(tor ? View.VISIBLE : View.GONE);
        country.setVisibility(tor ? View.VISIBLE : View.GONE);
        countryLabel.setVisibility(tor ? View.VISIBLE : View.GONE);
        customBox.setVisibility(tor && "custom".equals(Prefs.bridges(this)) ? View.VISIBLE : View.GONE);
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

    /** Spinner вызывает onItemSelected и при первичной установке — первый вызов пропускаем. */
    private abstract static class Picked implements AdapterView.OnItemSelectedListener {
        private boolean first = true;

        abstract void picked(int pos);

        @Override
        public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
            if (first) {
                first = false;
                return;
            }
            picked(position);
        }

        @Override
        public void onNothingSelected(AdapterView<?> parent) {}
    }
}
