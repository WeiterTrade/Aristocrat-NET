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

import java.util.Arrays;

/** Настройки: маршрут, мосты Tor, свои мосты, журнал. */
public class SettingsActivity extends Activity {
    private Spinner route, bridges;
    private View customBox, bridgesLabel;
    private EditText custom;
    private TextView log, torLine;
    private String[] routeValues, bridgeValues;
    private final Handler ui = new Handler(Looper.getMainLooper());

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            log.setText(ObhodVpnService.logTail(60));
            String st = ObhodVpnService.state;
            torLine.setText("on".equals(st) || "starting".equals(st) ? ObhodVpnService.torState : "");
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_settings);
        route = findViewById(R.id.route);
        bridges = findViewById(R.id.bridges);
        bridgesLabel = findViewById(R.id.bridgesLabel);
        customBox = findViewById(R.id.customBox);
        custom = findViewById(R.id.custom);
        log = findViewById(R.id.log);
        torLine = findViewById(R.id.torLine);
        routeValues = getResources().getStringArray(R.array.route_values);
        bridgeValues = getResources().getStringArray(R.array.bridge_values);

        route.setSelection(Math.max(0, Arrays.asList(routeValues).indexOf(Prefs.route(this))));
        bridges.setSelection(Math.max(0, Arrays.asList(bridgeValues).indexOf(Prefs.bridges(this))));
        custom.setText(Prefs.custom(this));
        updateVisibility();

        route.setOnItemSelectedListener(new Picked() {
            @Override void picked(int pos) { save("route", routeValues[pos]); }
        });
        bridges.setOnItemSelectedListener(new Picked() {
            @Override void picked(int pos) { save("bridges", bridgeValues[pos]); }
        });
        findViewById(R.id.saveCustom).setOnClickListener(v -> {
            Prefs.get(this).edit().putString("custom", custom.getText().toString()).apply();
            ObhodVpnService.restartIfRunning(this);
            Toast.makeText(this, R.string.save, Toast.LENGTH_SHORT).show();
        });
        route.requestFocus();
    }

    private void save(String key, String value) {
        if (value.equals(Prefs.get(this).getString(key, ""))) return;
        Prefs.get(this).edit().putString(key, value).apply();
        updateVisibility();
        ObhodVpnService.restartIfRunning(this);
    }

    private void updateVisibility() {
        boolean tor = !"dpi".equals(Prefs.route(this));
        bridges.setVisibility(tor ? View.VISIBLE : View.GONE);
        bridgesLabel.setVisibility(tor ? View.VISIBLE : View.GONE);
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
