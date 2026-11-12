package org.obhod.app;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Arrays;

/** Главный экран. Работает и с сенсорным экраном, и с пультом Android TV (D-pad). */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;

    private Button power;
    private TextView status, torStatus, log;
    private Spinner route, bridges;
    private View customBox, bridgesLabel;
    private EditText custom;
    private String[] routeValues, bridgeValues;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String lastState = "";

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
        log = findViewById(R.id.log);
        route = findViewById(R.id.route);
        bridges = findViewById(R.id.bridges);
        bridgesLabel = findViewById(R.id.bridgesLabel);
        customBox = findViewById(R.id.customBox);
        custom = findViewById(R.id.custom);
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
            restartIfRunning();
            Toast.makeText(this, R.string.save, Toast.LENGTH_SHORT).show();
        });
        power.setOnClickListener(v -> toggle());
        power.requestFocus();

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
    }

    private void save(String key, String value) {
        String old = Prefs.get(this).getString(key, "");
        if (value.equals(old)) return;
        Prefs.get(this).edit().putString(key, value).apply();
        updateVisibility();
        restartIfRunning();
    }

    private void updateVisibility() {
        boolean tor = !"dpi".equals(Prefs.route(this));
        bridges.setVisibility(tor ? View.VISIBLE : View.GONE);
        bridgesLabel.setVisibility(tor ? View.VISIBLE : View.GONE);
        customBox.setVisibility(tor && "custom".equals(Prefs.bridges(this)) ? View.VISIBLE : View.GONE);
    }

    /** Настройки применяются перезапуском службы. */
    private void restartIfRunning() {
        if (!"on".equals(ObhodVpnService.state) && !"starting".equals(ObhodVpnService.state)) return;
        startService(new Intent(this, ObhodVpnService.class).setAction(ObhodVpnService.ACTION_STOP));
        ui.postDelayed(this::startVpn, 800);
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
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            startVpn();
        } else if (requestCode == REQ_VPN) {
            Toast.makeText(this, "Без разрешения на VPN работа невозможна", Toast.LENGTH_LONG).show();
        }
    }

    private void startVpn() {
        Intent i = new Intent(this, ObhodVpnService.class).setAction(ObhodVpnService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(i);
        } else {
            startService(i);
        }
    }

    private void render() {
        String st = ObhodVpnService.state;
        boolean on = "on".equals(st);
        if (!st.equals(lastState)) {
            power.setBackgroundResource(on ? R.drawable.power_on : R.drawable.power_off);
            lastState = st;
        }
        power.setText(on || "starting".equals(st) ? R.string.disconnect : R.string.connect);
        switch (st) {
            case "on": status.setText(R.string.status_on); break;
            case "starting": status.setText(R.string.status_starting); break;
            case "error": status.setText("Ошибка: " + ObhodVpnService.error); break;
            default: status.setText(R.string.status_off);
        }
        torStatus.setText(on || "starting".equals(st) ? ObhodVpnService.torState : "");
        log.setText(ObhodVpnService.logTail(40));
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

    /** Spinner вызывает onItemSelected и при первичной установке — игнорируем первый вызов. */
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
