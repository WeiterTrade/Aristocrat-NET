package org.obhod.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ComponentName;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.util.List;

/**
 * Раздача и приём интернета. Телефон с сим-картой включает обычную точку доступа и «Раздачу»,
 * второе устройство подключается к точке доступа и включает «Интернет с телефона».
 */
public class ShareActivity extends Activity {
    private TextView status, info;
    private Button only, both, stop, recvOn, recvStop;
    private final Handler ui = new Handler(Looper.getMainLooper());
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
        setContentView(R.layout.activity_share);
        status = findViewById(R.id.shareStatus);
        info = findViewById(R.id.shareInfo);
        only = findViewById(R.id.shareOnly);
        both = findViewById(R.id.shareBoth);
        stop = findViewById(R.id.shareStop);
        recvOn = findViewById(R.id.recvOn);
        recvStop = findViewById(R.id.recvStop);
        only.setOnClickListener(v -> startActivity(StartActivity.intent(this, false, true)));
        both.setOnClickListener(v -> startActivity(StartActivity.intent(this, true, true)));
        // Выключить раздачу; обход (если был включён) продолжает работать.
        stop.setOnClickListener(v -> ObhodVpnService.run(this, ObhodVpnService.vpnActive(), false));
        recvOn.setOnClickListener(v -> startActivity(StartActivity.intent(this, false, false, true)));
        recvStop.setOnClickListener(v -> ObhodVpnService.run(this, false, false, false));
        findViewById(R.id.addTile).setOnClickListener(v -> addTile());
    }

    /** Android 13+: система сама предлагает добавить кнопки (по очереди). Раньше — подсказка, где их найти. */
    private void addTile() {
        if (Build.VERSION.SDK_INT >= 33) {
            try {
                android.app.StatusBarManager sbm = getSystemService(android.app.StatusBarManager.class);
                sbm.requestAddTileService(new ComponentName(this, AristocratTile.class),
                        getString(R.string.tile_vpn_label),
                        android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_tile),
                        getMainExecutor(), r -> sbm.requestAddTileService(new ComponentName(this, ShareTile.class),
                                getString(R.string.tile_share_label),
                                android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_tile_share),
                                getMainExecutor(), r2 -> { }));
                return;
            } catch (Exception ignored) {
            }
        }
        new AlertDialog.Builder(this)
                .setTitle(R.string.tile_add)
                .setMessage(R.string.tile_add_help)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    private void render() {
        boolean share = ObhodVpnService.shareActive();
        boolean withVpn = share && ObhodVpnService.runVpn;
        boolean recv = ObhodVpnService.recvActive();
        if ("error".equals(ObhodVpnService.state)) {
            status.setText("Ошибка: " + ObhodVpnService.error);
        } else if (recv) {
            status.setText(ObhodVpnService.recvHost.isEmpty() ? getString(R.string.recv_starting)
                    : getString(R.string.recv_on) + " " + ObhodVpnService.recvHost);
        } else if (share) {
            status.setText(withVpn ? R.string.share_on_both : R.string.share_on_plain);
        } else {
            status.setText(R.string.share_off);
        }
        if (share) {
            List<String> addrs = LanInfo.addresses();
            info.setText(addrs.isEmpty() ? getString(R.string.share_no_hotspot)
                    : getString(R.string.share_addr) + " " + android.text.TextUtils.join(", ", addrs)
                    + ", порт " + ObhodVpnService.SHARE_PORT + "\n" + getString(R.string.share_give_next));
        } else {
            info.setText(R.string.share_give_hint);
        }
        only.setVisibility(share && !withVpn ? View.GONE : View.VISIBLE);
        both.setVisibility(withVpn ? View.GONE : View.VISIBLE);
        stop.setVisibility(share ? View.VISIBLE : View.GONE);
        recvOn.setVisibility(recv ? View.GONE : View.VISIBLE);
        recvStop.setVisibility(recv ? View.VISIBLE : View.GONE);
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
