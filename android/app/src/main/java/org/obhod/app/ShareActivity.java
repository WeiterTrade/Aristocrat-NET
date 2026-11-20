package org.obhod.app;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

/** Раздача Wi-Fi: имя сети, пароль, адрес прокси и инструкция для подключаемых устройств. */
public class ShareActivity extends Activity {
    private TextView status, info;
    private View card;
    private Button only, both, stop;
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
        card = findViewById(R.id.shareCard);
        only = findViewById(R.id.shareOnly);
        both = findViewById(R.id.shareBoth);
        stop = findViewById(R.id.shareStop);
        only.setOnClickListener(v -> startActivity(StartActivity.intent(this, false, true)));
        both.setOnClickListener(v -> startActivity(StartActivity.intent(this, true, true)));
        // Выключить раздачу; обход (если был включён) продолжает работать.
        stop.setOnClickListener(v -> ObhodVpnService.run(this, ObhodVpnService.vpnActive(), false));
        findViewById(R.id.sharePassCopy).setOnClickListener(v -> {
            String p = ObhodVpnService.sharePass;
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm != null && !p.isEmpty()) {
                cm.setPrimaryClip(ClipData.newPlainText("password", p));
                Toast.makeText(this, R.string.share_pass_copied, Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void render() {
        boolean on = ObhodVpnService.shareActive();
        boolean withVpn = on && ObhodVpnService.runVpn;
        if (!on) {
            String err = "error".equals(ObhodVpnService.state) ? ObhodVpnService.error : "";
            status.setText(err.isEmpty() ? getString(R.string.share_off) : "Ошибка: " + err);
        } else if (ObhodVpnService.shareSsid.isEmpty()) {
            status.setText(ObhodVpnService.shareState.isEmpty() ? getString(R.string.share_starting) : ObhodVpnService.shareState);
        } else {
            status.setText(withVpn ? R.string.share_on_both : R.string.share_on_plain);
        }
        boolean ready = on && !ObhodVpnService.shareSsid.isEmpty();
        card.setVisibility(ready ? View.VISIBLE : View.GONE);
        if (ready) {
            String host = ObhodVpnService.shareHost + ":" + ObhodVpnService.SHARE_PORT;
            info.setText("Сеть Wi-Fi: " + ObhodVpnService.shareSsid
                    + "\nПароль: " + ObhodVpnService.sharePass
                    + "\nПрокси: " + ObhodVpnService.shareHost + ", порт " + ObhodVpnService.SHARE_PORT
                    + "\nАвтонастройка: http://" + host + "/proxy.pac");
        }
        only.setVisibility(on && !withVpn ? View.GONE : View.VISIBLE);
        both.setVisibility(withVpn ? View.GONE : View.VISIBLE);
        stop.setVisibility(on ? View.VISIBLE : View.GONE);
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
