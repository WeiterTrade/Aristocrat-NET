package org.obhod.app;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/** Журнал отдельным экраном: весь текст и кнопка «Копировать». */
public class LogActivity extends Activity {
    private TextView log;
    private ScrollView scroll;
    private String last = "";
    private final Handler ui = new Handler(Looper.getMainLooper());

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            String t = ObhodVpnService.logTail(200);
            if (!t.equals(last)) {
                boolean atEnd = scroll.getScrollY() + scroll.getHeight() >= log.getHeight() - 20;
                last = t;
                log.setText(t.isEmpty() ? "Журнал пуст" : t);
                if (atEnd) scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
            }
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_log);
        log = findViewById(R.id.log);
        scroll = findViewById(R.id.logScroll);
        findViewById(R.id.copyLog).setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("Aristocrat NET", ObhodVpnService.logTail(200)));
                Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show();
            }
        });
        findViewById(R.id.copyLog).requestFocus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        BridgeShare.resume(this);
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        BridgeShare.pause(this);
        ui.removeCallbacks(tick);
    }
}
