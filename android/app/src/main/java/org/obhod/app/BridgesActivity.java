package org.obhod.app;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.Toast;

/** «Свои мосты» отдельным экраном: большое поле, «Вставить», «Сохранить». */
public class BridgesActivity extends Activity {
    private EditText text;

    /** Сколько строк-мостов в тексте (без пустых и комментариев). */
    static int count(String s) {
        int n = 0;
        if (s == null) return 0;
        for (String l : s.split("\n")) {
            l = l.trim();
            if (!l.isEmpty() && !l.startsWith("#")) n++;
        }
        return n;
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_bridges);
        text = findViewById(R.id.bridgesText);
        text.setText(Prefs.custom(this));
        findViewById(R.id.saveBridges).setOnClickListener(v -> save());
        findViewById(R.id.pasteBridges).setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            ClipData c = cm != null ? cm.getPrimaryClip() : null;
            CharSequence t = c != null && c.getItemCount() > 0 ? c.getItemAt(0).coerceToText(this) : null;
            if (t == null || t.toString().trim().isEmpty()) {
                Toast.makeText(this, R.string.bridges_empty, Toast.LENGTH_SHORT).show();
                return;
            }
            String cur = text.getText().toString().trim();
            text.setText(cur.isEmpty() ? t.toString().trim() : cur + "\n" + t.toString().trim());
            text.setSelection(text.length());
        });
        findViewById(R.id.clearBridges).setOnClickListener(v -> text.setText(""));
    }

    private void save() {
        // Бот присылает мосты со строкой «Bridge» или пустыми строками — убираем лишнее.
        StringBuilder sb = new StringBuilder();
        for (String l : text.getText().toString().split("\n")) {
            l = l.trim();
            if (l.startsWith("Bridge ")) l = l.substring(7).trim();
            if (!l.isEmpty()) sb.append(l).append('\n');
        }
        String s = sb.toString().trim();
        android.content.SharedPreferences.Editor e = Prefs.get(this).edit().putString("custom", s);
        // Мосты вставлены, а выбран встроенный тип — переключаемся на свои (в «Авто» они и так первые).
        String br = Prefs.bridges(this);
        if (!s.isEmpty() && !"auto".equals(br) && !"custom".equals(br)) e.putString("bridges", "custom");
        e.apply();
        text.setText(s);
        ObhodVpnService.restartIfRunning(this);
        Toast.makeText(this, R.string.bridges_saved, Toast.LENGTH_SHORT).show();
        finish();
    }

    @Override
    protected void onResume() {
        super.onResume();
        BridgeShare.resume(this);
    }

    @Override
    protected void onPause() {
        super.onPause();
        BridgeShare.pause(this);
    }
}
