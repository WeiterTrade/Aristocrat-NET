package org.obhod.app;

import android.os.Handler;
import android.os.Looper;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Общее для кнопок в шторке. Пока шторка открыта, кнопка «слушает» — и служба сама
 * обновляет её при каждом изменении состояния (включается, включилась, выключилась).
 */
abstract class BaseTile extends TileService {
    private static final Set<BaseTile> LISTENING = Collections.synchronizedSet(new HashSet<>());
    private static final Handler UI = new Handler(Looper.getMainLooper());

    /** Включено ли то, чем управляет кнопка. */
    abstract boolean on();

    abstract String subtitle();

    @Override
    public void onStartListening() {
        LISTENING.add(this);
        update();
    }

    @Override
    public void onStopListening() {
        LISTENING.remove(this);
    }

    /** Обновить все открытые кнопки (вызывает служба при смене состояния). */
    static void refreshAll() {
        UI.post(() -> {
            BaseTile[] all;
            synchronized (LISTENING) {
                all = LISTENING.toArray(new BaseTile[0]);
            }
            for (BaseTile t : all) t.update();
        });
    }

    void update() {
        show(on());
    }

    /** Сразу показать ожидаемое состояние (служба подтвердит через секунду). */
    void show(boolean active) {
        Tile t = getQsTile();
        if (t == null) return;
        t.setState(active ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        if (android.os.Build.VERSION.SDK_INT >= 29) t.setSubtitle(subtitle());
        t.updateTile();
    }

    /** Запуск режима: если нужно разрешение на VPN — через экран приложения. */
    void start(boolean vpn, boolean share, boolean recv) {
        if ((vpn || recv) && android.net.VpnService.prepare(this) != null) {
            android.content.Intent i = StartActivity.intent(this, vpn, share, recv)
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            if (android.os.Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(android.app.PendingIntent.getActivity(this, 3, i,
                        android.app.PendingIntent.FLAG_IMMUTABLE | android.app.PendingIntent.FLAG_UPDATE_CURRENT));
            } else {
                startActivityAndCollapse(i);
            }
            return;
        }
        ObhodVpnService.run(this, vpn, share, recv);
        show(true);
    }
}
