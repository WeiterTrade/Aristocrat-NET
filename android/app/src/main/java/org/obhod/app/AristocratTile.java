package org.obhod.app;

import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/**
 * Плитка в шторке. Выключено — нажатие предлагает режим: обход блокировок, раздача Wi-Fi
 * или раздача с обходом. Включено — нажатие выключает.
 */
public class AristocratTile extends TileService {

    @Override
    public void onStartListening() {
        update();
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) return;
        boolean on = ObhodVpnService.active();
        t.setState(on ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.setLabel(getString(R.string.app_name));
        if (Build.VERSION.SDK_INT >= 29) t.setSubtitle(modeText());
        t.updateTile();
    }

    private String modeText() {
        if (!ObhodVpnService.active()) return getString(R.string.tile_off);
        if (ObhodVpnService.runVpn && ObhodVpnService.runShare) return getString(R.string.tile_both);
        if (ObhodVpnService.runShare) return getString(R.string.tile_share);
        return getString(R.string.tile_vpn);
    }

    @Override
    public void onClick() {
        if (ObhodVpnService.active()) {
            ObhodVpnService.run(this, false, false);
            update();
            return;
        }
        String[] items = {getString(R.string.mode_vpn), getString(R.string.mode_share), getString(R.string.mode_both)};
        AlertDialog d = new AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle(R.string.app_name)
                .setItems(items, (dlg, which) -> choose(which != 1, which != 0))
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        showDialog(d);
    }

    private void choose(boolean vpn, boolean share) {
        boolean needUi = (vpn && VpnService.prepare(this) != null)
                || (share && (WifiShare.missingPermission(this) != null || !WifiShare.wifiOn(this)));
        if (!needUi) {
            ObhodVpnService.run(this, vpn, share);
            update();
            return;
        }
        // Нужно разрешение (VPN, Wi-Fi Direct) или включить Wi-Fi — это делает экран приложения.
        Intent i = StartActivity.intent(this, vpn, share).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 3, i,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
        } else {
            startActivityAndCollapse(i);
        }
    }
}
