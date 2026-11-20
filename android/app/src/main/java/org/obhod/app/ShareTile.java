package org.obhod.app;

import android.app.AlertDialog;

/**
 * Кнопка «Раздача» (антенна). Выключено — нажатие предлагает: раздача, раздача с обходом
 * блокировок или приём интернета с другого телефона. Включено — нажатие выключает.
 */
public class ShareTile extends BaseTile {

    @Override
    boolean on() {
        return ObhodVpnService.shareActive() || ObhodVpnService.recvActive();
    }

    @Override
    String subtitle() {
        if (ObhodVpnService.recvActive()) return getString(R.string.tile_recv);
        if (!ObhodVpnService.shareActive()) return getString(R.string.tile_off);
        return ObhodVpnService.runVpn ? getString(R.string.tile_both) : getString(R.string.tile_on);
    }

    @Override
    public void onClick() {
        if (on()) {
            // Выключить раздачу или приём; обход (если включён щитом) остаётся.
            ObhodVpnService.run(this, ObhodVpnService.vpnActive(), false, false);
            show(false);
            return;
        }
        String[] items = {getString(R.string.mode_share), getString(R.string.mode_both), getString(R.string.mode_recv)};
        AlertDialog d = new AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle(R.string.tile_share_label)
                .setItems(items, (dlg, which) -> {
                    if (which == 2) start(false, false, true);
                    else start(which == 1 || ObhodVpnService.vpnActive(), true, false);
                })
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        showDialog(d);
    }
}
