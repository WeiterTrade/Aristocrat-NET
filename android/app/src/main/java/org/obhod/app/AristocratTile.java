package org.obhod.app;

/**
 * Кнопка «Обход блокировок» (щит). Нажатие включает обход, повторное — выключает.
 * Раздача, если она включена второй кнопкой, при этом продолжает работать.
 */
public class AristocratTile extends BaseTile {

    @Override
    boolean on() {
        return ObhodVpnService.vpnActive();
    }

    @Override
    String subtitle() {
        if (!on()) return getString(R.string.tile_off);
        return ObhodVpnService.shareActive() ? getString(R.string.tile_both) : getString(R.string.tile_on);
    }

    @Override
    public void onClick() {
        boolean share = ObhodVpnService.shareActive();
        if (on()) {
            ObhodVpnService.run(this, false, share);
            show(false);
        } else {
            start(true, share, false);
        }
    }
}
