package org.obhod.app;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Toast;

/**
 * Невидимый экран запуска: получает нужные разрешения (VPN, Wi-Fi Direct), проверяет Wi-Fi
 * и включает выбранный режим. Открывается из шторки, с главного экрана и экрана раздачи.
 */
public class StartActivity extends Activity {
    private static final int REQ_PERM = 1, REQ_VPN = 2;
    private boolean vpn, share, askedPerm, askedVpn;

    static Intent intent(Context c, boolean vpn, boolean share) {
        return new Intent(c, StartActivity.class)
                .putExtra(ObhodVpnService.EXTRA_VPN, vpn)
                .putExtra(ObhodVpnService.EXTRA_SHARE, share);
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        vpn = getIntent().getBooleanExtra(ObhodVpnService.EXTRA_VPN, true);
        share = getIntent().getBooleanExtra(ObhodVpnService.EXTRA_SHARE, false);
        next();
    }

    private void next() {
        if (share) {
            if (!WifiShare.supported(this)) {
                toast(R.string.share_unsupported);
                finish();
                return;
            }
            String p = WifiShare.missingPermission(this);
            if (p != null) {
                if (!askedPerm) {
                    askedPerm = true;
                    requestPermissions(new String[]{p}, REQ_PERM);
                } else {
                    toast(R.string.share_need_perm);
                    finish();
                }
                return;
            }
            if (!WifiShare.wifiOn(this)) {
                toast(R.string.share_need_wifi);
                try {
                    startActivity(new Intent(Build.VERSION.SDK_INT >= 29 ? Settings.Panel.ACTION_WIFI
                            : Settings.ACTION_WIFI_SETTINGS));
                } catch (Exception ignored) {
                }
                finish();
                return;
            }
        }
        if (vpn) {
            Intent p = VpnService.prepare(this);
            if (p != null) {
                if (!askedVpn) {
                    askedVpn = true;
                    startActivityForResult(p, REQ_VPN);
                } else {
                    toast(R.string.vpn_need_perm);
                    finish();
                }
                return;
            }
        }
        ObhodVpnService.run(this, vpn, share);
        finish();
    }

    private void toast(int res) {
        Toast.makeText(getApplicationContext(), res, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] res) {
        next();
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        next();
    }
}
