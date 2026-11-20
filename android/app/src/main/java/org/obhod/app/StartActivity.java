package org.obhod.app;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Toast;

/**
 * Невидимый экран запуска: спрашивает разрешение на VPN (если нужно) и включает выбранный режим.
 * Открывается из шторки, с главного экрана и экрана раздачи.
 */
public class StartActivity extends Activity {
    private static final int REQ_VPN = 2;
    private boolean vpn, share, recv, askedVpn;

    static Intent intent(Context c, boolean vpn, boolean share) {
        return intent(c, vpn, share, false);
    }

    static Intent intent(Context c, boolean vpn, boolean share, boolean recv) {
        return new Intent(c, StartActivity.class)
                .putExtra(ObhodVpnService.EXTRA_VPN, vpn)
                .putExtra(ObhodVpnService.EXTRA_SHARE, share)
                .putExtra(ObhodVpnService.EXTRA_RECV, recv);
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        vpn = getIntent().getBooleanExtra(ObhodVpnService.EXTRA_VPN, true);
        share = getIntent().getBooleanExtra(ObhodVpnService.EXTRA_SHARE, false);
        recv = getIntent().getBooleanExtra(ObhodVpnService.EXTRA_RECV, false);
        next();
    }

    private void next() {
        if (vpn || recv) {
            Intent p = VpnService.prepare(this);
            if (p != null) {
                if (!askedVpn) {
                    askedVpn = true;
                    startActivityForResult(p, REQ_VPN);
                } else {
                    Toast.makeText(getApplicationContext(), R.string.vpn_need_perm, Toast.LENGTH_LONG).show();
                    finish();
                }
                return;
            }
        }
        ObhodVpnService.run(this, vpn, share, recv);
        finish();
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        next();
    }
}
