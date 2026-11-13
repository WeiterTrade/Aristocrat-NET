package org.obhod.app;

import android.content.Context;
import android.content.SharedPreferences;

final class Prefs {
    private Prefs() {}

    static SharedPreferences get(Context c) {
        return c.getSharedPreferences("obhod", Context.MODE_PRIVATE);
    }

    static String route(Context c) { return get(c).getString("route", "auto"); }

    static String bridges(Context c) { return get(c).getString("bridges", "auto"); }

    static String custom(Context c) { return get(c).getString("custom", ""); }
}
