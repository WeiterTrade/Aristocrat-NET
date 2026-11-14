package org.obhod.app;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

final class Prefs {
    private Prefs() {}

    /**
     * Приложения, которые по умолчанию работают мимо «Обхода»: им не нужен обход блокировок,
     * а при включённом VPN или с чужим IP они отказываются работать (банки, госуслуги,
     * сервисы с привязкой к стране вроде Яндекс Музыки). Если приложение не установлено — пропускается.
     */
    static final Set<String> DEFAULT_EXCLUDED = new HashSet<>(Arrays.asList(
            "ru.yandex.music",
            "com.yandex.music",
            "kz.kaspi.mobile",
            "ru.sberbankmobile",
            "com.idamob.tinkoff.android",
            "ru.vtb24.mobilebanking.android",
            "ru.alfabank.mobile.android",
            "ru.rostel",
            "kz.egov.mobile"));

    static SharedPreferences get(Context c) {
        return c.getSharedPreferences("obhod", Context.MODE_PRIVATE);
    }

    static String route(Context c) { return get(c).getString("route", "auto"); }

    /** Запасной путь в режиме «Авто»: warp-tor | warp | tor. */
    static String heavy(Context c) { return get(c).getString("heavy", "warp-tor"); }

    static String bridges(Context c) { return get(c).getString("bridges", "auto"); }

    static String custom(Context c) { return get(c).getString("custom", ""); }

    /** Нужен ли Tor при текущих настройках. */
    static boolean needTor(Context c) {
        String r = route(c);
        if ("tor".equals(r)) return true;
        if (!"auto".equals(r)) return false;
        return !"warp".equals(heavy(c));
    }

    static Set<String> excluded(Context c) {
        Set<String> s = get(c).getStringSet("excluded", null);
        return s == null ? new HashSet<>(DEFAULT_EXCLUDED) : new HashSet<>(s);
    }

    static void setExcluded(Context c, Set<String> s) {
        get(c).edit().putStringSet("excluded", new HashSet<>(s)).apply();
    }
}
