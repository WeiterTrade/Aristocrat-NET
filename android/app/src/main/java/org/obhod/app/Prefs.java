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
            // Банки России
            "ru.sberbankmobile", "ru.sberbank.sberbankid", "com.idamob.tinkoff.android", "ru.tinkoff.mb",
            "ru.vtb24.mobilebanking.android", "ru.alfabank.mobile.android", "ru.gazprombank.android.mobilebank.app",
            "ru.raiffeisennews", "ru.rosbank.android", "ru.psbank.mobile", "ru.mkb.mobile", "ru.sovcombank.halva",
            "ru.pochtabank.pochtaapp", "ru.mtsbank.mobile", "ru.ozon.fintech.finance", "com.openbank",
            // Банки Казахстана
            "kz.kaspi.mobile", "kz.halyk.onlinebank", "kz.homebank.mobile", "kz.bcc.starbanking", "kz.jusan.mobile",
            "kz.forte.mobile", "kz.freedombank.mobile", "kz.berekebank.mobile",
            // Госуслуги и налоги
            "ru.rostel", "ru.gosuslugi.mobile", "ru.nalog.www", "com.gnivts.selfemployed", "ru.mos.polls",
            "kz.egov.mobile", "kz.gov.egov", "kz.nitec.egov.mgov",
            // Маркетплейсы, доставка, такси, связь
            "ru.ozon.app.android", "com.wildberries.ru", "com.avito.android", "ru.beru.android", "ru.yandex.taxi",
            "ru.yandex.yandexmaps", "ru.yandex.yandexnavi", "ru.dublgis.dgismobile", "com.deliveryclub",
            "ru.mts.mymts", "ru.megafon.mlk", "ru.beeline.services", "ru.tele2.mytele2", "kz.beeline.odp",
            "kz.kcell.mykcell", "kz.tele2.mytele2", "ru.vk.store", "ru.oneme.app",
            // Сервисы с привязкой к стране
            "ru.yandex.music", "com.yandex.music", "ru.kinopoisk", "ru.rutube.app", "ru.yandex.disk",
            "ru.gosuslugi.pos", "kz.chocofamily.chocotravel"));

    /** Версия списка по умолчанию: новые пункты добавляются пользователям, у которых список уже сохранён. */
    private static final int EXCLUDED_VER = 2;

    static SharedPreferences get(Context c) {
        return c.getSharedPreferences("obhod", Context.MODE_PRIVATE);
    }

    static String route(Context c) {
        String r = get(c).getString("route", "auto");
        return "dev".equals(r) ? "auto" : r; // прежний режим «Эдик на Чукотке» убран
    }

    /** Запасной путь в режиме «Авто»: warp-tor | warp | tor. */
    static String heavy(Context c) { return get(c).getString("heavy", "warp-tor"); }

    /** Страна выхода из Tor: any или код ISO (de, nl, us…). */
    static String torCountry(Context c) { return get(c).getString("country", "any"); }

    static String bridges(Context c) { return get(c).getString("bridges", "auto"); }

    static String custom(Context c) { return get(c).getString("custom", ""); }

    private static java.util.Set<String> devRoutes;

    /**
     * Режимы «через разработчика», которые есть в этой сборке: "moscow" (Ебаная Чукотка, сервер с белым IP).
     * Спрашивается у самого ядра — код вшит в libobhod.so.
     */
    static synchronized java.util.Set<String> devRoutes(Context c) {
        if (devRoutes != null) return devRoutes;
        java.util.Set<String> out = new java.util.HashSet<>();
        try {
            java.io.File core = new java.io.File(c.getApplicationInfo().nativeLibraryDir, "libobhod.so");
            Process p = new ProcessBuilder(core.getAbsolutePath(), "-dev-available").redirectErrorStream(true).start();
            byte[] buf = new byte[64];
            int n = p.getInputStream().read(buf);
            p.waitFor();
            if (n > 0) {
                for (String t : new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8).trim().split("\\s+")) {
                    if (t.equals("moscow")) out.add(t);
                }
            }
        } catch (Exception ignored) {
        }
        devRoutes = out;
        return out;
    }

    static boolean devAvailable(Context c) { return !devRoutes(c).isEmpty(); }

    /** Нужен ли Tor при текущих настройках. */
    static boolean needTor(Context c) {
        String r = route(c);
        if ("tor".equals(r)) return true;
        if (!"auto".equals(r) && !"moscow".equals(r)) return false; // «moscow»: запасной путь — как в «Авто»
        return !"warp".equals(heavy(c));
    }

    static Set<String> excluded(Context c) {
        SharedPreferences p = get(c);
        Set<String> s = p.getStringSet("excluded", null);
        if (s == null) return new HashSet<>(DEFAULT_EXCLUDED);
        Set<String> out = new HashSet<>(s);
        if (p.getInt("excluded_ver", 1) < EXCLUDED_VER) {
            out.addAll(DEFAULT_EXCLUDED);
            p.edit().putStringSet("excluded", out).putInt("excluded_ver", EXCLUDED_VER).apply();
        }
        return out;
    }

    /** Российские и казахстанские сайты — напрямую, с настоящим IP. */
    static boolean adBlock(Context c) { return get(c).getBoolean("ad_block", true); }

    static boolean keepLocal(Context c) { return get(c).getBoolean("keep_local", true); }

    /** В России Spotify и подобные — через Tor. */
    static boolean geoTor(Context c) { return get(c).getBoolean("geo_tor", true); }

    static void setExcluded(Context c, Set<String> s) {
        get(c).edit().putStringSet("excluded", new HashSet<>(s)).putInt("excluded_ver", EXCLUDED_VER).apply();
    }
}
