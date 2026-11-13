# Обход

Обход блокировок **без VPN-подписок и без своего сервера** для Android (телефоны и Android TV), Windows 7–11 и Linux.

Программа работает в два этапа:

1. **Обход DPI (локально, быстро).** Начало защищённого соединения (TLS ClientHello) нарезается так, чтобы ТСПУ провайдера не смог прочитать имя сайта: TLS-запись дробится, TCP-сегменты разбиваются, применяется disorder через TTL. DNS идёт через зашифрованный DoH (1.1.1.1, 8.8.8.8, 9.9.9.9). Скорость остаётся обычной.
2. **Tor (если сайт заблокирован по IP, DNS или обход DPI не помог).** Соединение автоматически уходит в сеть Tor через мосты, потому что в России и Казахстане прямой доступ к Tor заблокирован:
   - **snowflake** — по умолчанию;
   - **webtunnel**, **obfs4**, **meek**;
   - свои мосты из Telegram-бота @GetBridgesBot.

   Сайт запоминается, и в следующий раз соединение сразу идёт через Tor.

| Платформа | Интерфейс | Файл |
|---|---|---|
| Android 7+ (телефон, планшет, **Android TV**) | системный VPN для всех приложений; управление пультом | `Obhod-…-android-universal.apk` |
| Windows 7, 8, 8.1, 10, 11 (x86/x64) | нативное окно Windows + значок в трее; системный прокси | `Obhod-Setup-….exe`, `Obhod-Portable-…-windows.zip` |
| Linux x86_64 (Ubuntu 22.04+, Mint 21+, Debian 12, Fedora) | нативное окно (GTK/WebKitGTK) + значок в трее; системный прокси (GNOME/Cinnamon) | `obhod_…_amd64.deb`, `obhod-….x86_64.rpm` |

Главный экран: большая кнопка «Включить», под ней состояние («Шифрование включено») и ваш IP с флагом страны. «О программе» — справа сверху, настройки — шестерёнка слева снизу. Закрытие окна сворачивает программу в трей; выход — из меню значка в трее или в настройках.

В GNOME значок в трее появляется после установки расширения «AppIndicator and KStatusNotifierItem Support» (в Mint, KDE, XFCE работает сразу). Без него программа тоже работает: повторный запуск из меню открывает её окно.

## Как собрать (GitHub Actions)

1. Создайте репозиторий на GitHub и загрузите в него содержимое этой папки:
   ```bash
   git init
   git add .
   git commit -m "Обход"
   git branch -M main
   git remote add origin https://github.com/<ваш-логин>/obhod.git
   git push -u origin main
   ```
2. Откройте вкладку **Actions**: сборка запустится сама и займёт около 15–25 минут. Готовые файлы лежат внизу страницы запуска, в разделе **Artifacts** (`android`, `windows`, `linux`).
3. **Релиз со всеми файлами:** создайте тег.
   ```bash
   git tag v0.3.0
   git push origin v0.3.0
   ```
   На вкладке **Releases** появятся APK, EXE, DEB, RPM и SHA256SUMS.

### Подпись APK (желательно)

Без настройки APK подписывается временным debug-ключом, который при каждой сборке новый. Устанавливать такие APK можно, но **обновить поверх старой версии не получится** — придётся удалять старую. Чтобы обновления ставились, создайте свой ключ:

```bash
keytool -genkeypair -v -keystore release.jks -alias obhod -keyalg RSA -keysize 4096 -validity 10000
base64 -w0 release.jks > release.jks.b64
```

Затем в **Settings → Secrets and variables → Actions** добавьте секреты:

- `ANDROID_KEYSTORE_BASE64` — содержимое `release.jks.b64`;
- `ANDROID_KEYSTORE_PASSWORD` — пароль хранилища;
- `ANDROID_KEY_ALIAS` — `obhod`;
- `ANDROID_KEY_PASSWORD` — пароль ключа.

## Установка

- **Android / Android TV.** Установите `…-android-universal.apk`. Если APK нужен поменьше, выберите файл под архитектуру: `arm64-v8a` для большинства телефонов, `armeabi-v7a` для многих TV-приставок. Нажмите «Включить» и разрешите VPN. На TV всё управляется пультом. Поставить APK на TV можно с флешки, через «Send Files to TV» или `adb install`.
- **Windows.** Запустите `Obhod-Setup-….exe`. На Windows 7/8 установщик сам поставит совместимую версию Tor (13.5.x), на 10/11 — актуальную. Портативная версия (zip) работает везде без установки.
- **Linux.** `sudo apt install ./obhod_…_amd64.deb` или `sudo dnf install ./obhod-….x86_64.rpm`, затем запуск «Обход» из меню или командой `obhod`.

## Режимы

- **Авто** (по умолчанию) — обход DPI, при блокировке по IP — Tor.
- **Только обход DPI** — Tor не используется. Самый быстрый режим, но сайты, заблокированные по IP, не откроются.
- **Всё через Tor** — максимальная приватность, но медленнее.

## Ограничения (честно)

- **Tor медленнее прямого соединения.** Для видео в высоком качестве он подходит плохо, зато сайты, заблокированные по IP, через него открываются.
- **Некоторые сайты блокируют вход из Tor** (банки, часть магазинов). Их стоит оставить напрямую: российские сайты и так не заблокированы и идут напрямую.
- **Режим «белых списков»** на мобильном интернете может закрыть и Tor-мосты. Тогда попробуйте другой тип моста или свои мосты из @GetBridgesBot.
- **UDP/QUIC.** На ПК в Chrome стоит отключить QUIC: chrome://flags → Experimental QUIC protocol → Disabled. На Android UDP-трафик (кроме DNS) не туннелируется, и приложения сами переходят на TCP.

## Устройство проекта

```
core/        ядро на Go (общее для всех платформ): прокси, обход DPI, DoH, управление Tor, веб-интерфейс
android/     приложение для Android/TV (Java): VpnService + hev-socks5-tunnel + tor-android + ядро
packaging/   установщик Windows (NSIS), пакеты Linux (nfpm → deb/rpm)
scripts/     загрузка Tor Expert Bundle, сборка нативных частей Android
assets/      иконки
.github/workflows/build.yml — сборка всего
```

Используемые открытые компоненты:

- [Tor](https://www.torproject.org/) (Tor Expert Bundle; [tor-android](https://github.com/guardianproject/tor-android));
- [lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird) (obfs4, webtunnel, snowflake);
- [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel).

Сборка ядра для Windows идёт на Go 1.20 — последней версии, программы которой запускаются на Windows 7.

Локальная проверка ядра:

```bash
cd core && go test ./...
```
