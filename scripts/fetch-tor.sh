#!/usr/bin/env bash
# Скачивает Tor Expert Bundle и раскладывает его в единую структуру:
#   OUT/tor/   — tor(.exe) и его библиотеки
#   OUT/pt/    — lyrebird и др. транспорты + pt_config.json (встроенные мосты)
#   OUT/data/  — geoip, geoip6
#
# Использование: fetch-tor.sh <платформа> <OUT> [версия]
#   платформа: windows-i686 | windows-x86_64 | linux-x86_64 | android-aarch64 | android-armv7 | android-x86_64
#   версия:    например 13.5.29 (последняя с поддержкой Windows 7/8); по умолчанию — последняя стабильная.
set -euo pipefail
PLAT="$1"; OUT="$2"; VER="${3:-${TOR_VERSION:-}}"
DIST=${TOR_DIST_URL:-https://dist.torproject.org/torbrowser}
ARCH=${TOR_ARCHIVE_URL:-https://archive.torproject.org/tor-package-archive/torbrowser}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

try_get() { # $1 версия → скачивает в $TMP/teb.tar.gz
  local f="tor-expert-bundle-${PLAT}-$1.tar.gz"
  for base in "$DIST/$1" "$ARCH/$1"; do
    if curl -fsSL --retry 3 -o "$TMP/teb.tar.gz" "$base/$f"; then
      echo "Скачан $base/$f"; return 0
    fi
  done
  return 1
}

if [ -n "$VER" ]; then
  try_get "$VER" || { echo "Не найден Tor Expert Bundle $PLAT $VER"; exit 1; }
else
  # Последние стабильные версии (без alpha «a»), от новой к старой.
  mapfile -t VERS < <(curl -fsSL "$DIST/" | grep -oE 'href="[0-9]+\.[0-9]+(\.[0-9]+)?/"' | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -uV -r)
  ok=""
  for v in "${VERS[@]}"; do
    if try_get "$v"; then VER="$v"; ok=1; break; fi
  done
  [ -n "$ok" ] || { echo "Не удалось скачать Tor Expert Bundle для $PLAT"; exit 1; }
fi

mkdir -p "$TMP/x" && tar xzf "$TMP/teb.tar.gz" -C "$TMP/x"
rm -rf "$OUT" && mkdir -p "$OUT/tor" "$OUT/pt" "$OUT/data"

TOR_BIN=$(find "$TMP/x" -type f \( -name tor -o -name tor.exe -o -name libTor.so -o -name tor.so \) | head -1 || true)
if [ -n "$TOR_BIN" ]; then
  cp -a "$(dirname "$TOR_BIN")"/. "$OUT/tor/"
fi
PT_CFG=$(find "$TMP/x" -type f -name pt_config.json | head -1 || true)
if [ -n "$PT_CFG" ]; then
  cp -a "$(dirname "$PT_CFG")"/. "$OUT/pt/"
fi
# В папке tor/ нужны только сам tor и библиотеки — подпапки (транспорты, docs) убираем.
find "$OUT/tor" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
for g in geoip geoip6; do
  f=$(find "$TMP/x" -type f -name "$g" | head -1 || true)
  [ -n "$f" ] && cp "$f" "$OUT/data/"
done
# Если транспорты лежат не рядом с pt_config.json — ищем их по имени.
for name in lyrebird lyrebird.exe snowflake-client snowflake-client.exe conjure-client conjure-client.exe; do
  if [ ! -e "$OUT/pt/$name" ]; then
    f=$(find "$TMP/x" -type f -name "$name" | head -1 || true)
    [ -n "$f" ] && cp "$f" "$OUT/pt/"
  fi
done
echo "$VER" > "$OUT/VERSION"
chmod -R u+rwX,go+rX "$OUT"
find "$OUT" -type f -name 'tor' -o -type f -name '*lyrebird*' -o -type f -name 'snowflake-client' | xargs -r chmod +x
echo "Tor Expert Bundle $PLAT $VER →  $OUT"
find "$OUT" -maxdepth 2 | sort | sed 's/^/  /'
[ -f "$OUT/pt/pt_config.json" ] || { echo "ВНИМАНИЕ: нет pt_config.json"; exit 1; }
