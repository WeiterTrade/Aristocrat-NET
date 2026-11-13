#!/usr/bin/env bash
# Собирает нативные части Android-приложения для 4 архитектур:
#   libobhod.so            — ядро «Обход» (Go, GOOS=android) — запускается как отдельный процесс
#   liblyrebird.so         — транспорты Tor obfs4/webtunnel/snowflake (Go, GOOS=android)
#   libhev-socks5-tunnel.so — tun2socks (C, NDK)
# Нужны: Go, Android NDK (ANDROID_NDK_HOME или ANDROID_NDK_LATEST_HOME), git.
# Использование: scripts/build-android-natives.sh <версия>
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION="${1:-$(cat "$ROOT/VERSION")}"
# Предпочитаем закреплённый NDK (CI ставит r27), а не самый новый.
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK_LATEST_HOME:-}}}"
[ -d "$NDK" ] || { echo "Не найден Android NDK (ANDROID_NDK_HOME)"; exit 1; }
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
API=24
MAIN="$ROOT/android/app/src/main"
JNI="$MAIN/jniLibs"
WORK="${WORK:-$ROOT/build/android}"
mkdir -p "$JNI" "$WORK"

# --- lyrebird (транспорты Tor) ---
# gitlab.torproject.org часто недоступен с серверов GitHub, поэтому основной источник —
# зеркало Go-модулей proxy.golang.org (хранит копии модулей Tor Project).
LYRE_MOD="gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird"
LYRE=""
if J=$(cd "$WORK" && GOFLAGS= go mod download -json "$LYRE_MOD@${LYREBIRD_VERSION:-latest}"); then
  SRC=$(echo "$J" | sed -n 's/.*"Dir": *"\(.*\)".*/\1/p' | head -1)
  if [ -n "$SRC" ] && [ -d "$SRC" ]; then
    # Кэш модулей только для чтения — собираем из копии.
    rm -rf "$WORK/lyrebird-src" && cp -r "$SRC" "$WORK/lyrebird-src" && chmod -R u+w "$WORK/lyrebird-src"
    LYRE="$WORK/lyrebird-src"
    echo "lyrebird из proxy.golang.org: $(echo "$J" | sed -n 's/.*"Version": *"\(.*\)".*/\1/p' | head -1)"
  fi
fi
if [ -z "$LYRE" ] || [ ! -d "$LYRE/cmd/lyrebird" ]; then
  echo "proxy.golang.org не помог, пробую gitlab.torproject.org"
  LYRE="$WORK/lyrebird"
  if [ ! -d "$LYRE/.git" ] && ! git clone -q https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git "$LYRE"; then
    LYRE=""
  else
    TAG=$(git -C "$LYRE" tag --sort=-v:refname | grep -E '^lyrebird-[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
    [ -n "$TAG" ] && git -C "$LYRE" checkout -q "$TAG"
    echo "lyrebird из gitlab: ${TAG:-$(git -C "$LYRE" rev-parse --short HEAD)}"
  fi
fi

LDX="-s -w -extldflags=-Wl,-z,max-page-size=16384"
# -checklinkname=0 нужен lyrebird: его зависимость github.com/wlynxg/anet (для Android)
# обращается к net.zoneCache через go:linkname, что Go 1.23+ по умолчанию запрещает.
for abi in armeabi-v7a arm64-v8a x86 x86_64; do
  case "$abi" in
    armeabi-v7a) GA=arm   CC="$TC/armv7a-linux-androideabi$API-clang" ;;
    arm64-v8a)   GA=arm64 CC="$TC/aarch64-linux-android$API-clang" ;;
    x86)         GA=386   CC="$TC/i686-linux-android$API-clang" ;;
    x86_64)      GA=amd64 CC="$TC/x86_64-linux-android$API-clang" ;;
  esac
  mkdir -p "$JNI/$abi"
  echo "==> $abi: ядро"
  (cd "$ROOT/core" && CGO_ENABLED=1 GOOS=android GOARCH=$GA GOARM=7 CC="$CC" \
     go build -trimpath -ldflags "$LDX -X main.appVersion=$VERSION" -o "$JNI/$abi/libobhod.so" .)
  if [ -n "$LYRE" ]; then
    echo "==> $abi: lyrebird"
    (cd "$LYRE" && CGO_ENABLED=1 GOOS=android GOARCH=$GA GOARM=7 CC="$CC" GOFLAGS=-mod=mod \
       go build -trimpath -ldflags "$LDX -checklinkname=0" -o "$JNI/$abi/liblyrebird.so" ./cmd/lyrebird)
  fi
done

# --- hev-socks5-tunnel 2.13.0 (последняя версия с mapdns и поддержкой API < 29) ---
HEV="$MAIN/jni/hev-socks5-tunnel"
if [ ! -d "$HEV" ]; then
  git clone -q --depth 1 -b 2.13.0 --recurse-submodules --shallow-submodules \
    https://github.com/heiher/hev-socks5-tunnel "$HEV"
fi
# Исправление из апстрима (5b0efbd): обнулять ARCOUNT в ответах mapdns.
if ! grep -q 'shdr->ar = 0;' "$HEV/src/hev-mapped-dns.c"; then
  sed -i 's/^\(\s*\)shdr->an = 0;/&\n\1shdr->ar = 0;/' "$HEV/src/hev-mapped-dns.c"
  grep -q 'shdr->ar = 0;' "$HEV/src/hev-mapped-dns.c" || { echo "не удалось применить патч mapdns"; exit 1; }
fi
# NDK r28+ раскрывает макрос errno внутри «#include LWIP_ERRNO_INCLUDE» → <(*__errno()).h>.
LWERR="$HEV/third-part/lwip/src/include/lwip/errno.h"
if grep -q '^#include LWIP_ERRNO_INCLUDE$' "$LWERR"; then
  sed -i 's|^#include LWIP_ERRNO_INCLUDE$|#include <errno.h> /* obhod: обход раскрытия errno в NDK r28+ */|' "$LWERR"
fi
echo "NDK: $NDK"
echo "==> hev-socks5-tunnel (ndk-build)"
# ndk-build при установке удаляет из папки вывода «чужие» .so (ядро и lyrebird),
# поэтому собираем в отдельную папку и копируем только libhev-socks5-tunnel.so.
NDKLIBS="$WORK/ndk-libs"
rm -rf "$NDKLIBS"
(cd "$MAIN" && "$NDK/ndk-build" -j"$(nproc)" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk \
   NDK_APPLICATION_MK=jni/Application.mk NDK_LIBS_OUT="$NDKLIBS" NDK_OUT="$WORK/ndk-obj")
for abi in armeabi-v7a arm64-v8a x86 x86_64; do
  mkdir -p "$JNI/$abi"
  cp "$NDKLIBS/$abi/libhev-socks5-tunnel.so" "$JNI/$abi/"
done

# Запасной вариант: готовый lyrebird из Android-сборки Tor (dist.torproject.org).
if [ -z "$LYRE" ]; then
  echo "Исходники lyrebird недоступны — беру готовые файлы из Tor Expert Bundle для Android"
  for pair in arm64-v8a:android-aarch64 armeabi-v7a:android-armv7 x86_64:android-x86_64; do
    abi=${pair%%:*}; plat=${pair#*:}
    if bash "$ROOT/scripts/fetch-tor.sh" "$plat" "$WORK/teb-$abi" >/dev/null 2>&1; then
      f=$(find "$WORK/teb-$abi" -type f -iname '*lyrebird*' | head -1 || true)
      [ -n "$f" ] && cp "$f" "$JNI/$abi/liblyrebird.so" && echo "  $abi: $(basename "$f")"
    fi
  done
fi

# В APK должны попасть только lib*.so (ndk-build может положить и исполняемый файл).
find "$JNI" -type f ! -name 'lib*.so' -delete

echo "Готово:"
find "$JNI" -type f -name '*.so' -exec ls -la {} \;
for abi in armeabi-v7a arm64-v8a x86 x86_64; do
  for f in libobhod.so libhev-socks5-tunnel.so; do
    [ -s "$JNI/$abi/$f" ] || { echo "Нет $abi/$f"; exit 1; }
  done
  if [ ! -s "$JNI/$abi/liblyrebird.so" ]; then
    # Без lyrebird на этой архитектуре Tor работает только без мостов — не повод ронять сборку.
    [ "$abi" = x86 ] && { echo "ВНИМАНИЕ: нет lyrebird для x86"; continue; }
    echo "Нет $abi/liblyrebird.so"; exit 1
  fi
done
