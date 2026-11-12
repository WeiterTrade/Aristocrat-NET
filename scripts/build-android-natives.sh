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
NDK="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
[ -d "$NDK" ] || { echo "Не найден Android NDK (ANDROID_NDK_HOME)"; exit 1; }
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
API=24
MAIN="$ROOT/android/app/src/main"
JNI="$MAIN/jniLibs"
WORK="${WORK:-$ROOT/build/android}"
mkdir -p "$JNI" "$WORK"

# --- lyrebird (исходники Tor Project) ---
LYRE="$WORK/lyrebird"
if [ ! -d "$LYRE/.git" ]; then
  git clone -q https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git "$LYRE"
fi
TAG=$(git -C "$LYRE" tag --sort=-v:refname | grep -E '^lyrebird-[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
[ -n "$TAG" ] && git -C "$LYRE" checkout -q "$TAG"
echo "lyrebird: ${TAG:-$(git -C "$LYRE" rev-parse --short HEAD)}"

LDX="-s -w -extldflags=-Wl,-z,max-page-size=16384"
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
  echo "==> $abi: lyrebird"
  (cd "$LYRE" && CGO_ENABLED=1 GOOS=android GOARCH=$GA GOARM=7 CC="$CC" \
     go build -trimpath -ldflags "$LDX" -o "$JNI/$abi/liblyrebird.so" ./cmd/lyrebird)
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
echo "==> hev-socks5-tunnel (ndk-build)"
(cd "$MAIN" && "$NDK/ndk-build" -j"$(nproc)" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk \
   NDK_APPLICATION_MK=jni/Application.mk NDK_LIBS_OUT=jniLibs NDK_OUT="$WORK/ndk-obj")

# В APK должны попасть только lib*.so (ndk-build может положить и исполняемый файл).
find "$JNI" -type f ! -name 'lib*.so' -delete

echo "Готово:"
find "$JNI" -type f -name '*.so' -exec ls -la {} \;
for abi in armeabi-v7a arm64-v8a x86 x86_64; do
  for f in libobhod.so liblyrebird.so libhev-socks5-tunnel.so; do
    [ -s "$JNI/$abi/$f" ] || { echo "Нет $abi/$f"; exit 1; }
  done
done
