APP_OPTIM := release
APP_PLATFORM := android-24
APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
# JNI-класс: org.obhod.app.TProxyService
APP_CFLAGS := -O3 -DPKGNAME=org/obhod/app -DCLSNAME=TProxyService
NDK_TOOLCHAIN_VERSION := clang
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
