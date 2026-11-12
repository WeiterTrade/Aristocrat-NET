package org.obhod.app;

/**
 * JNI-мост к hev-socks5-tunnel: переводит пакеты из TUN в SOCKS5-соединения к ядру.
 * Имя класса и пакета зашиты в библиотеку при сборке (PKGNAME/CLSNAME в Application.mk).
 */
public final class TProxyService {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    private TProxyService() {}

    public static native void TProxyStartService(String configPath, int fd);

    public static native void TProxyStopService();

    public static native long[] TProxyGetStats();
}
