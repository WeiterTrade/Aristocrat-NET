#!/bin/sh
# Права на исполнение для tor и транспортов (на случай, если менеджер пакетов их сбросил).
chmod 755 /opt/obhod/obhod 2>/dev/null || true
[ -f /opt/obhod/tor/tor/tor ] && chmod 755 /opt/obhod/tor/tor/tor
for f in /opt/obhod/tor/pt/*; do
  case "$f" in *.json|*.md|*.txt) ;; *) chmod 755 "$f" 2>/dev/null || true ;; esac
done
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q /usr/share/icons/hicolor || true
exit 0
