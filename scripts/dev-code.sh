#!/usr/bin/env bash
# Печатает код подключения к компьютеру разработчика (или пустую строку).
# Источник: секрет GitHub DEV_CODE (переменная окружения), иначе файл dev-code.txt в корне репозитория.
# Формат: <56 символов адреса .onion>:<52 символа ключа>.
set -u
RE='^[a-z2-7]{56}(\.onion)?:[A-Z2-7]{52}$'
DC="$(printf '%s' "${DEV_CODE:-}" | tr -d '[:space:]')"
if [ -z "$DC" ] && [ -f "$(dirname "$0")/../dev-code.txt" ]; then
  DC="$(grep -vE '^\s*#' "$(dirname "$0")/../dev-code.txt" | tr -d '[:space:]' | head -c 200)"
fi
if [ -n "$DC" ] && ! printf '%s' "$DC" | grep -qE "$RE"; then
  echo "Код подключения задан, но в неверном формате — режим «Через разработчика» не будет включён" >&2
  DC=""
fi
printf '%s' "$DC"
