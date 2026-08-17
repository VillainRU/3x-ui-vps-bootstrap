#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_NAME="3x-ui-vps-bootstrap"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly SSHD_DROPIN="${SSHD_DROPIN_DIR}/00-3x-ui-vps-hardening.conf"
readonly SSH_SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
readonly SSH_SOCKET_DROPIN="${SSH_SOCKET_DROPIN_DIR}/00-3x-ui-vps-hardening.conf"
readonly XUI_INSTALLER_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh"
readonly XUI_BINARY="/usr/local/x-ui/x-ui"
readonly RESULT_FILE="/root/3x-ui-vps-install-result.env"

NEW_USER=""
NEW_USER_PASSWORD=""
USER_WAS_EXISTING=0
USER_HOME=""
PUBLIC_KEY=""
SSH_PORT=""
PANEL_PORT=""
PANEL_USER=""
PANEL_PASSWORD=""
READ_PASSWORD_RESULT=""
SERVER_IP=""
WEB_BASE_PATH=""
BACKUP_DIR=""
XUI_LOG=""
SOCKET_MODE=0
SSH_FILES_CREATED=0
SSH_SERVICE_RESTARTED=0
UFW_RULE_ADDED=0
FIREWALLD_RULE_ADDED=0
COMPLETED=0

cleanup_sensitive() {
    unset NEW_USER_PASSWORD PANEL_PASSWORD READ_PASSWORD_RESULT PUBLIC_KEY
}

rollback_ssh() {
    local rollback_rc=0

    if (( SSH_FILES_CREATED == 0 )); then
        return 0
    fi

    printf '\n[!] Откатываю только изменения SSH, сделанные этим запуском...\n' >&2
    set +e
    rm -f -- "$SSHD_DROPIN" "$SSH_SOCKET_DROPIN"
    systemctl daemon-reload >/dev/null 2>&1

    if (( SSH_SERVICE_RESTARTED == 1 )); then
        if (( SOCKET_MODE == 1 )); then
            systemctl restart ssh.socket >/dev/null 2>&1 || rollback_rc=1
        else
            systemctl restart ssh.service >/dev/null 2>&1 || rollback_rc=1
        fi
    fi

    if (( UFW_RULE_ADDED == 1 )) && command -v ufw >/dev/null 2>&1; then
        ufw delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || rollback_rc=1
    fi

    if (( FIREWALLD_RULE_ADDED == 1 )) && command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${SSH_PORT}/tcp" >/dev/null 2>&1 || rollback_rc=1
        firewall-cmd --reload >/dev/null 2>&1 || rollback_rc=1
    fi
    set -e

    if (( rollback_rc != 0 )); then
        printf '[!] Автоматический откат завершился с предупреждениями. Текущую SSH-сессию не закрывайте.\n' >&2
    else
        printf '[+] SSH-конфигурация возвращена к состоянию до изменения.\n' >&2
    fi
}

on_exit() {
    local rc=$?
    if (( rc != 0 && COMPLETED == 0 )); then
        rollback_ssh || true
        printf '[!] Установка завершилась с ошибкой. Созданный пользователь и уже установленная панель не удалялись автоматически.\n' >&2
    fi
    cleanup_sensitive
    exit "$rc"
}
trap on_exit EXIT

die() {
    printf '[!] %s\n' "$*" >&2
    exit 1
}

info() {
    printf '[i] %s\n' "$*"
}

ok() {
    printf '[+] %s\n' "$*"
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( 1 <= 10#$1 && 10#$1 <= 65535 ))
}

is_port_in_use() {
    local port="$1"
    ss -H -ltn 2>/dev/null | awk -v needle=":${port}" '$4 ~ (needle "$") { found=1 } END { exit !found }'
}

is_valid_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local octet
    IFS=. read -r -a octets <<< "$1"
    for octet in "${octets[@]}"; do
        (( 0 <= 10#$octet && 10#$octet <= 255 )) || return 1
    done
}

is_valid_linux_username() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && [[ "$1" != "root" ]]
}

is_valid_panel_username() {
    [[ "$1" =~ ^[A-Za-z0-9._-]{3,64}$ ]]
}

read_password_pair() {
    local label="$1"
    local first=""
    local second=""
    READ_PASSWORD_RESULT=""
    while true; do
        read -r -s -p "$label" first || die "Ввод пароля прерван."
        printf '\n' >&2
        read -r -s -p "Повторите пароль: " second || die "Ввод пароля прерван."
        printf '\n' >&2
        if [[ "$first" != "$second" ]]; then
            printf 'Пароли не совпадают, повторите ввод.\n' >&2
            continue
        fi
        if (( ${#first} < 12 )); then
            printf 'Используйте пароль длиной не менее 12 символов.\n' >&2
            continue
        fi
        READ_PASSWORD_RESULT="$first"
        return 0
    done
}

detect_public_ipv4() {
    local detected=""
    detected="$(curl -4fsS --max-time 5 https://api4.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
    if is_valid_ipv4 "$detected"; then
        printf '%s' "$detected"
        return 0
    fi

    detected="$(hostname -I 2>/dev/null | awk '($1 !~ /^127\./ && $1 !~ /:/ && $1 != "") { if (!found) { print $1; found=1 } }' || true)"
    is_valid_ipv4 "$detected" && printf '%s' "$detected"
}

get_effective_sshd_option() {
    local option="$1"
    sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null \
        | awk -v wanted="$option" '$1 == wanted && !found { print $2; found=1 }'
}

check_command() {
    command -v "$1" >/dev/null 2>&1 || die "Не найдена команда '$1'."
}

install_prerequisites() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
    else
        die "Не найден /etc/os-release."
    fi

    case "${ID:-}" in
        ubuntu|debian)
            info "Устанавливаю необходимые пакеты..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --no-install-recommends \
                ca-certificates curl iproute2 openssh-server openssl sudo
            ;;
        *)
            die "Поддерживаются Ubuntu и Debian. Обнаружена система: ${PRETTY_NAME:-unknown}."
            ;;
    esac

    for command_name in awk curl getent grep id install ip ss ssh-keygen sshd systemctl useradd; do
        check_command "$command_name"
    done
    for command_name in chpasswd usermod; do
        check_command "$command_name"
    done
}

collect_inputs() {
    printf '\n=== Создание пользователя и защита SSH ===\n'
    while true; do
        read -r -p "Имя Linux-пользователя: " NEW_USER || die "Ввод прерван."
        if ! is_valid_linux_username "$NEW_USER"; then
            printf 'Допустимы строчные латинские буквы, цифры, _, -, первый символ не цифра; root запрещён.\n' >&2
            continue
        fi
        if getent passwd "$NEW_USER" >/dev/null 2>&1; then
            USER_WAS_EXISTING=1
            printf 'Пользователь уже существует. Будет переиспользована эта учётная запись: пароль обновится, группа sudo будет добавлена, а ключ сохранится/добавится.\n' >&2
        else
            USER_WAS_EXISTING=0
        fi
        break
    done

    read_password_pair "Пароль для ${NEW_USER}: "
    NEW_USER_PASSWORD="$READ_PASSWORD_RESULT"

    printf '\nВставьте одну строку публичного SSH-ключа. Примеры получения:\n'
    printf '  Windows 10/11: PowerShell → Get-Content $env:USERPROFILE\\.ssh\\id_ed25519.pub\n'
    printf '  Linux/macOS:   cat ~/.ssh/id_ed25519.pub\n'
    printf '  Если ключа нет: ssh-keygen -t ed25519\n'
    while true; do
        read -r -p "Публичный ключ: " PUBLIC_KEY || die "Ввод прерван."
        [[ "$PUBLIC_KEY" != *$'\n'* ]] || { printf 'Нужна одна строка ключа.\n' >&2; continue; }
        local key_file
        key_file="$(mktemp)"
        chmod 600 "$key_file"
        printf '%s\n' "$PUBLIC_KEY" > "$key_file"
        if ssh-keygen -lf "$key_file" >/dev/null 2>&1; then
            rm -f -- "$key_file"
            break
        fi
        rm -f -- "$key_file"
        printf 'Строка не похожа на корректный публичный ключ OpenSSH.\n' >&2
    done

    while true; do
        read -r -p "Новый SSH-порт (1–65535, кроме 22): " SSH_PORT || die "Ввод прерван."
        if ! is_valid_port "$SSH_PORT" || (( SSH_PORT == 22 )); then
            printf 'Введите корректный порт 1–65535, отличный от 22.\n' >&2
            continue
        fi
        if is_port_in_use "$SSH_PORT"; then
            printf 'Порт уже занят локальным слушателем.\n' >&2
            continue
        fi
        break
    done

    while true; do
        read -r -p "Порт административной панели 3x-ui (1–65535): " PANEL_PORT || die "Ввод прерван."
        if ! is_valid_port "$PANEL_PORT"; then
            printf 'Введите корректный порт 1–65535.\n' >&2
            continue
        fi
        if (( PANEL_PORT == SSH_PORT )); then
            printf 'Порт панели должен отличаться от SSH-порта.\n' >&2
            continue
        fi
        if is_port_in_use "$PANEL_PORT"; then
            printf 'Порт уже занят локальным слушателем.\n' >&2
            continue
        fi
        break
    done

    while true; do
        read -r -p "Имя пользователя для входа в 3x-ui: " PANEL_USER || die "Ввод прерван."
        if is_valid_panel_username "$PANEL_USER"; then
            break
        fi
        printf 'Используйте 3–64 символа: латиница, цифры, точка, _, -.\n' >&2
    done
    read_password_pair "Пароль для 3x-ui: "
    PANEL_PASSWORD="$READ_PASSWORD_RESULT"

    SERVER_IP="$(detect_public_ipv4 || true)"
    while true; do
        if [[ -n "$SERVER_IP" ]]; then
            read -r -p "IPv4 сервера для генерируемых ссылок [${SERVER_IP}]: " entered_ip || die "Ввод прерван."
            SERVER_IP="${entered_ip:-$SERVER_IP}"
        else
            read -r -p "Публичный IPv4 сервера для генерируемых ссылок: " SERVER_IP || die "Ввод прерван."
        fi
        if is_valid_ipv4 "$SERVER_IP"; then
            break
        fi
        printf 'Введите корректный IPv4-адрес.\n' >&2
        SERVER_IP=""
    done

    WEB_BASE_PATH="$(openssl rand -hex 12)"
    [[ -n "$WEB_BASE_PATH" ]] || die "Не удалось сгенерировать путь панели."
}

create_linux_user() {
    local primary_group authorized_keys

    if (( USER_WAS_EXISTING == 1 )); then
        info "Использую существующего пользователя ${NEW_USER} и добавляю его в группу sudo..."
    else
        info "Создаю пользователя ${NEW_USER} и добавляю его в группу sudo..."
        useradd --create-home --shell /bin/bash "$NEW_USER"
    fi

    USER_HOME="$(getent passwd "$NEW_USER" | awk -F: 'NR == 1 { print $6 }')"
    [[ -n "$USER_HOME" && "$USER_HOME" != "/" ]] || die "Не удалось определить домашний каталог пользователя ${NEW_USER}."
    primary_group="$(id -gn "$NEW_USER")" || die "Не удалось определить основную группу пользователя ${NEW_USER}."

    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
    usermod --append --groups sudo "$NEW_USER"

    install -d -m 700 -o "$NEW_USER" -g "$primary_group" "$USER_HOME/.ssh"
    authorized_keys="$USER_HOME/.ssh/authorized_keys"
    [[ ! -L "$authorized_keys" ]] || die "Файл ${authorized_keys} является символической ссылкой; остановлено для безопасности."
    if [[ ! -e "$authorized_keys" ]]; then
        install -m 600 -o "$NEW_USER" -g "$primary_group" /dev/null "$authorized_keys"
    fi
    if (( USER_WAS_EXISTING == 1 )); then
        grep -Fqx -- "$PUBLIC_KEY" "$authorized_keys" || printf '%s\n' "$PUBLIC_KEY" >> "$authorized_keys"
    else
        printf '%s\n' "$PUBLIC_KEY" > "$authorized_keys"
    fi
    chown "$NEW_USER:$primary_group" "$authorized_keys"
    chmod 600 "$authorized_keys"

    if (( USER_WAS_EXISTING == 1 )); then
        ok "Существующий пользователь подготовлен; права superuser предоставлены через группу sudo, ключ сохранён/добавлен."
    else
        ok "Пользователь создан; права superuser предоставлены через группу sudo."
    fi
}

install_3x_ui() {
    [[ ! -e /usr/local/x-ui/x-ui ]] || die "Похоже, 3x-ui уже установлен. Скрипт не обновляет существующую установку."

    local installer_tmp
    installer_tmp="$(mktemp)"
    XUI_LOG="/var/log/3x-ui-vps-bootstrap-install.log"
    install -m 600 /dev/null "$XUI_LOG"
    info "Загружаю официальный установщик 3x-ui; подробный лог: ${XUI_LOG}"
    if ! curl -fL --retry 3 --connect-timeout 15 --max-time 120 "$XUI_INSTALLER_URL" -o "$installer_tmp"; then
        rm -f -- "$installer_tmp"
        die "Не удалось загрузить официальный установщик 3x-ui."
    fi
    [[ -s "$installer_tmp" ]] || { rm -f -- "$installer_tmp"; die "Официальный установщик пуст."; }
    chmod 700 "$installer_tmp"

    # Инсталлятор upstream работает без вопросов с этими переменными. TLS не
    # выпускаем: административная панель будет доступна только через SSH-туннель.
    if ! XUI_NONINTERACTIVE=1 \
        XUI_SSL_MODE=none \
        XUI_PANEL_PORT="$PANEL_PORT" \
        XUI_WEB_BASE_PATH="$WEB_BASE_PATH" \
        XUI_SERVER_IP="$SERVER_IP" \
        XUI_DB_TYPE=sqlite \
        bash "$installer_tmp" >"$XUI_LOG" 2>&1; then
        rm -f -- "$installer_tmp"
        tail -n 60 "$XUI_LOG" >&2 || true
        die "Официальный установщик 3x-ui завершился ошибкой."
    fi
    rm -f -- "$installer_tmp"
    [[ -x "$XUI_BINARY" ]] || die "После установки не найден ${XUI_BINARY}."

    info "Устанавливаю заданные учётные данные и привязываю панель к loopback..."
    if ! "$XUI_BINARY" setting \
        -username "$PANEL_USER" \
        -password "$PANEL_PASSWORD" \
        -port "$PANEL_PORT" \
        -webBasePath "$WEB_BASE_PATH" \
        -listenIP "127.0.0.1" >/dev/null 2>&1; then
        die "Не удалось применить настройки 3x-ui."
    fi
    systemctl restart x-ui
    systemctl is-active --quiet x-ui || die "Сервис x-ui не запустился. Проверьте ${XUI_LOG}."

    local settings
    settings="$($XUI_BINARY setting -show true 2>/dev/null || true)"
    grep -Eq "^port: ${PANEL_PORT}$" <<< "$settings" || die "Порт панели не прошёл проверку."
    grep -Eq '^listenIP: 127\.0\.0\.1$' <<< "$settings" || die "Привязка панели к 127.0.0.1 не прошла проверку."
    grep -Eq "^webBasePath: /?${WEB_BASE_PATH}$" <<< "$settings" || die "WebBasePath панели не прошёл проверку."
    if ! ss -H -ltn 2>/dev/null | awk -v needle="127.0.0.1:${PANEL_PORT}" '$4 == needle { found=1 } END { exit !found }'; then
        die "Порт панели ${PANEL_PORT} не слушается на 127.0.0.1."
    fi
    if ss -H -ltn 2>/dev/null | awk -v needle=":${PANEL_PORT}" '$4 ~ (needle "$") && $4 !~ /^127\.0\.0\.1:/ && $4 !~ /^\[::1\]:/ { found=1 } END { exit !found }'; then
        die "Панель обнаружена на внешнем интерфейсе."
    fi

    local xui_result="/etc/x-ui/install-result.env"
    local old_umask
    old_umask="$(umask)"
    umask 077
    {
        printf 'XUI_USERNAME=%q\n' "$PANEL_USER"
        printf 'XUI_PASSWORD=%q\n' "$PANEL_PASSWORD"
        printf 'XUI_PANEL_PORT=%q\n' "$PANEL_PORT"
        printf 'XUI_WEB_BASE_PATH=%q\n' "$WEB_BASE_PATH"
        printf 'XUI_ACCESS_URL=%q\n' "http://127.0.0.1:${PANEL_PORT}/${WEB_BASE_PATH}"
        printf 'XUI_LISTEN_IP=127.0.0.1\n'
    } > "$xui_result"
    chmod 600 "$xui_result"
    chown root:root "$xui_result"
    umask "$old_umask"
    ok "3x-ui установлена; административная панель слушает только 127.0.0.1:${PANEL_PORT}."
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | awk '$0 == "Status: active" { found=1 } END { exit !found }'; then
        if ! ufw status 2>/dev/null | awk -v needle="${SSH_PORT}/tcp" 'index($0, needle) { found=1 } END { exit !found }'; then
            ufw allow "${SSH_PORT}/tcp" >/dev/null
            UFW_RULE_ADDED=1
            info "В UFW добавлено разрешение для SSH-порта ${SSH_PORT}/tcp."
        fi
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        if ! firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | awk -v needle="${SSH_PORT}/tcp" '$0 == needle { found=1 } END { exit !found }'; then
            firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null
            firewall-cmd --reload >/dev/null
            FIREWALLD_RULE_ADDED=1
            info "В firewalld добавлено разрешение для SSH-порта ${SSH_PORT}/tcp."
        fi
    fi
}

prepare_ssh_files() {
    grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "$SSHD_CONFIG" \
        || die "В ${SSHD_CONFIG} нет стандартного Include для sshd_config.d; остановлено для безопасности."

    install -d -m 755 "$SSHD_DROPIN_DIR"
    if [[ -e "$SSHD_DROPIN" || -e "$SSH_SOCKET_DROPIN" ]]; then
        die "Файл конфигурации скрипта уже существует; сначала проверьте предыдущий запуск."
    fi

    BACKUP_DIR="/root/${SCRIPT_NAME}-backup-$(date +%Y%m%d-%H%M%S)"
    install -d -m 700 "$BACKUP_DIR"
    cp -a "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config"

    cat > "$SSHD_DROPIN" <<EOF
# Managed by ${SCRIPT_NAME}. Remove only after restoring the previous SSH policy.
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
EOF
    chmod 644 "$SSHD_DROPIN"

    if systemctl cat ssh.socket >/dev/null 2>&1 && \
        (systemctl is-active --quiet ssh.socket || systemctl is-enabled --quiet ssh.socket 2>/dev/null); then
        SOCKET_MODE=1
        install -d -m 755 "$SSH_SOCKET_DROPIN_DIR"
        cat > "$SSH_SOCKET_DROPIN" <<EOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
        chmod 644 "$SSH_SOCKET_DROPIN"
    fi
    SSH_FILES_CREATED=1
}

apply_ssh_hardening() {
    info "Проверяю новую SSH-конфигурацию до перезапуска службы..."
    sshd -t || die "sshd -t отклонил новую конфигурацию."

    local effective_port effective_root effective_password effective_keyboard
    effective_port="$(get_effective_sshd_option port)"
    effective_root="$(get_effective_sshd_option permitrootlogin)"
    effective_password="$(get_effective_sshd_option passwordauthentication)"
    effective_keyboard="$(get_effective_sshd_option kbdinteractiveauthentication)"
    [[ "$effective_port" == "$SSH_PORT" ]] || die "Эффективный SSH-порт остался ${effective_port:-неизвестно}, ожидался ${SSH_PORT}."
    [[ "$effective_root" == "no" ]] || die "PermitRootLogin не стал no."
    [[ "$effective_password" == "no" ]] || die "PasswordAuthentication не стал no."
    [[ "$effective_keyboard" == "no" ]] || die "KbdInteractiveAuthentication не стал no."

    configure_firewall
    systemctl daemon-reload
    if (( SOCKET_MODE == 1 )); then
        systemctl restart ssh.socket
    else
        systemctl restart ssh.service
    fi
    SSH_SERVICE_RESTARTED=1

    if ! ss -H -ltn 2>/dev/null | awk -v needle=":${SSH_PORT}" '$4 ~ (needle "$") { found=1 } END { exit !found }'; then
        die "После перезапуска SSH-порт ${SSH_PORT} не слушается."
    fi
    ok "SSH переключён на порт ${SSH_PORT}; root-вход и парольная аутентификация отключены."
}

save_result() {
    local old_umask
    old_umask="$(umask)"
    umask 077
    {
        printf 'SERVER_IP=%q\n' "$SERVER_IP"
        printf 'SSH_USER=%q\n' "$NEW_USER"
        printf 'SSH_PORT=%q\n' "$SSH_PORT"
        printf 'PANEL_USER=%q\n' "$PANEL_USER"
        printf 'PANEL_PASSWORD=%q\n' "$PANEL_PASSWORD"
        printf 'PANEL_PORT=%q\n' "$PANEL_PORT"
        printf 'PANEL_LISTEN_IP=127.0.0.1\n'
        printf 'PANEL_WEB_BASE_PATH=%q\n' "$WEB_BASE_PATH"
        printf 'SSH_BACKUP_DIR=%q\n' "$BACKUP_DIR"
    } > "$RESULT_FILE"
    chmod 600 "$RESULT_FILE"
    chown root:root "$RESULT_FILE"
    umask "$old_umask"
}

show_final_instructions() {
    local ssh_uri="ssh://${NEW_USER}@${SERVER_IP}:${SSH_PORT}"
    local tunnel_command="ssh -N -T -p ${SSH_PORT} -L 127.0.0.1:${PANEL_PORT}:127.0.0.1:${PANEL_PORT} ${NEW_USER}@${SERVER_IP}"
    local panel_url="http://127.0.0.1:${PANEL_PORT}/${WEB_BASE_PATH}"

    printf '\n=== Установка завершена ===\n'
    printf 'Проверочная SSH-ссылка:\n  %s\n' "$ssh_uri"
    printf '\nОткройте второй терминал и проверьте вход командой:\n  ssh -p %s %s@%s\n' "$SSH_PORT" "$NEW_USER" "$SERVER_IP"
    printf '\nВведите YES после успешного входа во второй SSH-сеанс: '
    local verification=""
    read -r verification || verification=""
    verification="${verification,,}"
    if [[ "$verification" != "yes" && "$verification" != "y" && "$verification" != "да" && "$verification" != "д" ]]; then
        die "Проверка второго SSH-сеанса не подтверждена."
    fi

    save_result
    printf '\nСсылка/команда для поднятия SSH-туннеля:\n  %s\n' "$tunnel_command"
    printf 'После запуска туннеля откройте панель здесь:\n  %s\n' "$panel_url"
    printf '\nУчётные данные 3x-ui:\n  Пользователь: %s\n  Пароль:       %s\n  Порт:         %s\n  WebBasePath:  /%s\n' \
        "$PANEL_USER" "$PANEL_PASSWORD" "$PANEL_PORT" "$WEB_BASE_PATH"
    printf '\nВажно: после создания подключения и получения ссылки вида vless://... замените в ней слово localhost на IP-адрес сервера (%s), если 3x-ui записал localhost.\n' "$SERVER_IP"
    printf 'Результат с правами 600 сохранён в: %s\n' "$RESULT_FILE"
    printf 'Резервная копия SSH-конфигурации: %s\n' "$BACKUP_DIR"
}

main() {
    (( EUID == 0 )) || die "Запустите скрипт от root: sudo bash <(curl -fsSL URL)."
    [[ -t 0 ]] || die "Нужен интерактивный SSH-терминал. Используйте bash <(curl -fsSL URL), а не curl URL | bash."

    printf '%s\n' "=== ${SCRIPT_NAME} ==="
    printf 'Скрипт рассчитан на чистый Ubuntu/Debian VPS. Текущую SSH-сессию не закрывайте до конца проверки.\n\n'
    install_prerequisites
    collect_inputs
    create_linux_user
    install_3x_ui
    prepare_ssh_files
    apply_ssh_hardening
    show_final_instructions
    COMPLETED=1
    ok "Готово."
}

main "$@"
