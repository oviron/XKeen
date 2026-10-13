#!/bin/sh
# Преполёт перед перезапуском: proxy_preflight и ветка restart менеджера команд
# в 04_register_init.sh.
#
# Баг, ради которого написан: ветка restart выполняла proxy_stop до proxy_start,
# а валидаторы конфигурации живут в начале proxy_start и завершают процесс через
# log_error_terminal. Опечатка в xkeen.json оставляла роутер без прокси (killall)
# и без правил (clean_firewall), хотя до команды всё работало.
#
# Модуль целиком не подключаем (на верхнем уровне он ходит curl в RCI роутера):
# берём ровно проверяемые функции из реального файла, тест бьёт по реальному коду.
# Ветка case тоже берётся из файла, а не переписывается.

SRC=/repo/scripts/_xkeen/02_install/07_install_register/04_register_init.sh

extract() { awk "/^${1}\\(\\) \\{/,/^\\}/" "$SRC"; }

pass=0; fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf 'OK   %s\n' "$1"; pass=$((pass+1))
    else
        printf 'FAIL %s\n       ожидалось [%s]\n       получено  [%s]\n' "$1" "$3" "$2"; fail=$((fail+1))
    fi
}
contains() {
    case "$2" in
        *"$3"*) printf 'OK   %s\n' "$1"; pass=$((pass+1)) ;;
        *) printf 'FAIL %s\n       в выводе нет [%s]\n       вывод     [%s]\n' "$1" "$3" "$2"; fail=$((fail+1)) ;;
    esac
}

eval "$(extract proxy_preflight)"
eval "$(extract validate_xkeen_json)"
eval "$(extract check_policy_name_conflict)"
eval "$(extract check_xray_backups)"
eval "$(extract info_health_binary)"
eval "$(extract check_binary)"
eval "$(extract strip_json_comments)"
eval "$(extract _xkeen_cached_json)"
# Однострочные функции логирования: тело в одну строку, awk-диапазон их не берёт.
eval "$(grep -E '^log_(error|warning|info)_(terminal|router)\(\) \{' "$SRC")"

green=""; red=""; yellow=""; light_blue=""; reset=""
missing_files_template='%b'
name_policy="xkeen"
name_policy_full="xkeen_full"
start_auto="on"

# Системный журнал подменяем файлом: logger в контейнере некуда писать,
# а проверять надо именно то, какая проверка не прошла.
log_error_router() { printf 'router:%s\n' "$1" >> "$calls"; }

workdir=$(mktemp -d)
install_dir="$workdir/sbin"
directory_xray_config="$workdir/configs"
xkeen_config="$workdir/xkeen.json"
calls="$workdir/calls"
mkdir -p "$install_dir" "$directory_xray_config"
PATH="$install_dir:$PATH"

make_core() {
    printf '#!/bin/sh\nexit %s\n' "$2" > "$install_dir/$1"
    chmod +x "$install_dir/$1"
}
make_core xray 0
make_core mihomo 0
make_core yq 0

reset_state() {
    name_client="xray"
    : > "$calls"
    printf '{ "xkeen": { "policy": [ { "name": "work" } ] } }\n' > "$xkeen_config"
    rm -f "$directory_xray_config"/*.json 2>/dev/null
    make_core xray 0
    # Кэш xkeen.json прогревается в файле барным вызовом (строка ~215):
    # без сброса следующий сценарий читал бы предыдущий конфиг.
    _xkeen_json_cache_set=0
    _xkeen_json_cache=""
}

# $1 - аргумент preflight. Возвращает вывод, код в $rc, вызовы в $calls.
run_preflight() {
    out=$( (proxy_preflight "$1") 2>&1 )
    rc=$?
}

# =========================================================================
# Исправная конфигурация: преполёт молчит и пропускает дальше
# =========================================================================
reset_state
run_preflight on
check "исправная конфигурация: rc=0" "$rc" '0'
check "исправная конфигурация: вывода нет" "$out" ''
check "исправная конфигурация: в журнал не пишем" "$(cat "$calls")" ''

# =========================================================================
# Каждая из четырёх проверок останавливает перезапуск и называет причину
# =========================================================================
reset_state
printf '{ "xkeen": { "policy": [ { "name": \n' > "$xkeen_config"
run_preflight on
check "битый xkeen.json: rc=1" "$rc" '1'
contains "битый xkeen.json: причина в журнале" "$(cat "$calls")" "не пройдена проверка 'xkeen.json'"
contains "битый xkeen.json: сказано, что состояние не изменено" "$out" 'состояние прокси-клиента не изменено'
contains "битый xkeen.json: сообщение валидатора видно" "$out" 'синтаксические ошибки'

reset_state
printf '{ "xkeen": { "policy": [ { "name": "xkeen" } ] } }\n' > "$xkeen_config"
run_preflight on
check "зарезервированное имя политики: rc=1" "$rc" '1'
contains "зарезервированное имя политики: причина в журнале" "$(cat "$calls")" "не пройдена проверка 'имена политик в xkeen.json'"

reset_state
: > "$directory_xray_config/05_routing_bak.json"
run_preflight on
check "резервная копия в каталоге Xray: rc=1" "$rc" '1'
contains "резервная копия в каталоге Xray: причина в журнале" "$(cat "$calls")" "не пройдена проверка 'резервные копии"

reset_state
make_core xray 139
run_preflight on
check "ядро не запускается: rc=1" "$rc" '1'
contains "ядро не запускается: причина в журнале" "$(cat "$calls")" "не пройдена проверка 'бинарные файлы"

# =========================================================================
# Преполёт не строже самого запуска: при start_manual не on и start_auto off
# proxy_start валидаторов не зовёт (условие на строке с start_manual), значит
# и преполёт обязан молчать, иначе он отклонит то, что запуск принял бы.
# =========================================================================
reset_state
printf '{ "xkeen": { "policy": [ { "name": \n' > "$xkeen_config"
start_auto="off"
run_preflight ""
check "start_auto=off и аргумент не on: битый конфиг пропускается" "$rc" '0'
check "start_auto=off и аргумент не on: в журнал не пишем" "$(cat "$calls")" ''
start_auto="on"
run_preflight ""
check "start_auto=on: битый конфиг останавливает перезапуск и без аргумента" "$rc" '1'

# =========================================================================
# Ветка restart берётся из файла: преполёт обязан стоять до proxy_stop
# =========================================================================
branch=$(grep -E '^    restart\)' "$SRC")
contains "ветка restart из файла содержит преполёт" "$branch" 'proxy_preflight'
check "в ветке restart преполёт раньше остановки" \
    "$(printf '%s' "$branch" | awk '{ print (index($0,"proxy_preflight") < index($0,"proxy_stop")) ? "да" : "нет" }')" 'да'

proxy_stop() { printf 'stop\n' >> "$calls"; }
proxy_start() { printf 'start\n' >> "$calls"; }
run_branch() {
    _cmd_rc=0
    ( eval "case \"restart\" in
$branch
    esac" ) >/dev/null 2>&1
    return $?
}

reset_state
run_branch
check "исправная конфигурация: остановка и запуск выполняются" "$(tr '\n' ' ' < "$calls")" 'stop start '

reset_state
printf '{ "xkeen": { "policy": [ { "name": \n' > "$xkeen_config"
run_branch
check "битый конфиг: остановки не было, прокси остался жить" "$(grep -c '^stop$' "$calls")" '0'
check "битый конфиг: запуска не было" "$(grep -c '^start$' "$calls")" '0'

rm -rf "$workdir"

printf '\n=== пройдено: %s, провалено: %s ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
