#!/bin/sh
# Тесты проверки перехвата трафика (scripts/_xkeen/05_tests/04_tests_intercept.sh)
#
# Проверяется то, ради чего команда написана: вердикт обязан отличать живой
# перехват от снесённых правил, и обязан молчать там, где пусто штатно
# (таблица nat в режиме TProxy, IPv6 без аплинка, aghfix без меток политик).
#
# Фикстура хука пишется НАСТОЯЩЕЙ inject_var из 04_register_init.sh, чтобы
# формат запекания в тесте и в бою не разошёлся.

repo=/repo
module="$repo/scripts/_xkeen/05_tests/04_tests_intercept.sh"
init="$repo/scripts/_xkeen/02_install/07_install_register/04_register_init.sh"

TD=$(mktemp -d)
trap 'rm -rf "$TD"' EXIT

pass=0; fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf 'OK   %s\n' "$1"; pass=$((pass+1))
    else
        printf 'FAIL %s\n       ожидалось [%s]\n       получено  [%s]\n' "$1" "$3" "$2"; fail=$((fail+1))
    fi
}
has()   { case "$2" in *"$3"*) check "$1" "да" "да" ;; *) check "$1" "нет: [$2]" "да" ;; esac; }
hasnt() { case "$2" in *"$3"*) check "$1" "найдено: [$3]" "не найдено" ;; *) check "$1" "не найдено" "не найдено" ;; esac; }

# ---------------------------------------------------------------- окружение
. "$module"

eval "$(awk '/^    inject_var\(\) \{/,/^    \}/' "$init")"
check "inject_var извлечена из 04_register_init.sh" "$(command -v inject_var >/dev/null && echo да || echo нет)" "да"

green=; red=; yellow=; light_blue=; italic=; reset=
file_netfilter_hook="$TD/proxy.sh"
initd_file="$TD/S05xkeen"
tmp_ram="$TD/rundir/work.$$"
mkdir -p "$TD/rundir" "$TD/ipt" "$TD/ip"

sleep() { :; }                       # повтор проверки не должен тормозить тест
pidof() { case " $FAKE_PIDS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
netstat() { cat "$TD/netstat" 2>/dev/null; }
curl_api() { cat "$TD/rci" 2>/dev/null; }

_fake_ipt() {
    _b=$1; shift
    _t=; _c=; _mode=S
    while [ $# -gt 0 ]; do
        case "$1" in
            -t)  _t=$2; shift 2 ;;
            -S)  _c=$2; _mode=S; shift 2 ;;
            -nL) _c=$2; _mode=L; shift 2 ;;
            *)   shift ;;
        esac
    done
    [ -f "$TD/ipt/$_b.$_t.$_c" ] || return 1
    [ "$_mode" = "L" ] && return 0
    cat "$TD/ipt/$_b.$_t.$_c"
}
iptables()  { _fake_ipt iptables "$@"; }
ip6tables() { _fake_ipt ip6tables "$@"; }
ip() {
    _fam=$1
    case "$_fam" in -4|-6) shift ;; *) _fam=-4 ;; esac
    case "$1" in
        rule)  cat "$TD/ip/rule$_fam"  2>/dev/null ;;
        route)
            shift
            case "$*" in
                *"table 111"*) cat "$TD/ip/table111$_fam" 2>/dev/null ;;
                *"table "*)    cat "$TD/ip/tablepolicy$_fam" 2>/dev/null ;;
                *)             cat "$TD/ip/default$_fam" 2>/dev/null ;;
            esac
            ;;
    esac
    return 0
}

# Здоровое состояние TProxy: ядро слушает 1181, цепочка mangle с правилами,
# переход из PREROUTING, маршруты на месте, метка политики совпадает.
reset_state() {
    rm -rf "$TD/ipt" "$TD/ip" "$TD/rundir"
    mkdir -p "$TD/ipt" "$TD/ip" "$TD/rundir"
    : > "$TD/rundir/ready"
    FAKE_PIDS="xray"

    printf 'tcp 0 0 0.0.0.0:1181 0.0.0.0:* LISTEN 777/xray\n' > "$TD/netstat"
    printf -- '-N xkeen\n-A xkeen -j TPROXY --on-port 1181\n' > "$TD/ipt/iptables.mangle.xkeen"
    printf -- '-A PREROUTING -m set --match-set xkeen_deny src -m comment --comment xkeen_rule -j RETURN\n-A PREROUTING -m connmark --mark 0xffffd00 -m comment --comment xkeen_rule -j xkeen\n' \
        > "$TD/ipt/iptables.mangle.PREROUTING"
    printf 'from all fwmark 0x111 lookup 111\n' > "$TD/ip/rule-4"
    printf 'local default dev lo scope host\n'  > "$TD/ip/table111-4"
    printf 'default via 192.168.0.1 dev eth3\n' > "$TD/ip/default-4"
    printf '{"Policy0":{"description":"xkeen","mark":"ffffd00"}}\n' > "$TD/rci"

    printf "name_chain='xkeen'\nname_policy='xkeen'\nname_policy_full='xkeen_full'\n" > "$initd_file"

    write_hook TProxy
}

# Фикстура хука: пролог, настоящая inject_var, многострочный user_policies
# с враждебной строкой-двойником и restart_script в хвосте.
write_hook() {
    _wh_mode=$1
    : > "$file_netfilter_hook"
    {
        echo '#!/bin/sh'
        echo 'PATH="/opt/bin:/opt/sbin:/sbin:/bin:/usr/sbin:/usr/bin"'
        echo '_xkeen_rundir=$(_xkeen_secure_rundir) || exit 1'
    } >> "$file_netfilter_hook"

    inject_var name_client  "${HK_CLIENT:-xray}"
    inject_var mode_proxy   "$_wh_mode"
    inject_var name_chain   "xkeen"
    inject_var comment_tag  "xkeen_rule"
    case "$_wh_mode" in
        TProxy)   inject_var port_redirect ""     ; inject_var port_tproxy "1181" ;;
        Redirect) inject_var port_redirect "1082" ; inject_var port_tproxy ""     ;;
        Hybrid)   inject_var port_redirect "1082" ; inject_var port_tproxy "1181" ;;
        Other)    inject_var port_redirect ""     ; inject_var port_tproxy ""     ;;
    esac
    inject_var policy_mark "${HK_MARK-0xffffd00}"
    inject_var policy_mark_full ""
    inject_var custom_mark "${HK_CUSTOM:-}"
    # Секрет и многострочное значение идут ДО табличных переменных — ровно
    # как в configure_firewall (rci_token 2238, user_policies 2212).
    inject_var rci_token "s3cr3t-tok'en"
    inject_var user_policies "${HK_UP-home|ffffd01|all|
table_id='999'
iptables_supported='false'
work|ffffd02|exclude|80,443}"
    inject_var table_redirect "nat"
    inject_var table_tproxy   "mangle"
    inject_var table_mark     "0x111"
    inject_var table_id       "111"
    inject_var file_dns       "false"
    inject_var proxy_dns      "off"
    inject_var proxy_router   "${HK_PR:-off}"
    inject_var iptables_supported  "${HK_IP4:-true}"
    inject_var ip6tables_supported "${HK_IP6:-false}"
    inject_var aghfix "${HK_AGH:-off}"
    {
        echo 'restart_script() {'
        echo "    name_chain='подмена_после_restart_script'"
        echo '}'
    } >> "$file_netfilter_hook"
}

run() { out=$(tests_intercept_check); rc=$?; }

# ------------------------------------------------------------------ парсер
HK_PR=off HK_IP6=false HK_AGH=off; reset_state
_ci_rundir="${tmp_ram%/*}"
_ci_read_hook; parse_rc=$?
check "разбор хука удался"                 "$parse_rc"          "0"
check "name_chain прочитан"                "$h_name_chain"      "xkeen"
check "comment_tag прочитан"               "$h_comment_tag"     "xkeen_rule"
check "port_tproxy прочитан"               "$h_port_tproxy"     "1181"
check "table_mark прочитан"                "$h_table_mark"      "0x111"
check "table_id не подменён двойником"     "$h_table_id"        "111"
check "iptables_supported не подменён"     "$h_iptables_supported" "true"
check "строки после restart_script не читаются" "$h_name_chain" "xkeen"
check "многострочное значение не ломает разбор" "$h_mode_proxy" "TProxy"
check "непустой user_policies замечен"     "$h_user_policies"   "yes"

# --------------------------------------------------------- здоровое дерево
reset_state; run
check "здоровый TProxy: rc"                "$rc" "0"
hasnt "здоровый TProxy: нет слова сбой"    "$out" "сбой"
has   "здоровый TProxy: порт"              "$out" "слушает порт 1181"
has   "здоровый TProxy: цепочка"           "$out" "IPv4 mangle: цепочка xkeen"
has   "здоровый TProxy: маршруты"          "$out" "IPv4 маршруты: fwmark 0x111"
has   "здоровый TProxy: метка политики"    "$out" "метка политики 'xkeen' совпадает"
hasnt "здоровый TProxy: nat не проверяется" "$out" "IPv4 nat"
hasnt "секрет из хука не попадает в вывод" "$out" "s3cr3t"

# ------------------------------------------------------------------- сбои
reset_state; printf -- '-N xkeen\n' > "$TD/ipt/iptables.mangle.xkeen"; run
check "цепочка пуста: rc"                  "$rc" "1"
has   "цепочка пуста: причина"             "$out" "цепочка xkeen пуста или отсутствует"

reset_state; rm -f "$TD/ipt/iptables.mangle.xkeen"; run
check "цепочки нет: rc"                    "$rc" "1"
has   "цепочки нет: причина"               "$out" "цепочка xkeen пуста или отсутствует"

reset_state; : > "$TD/ipt/iptables.mangle.PREROUTING"; run
check "нет перехода из PREROUTING: rc"     "$rc" "1"
has   "нет перехода из PREROUTING"         "$out" "из PREROUTING нет перехода"

# Один MAC-bypass RETURN несёт тот же комментарий, что и настоящий переход:
# проверка по комментарию дала бы зелёный на снесённом перехвате.
reset_state
printf -- '-A PREROUTING -m set --match-set xkeen_deny src -m comment --comment xkeen_rule -j RETURN\n' \
    > "$TD/ipt/iptables.mangle.PREROUTING"
run
check "только RETURN с нашим комментарием: rc" "$rc" "1"
has   "только RETURN с нашим комментарием"     "$out" "из PREROUTING нет перехода"

# Переход в цепочку принудительного проксирования тоже считается переходом.
reset_state
printf -- '-A PREROUTING -m connmark --mark 0xffffd01 -m comment --comment xkeen_rule -j xkeen_force\n' \
    > "$TD/ipt/iptables.mangle.PREROUTING"
run
check "переход в xkeen_force засчитан"     "$rc" "0"

HK_PR=on; reset_state; run
check "proxy_router=on без OUTPUT: rc"     "$rc" "1"
has   "proxy_router=on без OUTPUT"         "$out" "из OUTPUT нет перехода"
printf -- '-A OUTPUT -m comment --comment xkeen_rule -j xkeen\n' > "$TD/ipt/iptables.mangle.OUTPUT"; run
check "proxy_router=on c OUTPUT: rc"       "$rc" "0"
HK_PR=off

reset_state; : > "$TD/netstat"; run
check "порт не слушается: rc"              "$rc" "1"
has   "порт не слушается: причина"         "$out" "не слушает порт 1181"

# Без ready хук выходит первой строкой: правила после события NDM не вернутся.
reset_state; rm -f "$TD/rundir/ready"; run
check "нет флага ready: rc"                "$rc" "1"
has   "нет флага ready: причина"           "$out" "флага ready нет"

# ---------------------------------------------------------------- маршруты
reset_state; rm -f "$TD/ip/rule-4"; run
check "нет ip rule при живом аплинке: rc"  "$rc" "1"
has   "нет ip rule при живом аплинке"      "$out" "нет правила fwmark 0x111"

reset_state; rm -f "$TD/ip/rule-4" "$TD/ip/default-4"; run
check "нет ip rule без маршрута по умолчанию: rc" "$rc" "0"
has   "нет ip rule без маршрута по умолчанию"     "$out" "нет маршрута IPv4 по умолчанию"

# Политика на v4-only подключении: в её таблице нет IPv6-маршрута, и
# configure_route штатно не создаёт правило fwmark для IPv6.
HK_IP6=true; reset_state
cp "$TD/ipt/iptables.mangle.xkeen"      "$TD/ipt/ip6tables.mangle.xkeen"
cp "$TD/ipt/iptables.mangle.PREROUTING" "$TD/ipt/ip6tables.mangle.PREROUTING"
printf 'from all fwmark 0xffffd00 lookup 42\n' > "$TD/ip/rule-4"
printf 'from all fwmark 0x111 lookup 111\n'   >> "$TD/ip/rule-4"
printf 'default via fe80::1 dev eth3\n' > "$TD/ip/default-6"
: > "$TD/ip/tablepolicy-6"
run
check "IPv6 без маршрута в таблице политики: rc" "$rc" "0"
has   "IPv6 без маршрута в таблице политики"     "$out" "нет маршрута IPv6 по умолчанию"
HK_IP6=false

reset_state; printf 'unreachable default\n' > "$TD/ip/table111-4"; run
check "нет local default dev lo: rc"       "$rc" "1"
has   "нет local default dev lo"           "$out" "нет local default dev lo"

# ------------------------------------------------------------ режимы и IPv6
HK_IP6=true; reset_state
cp "$TD/ipt/iptables.mangle.xkeen"      "$TD/ipt/ip6tables.mangle.xkeen"
cp "$TD/ipt/iptables.mangle.PREROUTING" "$TD/ipt/ip6tables.mangle.PREROUTING"
cp "$TD/ip/rule-4" "$TD/ip/rule-6"; cp "$TD/ip/table111-4" "$TD/ip/table111-6"
cp "$TD/ip/default-4" "$TD/ip/default-6"; run
check "IPv6 включён и цел: rc"             "$rc" "0"
has   "IPv6 проверяется"                   "$out" "IPv6 mangle: цепочка xkeen"
rm -f "$TD/ipt/ip6tables.mangle.xkeen"; run
check "IPv6 цепочка снесена: rc"           "$rc" "1"
HK_IP6=false

# Ни одно семейство не поддерживается: пустой зелёный вердикт был бы ложью.
HK_IP4=false HK_IP6=false; reset_state; run
check "нет поддерживаемых семейств: rc"    "$rc" "0"
has   "нет поддерживаемых семейств"        "$out" "ни IPv4, ни IPv6"
HK_IP4=true

reset_state; write_hook Hybrid
printf -- '-N xkeen\n-A xkeen -j REDIRECT --to-ports 1082\n' > "$TD/ipt/iptables.nat.xkeen"
printf -- '-A PREROUTING -m comment --comment xkeen_rule -j xkeen\n' > "$TD/ipt/iptables.nat.PREROUTING"
printf 'tcp 0 0 0.0.0.0:1181 0.0.0.0:* LISTEN 777/xray\ntcp 0 0 0.0.0.0:1082 0.0.0.0:* LISTEN 777/xray\n' > "$TD/netstat"
run
check "Hybrid: rc"                         "$rc" "0"
has   "Hybrid: проверена nat"              "$out" "IPv4 nat: цепочка xkeen"
has   "Hybrid: проверена mangle"           "$out" "IPv4 mangle: цепочка xkeen"

reset_state; write_hook Redirect
printf -- '-N xkeen\n-A xkeen -j REDIRECT --to-ports 1082\n' > "$TD/ipt/iptables.nat.xkeen"
printf -- '-A PREROUTING -m comment --comment xkeen_rule -j xkeen\n' > "$TD/ipt/iptables.nat.PREROUTING"
printf 'tcp 0 0 0.0.0.0:1082 0.0.0.0:* LISTEN 777/xray\n' > "$TD/netstat"
rm -f "$TD/ip/rule-4"
run
check "Redirect: маршруты не проверяются"  "$rc" "0"
hasnt "Redirect: нет строки о маршрутах"   "$out" "IPv4 маршруты"

reset_state; write_hook Other; run
check "Other: rc"                          "$rc" "0"
has   "Other: перехват не используется"    "$out" "прозрачный перехват не используется"

# ------------------------------------------------------------------ aghfix
HK_AGH=on; reset_state; run
check "aghfix=on без правил DNS: rc"       "$rc" "0"
has   "aghfix=on без правил DNS"           "$out" "_NDM_HOTSPOT_DNSREDIR"
printf -- '-A _NDM_HOTSPOT_DNSREDIR -m comment --comment xkeen_rule -j REDIRECT\n' \
    > "$TD/ipt/iptables.nat._NDM_HOTSPOT_DNSREDIR"
run
check "aghfix=on c правилами DNS: rc"      "$rc" "0"
hasnt "aghfix=on c правилами DNS: без жалоб" "$out" "нет правил XKeen"

# Без единой метки dns_redir ничего не ставит: требовать правила нельзя.
HK_AGH=on HK_MARK= HK_UP= HK_CUSTOM=; reset_state
printf -- '-A PREROUTING -m comment --comment xkeen_rule -j xkeen\n' > "$TD/ipt/iptables.mangle.PREROUTING"
run
check "aghfix=on без меток политик: rc"    "$rc" "0"
hasnt "aghfix=on без меток политик: молчит" "$out" "_NDM_HOTSPOT_DNSREDIR"
unset HK_MARK HK_UP HK_CUSTOM; HK_AGH=off

# ----------------------------------------------------------------- политика
reset_state; printf '{"Policy0":{"description":"other","mark":"ffffd09"}}\n' > "$TD/rci"; run
check "политика удалена: rc"               "$rc" "1"
has   "политика удалена"                   "$out" "в роутере нет"

# Чужая политика с другой меткой не должна засчитываться за свою.
reset_state; printf '{"Policy0":{"description":"other","mark":"ffffd00"},"Policy1":{"description":"xkeen","mark":"ffffd55"}}\n' > "$TD/rci"; run
check "метка политики сменилась: rc"       "$rc" "1"
has   "метка политики сменилась"           "$out" "сменилась"

reset_state; : > "$TD/rci"; run
check "RCI молчит: rc не меняется"         "$rc" "0"
has   "RCI молчит: предупреждение"         "$out" "метки не проверены"

# -------------------------------------------------- хук пуст, замки, ядро
reset_state; : > "$file_netfilter_hook"; rm -rf "$TD/ipt"; mkdir -p "$TD/ipt"; run
check "пустой хук, ядро живо, ready есть: rc" "$rc" "0"
has   "пустой хук, ядро живо, ready есть"     "$out" "Режим Other"

# Хук затёрли, а правила остались: перехват снимется первой пересборкой NDM.
reset_state; : > "$file_netfilter_hook"; run
check "пустой хук при живых правилах: rc"  "$rc" "1"
has   "пустой хук при живых правилах"      "$out" "netfilter-хук пуст"

reset_state; : > "$file_netfilter_hook"; rm -rf "$TD/ipt"; mkdir -p "$TD/ipt"
rm -f "$TD/rundir/ready"; run
check "пустой хук без ready: rc"           "$rc" "1"
has   "пустой хук без ready"               "$out" "запуск не завершён"

reset_state; : > "$file_netfilter_hook"; FAKE_PIDS=""; run
check "пустой хук и ядро мертво: rc"       "$rc" "1"
has   "пустой хук и ядро мертво"           "$out" "не запущен"

reset_state; FAKE_PIDS=""; run
check "ядро мертво при живом хуке: rc"     "$rc" "1"
has   "ядро мертво при живом хуке"         "$out" "не запущено, netfilter-хук остался"

reset_state; mkdir -p "$TD/rundir/proxy.mutex.d"; echo $$ > "$TD/rundir/proxy.mutex.d/pid"; run
check "идёт запуск или остановка: rc"      "$rc" "2"
has   "идёт запуск или остановка"          "$out" "повторите проверку"

reset_state; mkdir -p "$TD/rundir/starting.lock.d"; echo $$ > "$TD/rundir/starting.lock.d/pid"; run
check "замок starting.lock.d учтён: rc"    "$rc" "2"

reset_state; mkdir -p "$TD/rundir/proxy.mutex.d"; echo 999999 > "$TD/rundir/proxy.mutex.d/pid"; run
check "мёртвый замок не глушит проверку"   "$rc" "0"

# -------------------------------- сверка предиката с самим хуком (анти-дрейф)
# _ci_chains_probe обязан давать тот же вердикт, что _xkeen_family_intact,
# везде кроме одного намеренного расхождения: наша проверка требует перехода
# именно в $name_chain, а хуку довольно любого правила с комментарием.
eval "$(awk '/^    _xkeen_family_intact\(\) \{/,/^    \}/' "$init")"
check "_xkeen_family_intact извлечена" "$(command -v _xkeen_family_intact >/dev/null && echo да || echo нет)" "да"
name_chain=xkeen; comment_tag=xkeen_rule; proxy_router=off; aghfix=off
file_dns=false; proxy_dns=off; _xkeen_hook_tables=mangle

for state in полный пустая_цепочка нет_цепочки нет_PREROUTING; do
    reset_state
    case "$state" in
        пустая_цепочка) printf -- '-N xkeen\n' > "$TD/ipt/iptables.mangle.xkeen" ;;
        нет_цепочки)    rm -f "$TD/ipt/iptables.mangle.xkeen" ;;
        нет_PREROUTING) : > "$TD/ipt/iptables.mangle.PREROUTING" ;;
    esac
    _xkeen_family_intact iptables && hook=цел || hook=порвано
    _ci_chains_probe iptables mangle
    [ -z "$_ci_why" ] && mine=цел || mine=порвано
    check "сверка с предикатом хука: $state" "$mine" "$hook"
done

reset_state
printf -- '-A PREROUTING -m set --match-set xkeen_deny src -m comment --comment xkeen_rule -j RETURN\n' \
    > "$TD/ipt/iptables.mangle.PREROUTING"
_xkeen_family_intact iptables && hook=цел || hook=порвано
_ci_chains_probe iptables mangle
[ -z "$_ci_why" ] && mine=цел || mine=порвано
check "намеренно строже хука: только RETURN, хук" "$hook" "цел"
check "намеренно строже хука: только RETURN, мы"  "$mine" "порвано"

printf '\n=== пройдено: %s, провалено: %s ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
