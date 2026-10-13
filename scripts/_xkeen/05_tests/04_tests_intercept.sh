# Проверка прозрачного перехвата трафика (xkeen -check)
#
# Откуда берётся "как должно быть": из netfilter-хука. configure_firewall()
# (02_install/07_install_register/04_register_init.sh) запекает в хук все
# применённые значения строками name='value' (inject_var), поэтому хук —
# снимок того, что реально стоит в ядре. Пересчитывать значения из конфигов
# нельзя: конфиг могли поменять без перезапуска, и проверка оказалась бы о
# правилах, которых в iptables нет.
#
# Предикат цепочек близок к _xkeen_family_intact — функции самого хука (там
# же, внутри heredoc configure_firewall), но строже: переход из PREROUTING
# засчитывается только по цели $name_chain, а не по одному комментарию,
# который есть и у MAC-bypass RETURN. Правится синхронно с хуком,
# расхождение ловит spec/test_check_intercept.sh.
#
# Команда только читает состояние: ничего не чинит и не перезапускает.

# Строка вердикта: $1 ok|warn|fail|skip, $2 текст, $3 подсказка
_ci_line() {
    case "$1" in
        ok)   echo -e "  ${green}норма${reset}     $2" ;;
        warn) echo -e "  ${yellow}внимание${reset}  $2"; _ci_warn=$((_ci_warn + 1)) ;;
        skip) echo -e "  ${light_blue}пропуск${reset}   $2" ;;
        *)    echo -e "  ${red}сбой${reset}      $2"; _ci_fail=$((_ci_fail + 1)) ;;
    esac
    [ -z "$3" ] || echo -e "            ${italic}$3${reset}"
    return 0
}

# Идёт ли сейчас запуск, остановка или пересборка правил: при живом владельце
# любого из замков состояние заведомо промежуточное, проверять нечего.
_ci_busy() {
    [ -n "$_ci_rundir" ] || return 1
    for _ci_l in proxy.mutex.d coldstart.lock.d netfilter.lock.d starting.lock.d; do
        _ci_lpid=$(cat "$_ci_rundir/$_ci_l/pid" 2>/dev/null)
        [ -n "$_ci_lpid" ] && kill -0 "$_ci_lpid" 2>/dev/null && return 0
    done
    return 1
}

# Значение переменной из файла автозапуска. Нужно для того, что в хук не
# запекается: имена политик и name_chain при пустом хуке.
_ci_initd_var() {
    [ -s "$initd_file" ] || return 1
    sed -n "s/^$1=[\"']\([A-Za-z0-9_.:/-]*\)[\"']\$/\1/p" "$initd_file" | head -1
}

# Читает из хука только перечисленные имена в переменные h_*.
# Хук не исполняется и не eval-ится: awk отдаёт пары key=value, значение
# принимается только из безопасного алфавита, присваивание — явным case.
# rci_token в списке нет, в память он не попадает.
#
# Значение в хуке бывает многострочным (user_policies — список политик по
# строке на каждую), поэтому awk ведёт состояние одинарной кавычки и строки
# из середины чужого значения не разбирает: иначе имя политики с переводом
# строки могло бы подменить настоящее table_id.
_ci_read_hook() {
    h_name_client=""; h_mode_proxy=""; h_name_chain=""; h_comment_tag=""
    h_port_redirect=""; h_port_tproxy=""; h_table_redirect=""; h_table_tproxy=""
    h_table_id=""; h_table_mark=""; h_proxy_router=""; h_aghfix=""
    h_proxy_dns=""; h_file_dns=""; h_iptables_supported=""; h_ip6tables_supported=""
    h_policy_mark=""; h_policy_mark_full=""; h_custom_mark=""; h_user_policies=""

    [ -s "$file_netfilter_hook" ] || return 1

    # user_policies многострочный, безопасным алфавитом не описывается:
    # для проверок хватает факта, что он непуст.
    grep -q "^user_policies='[^']" "$file_netfilter_hook" 2>/dev/null && h_user_policies="yes"

    _ci_raw=$(awk -v keys=" name_client mode_proxy name_chain comment_tag port_redirect port_tproxy table_redirect table_tproxy table_id table_mark proxy_router aghfix proxy_dns file_dns iptables_supported ip6tables_supported policy_mark policy_mark_full custom_mark " '
        function scan(s, q,   i, c, n) {
            n = length(s)
            for (i = 1; i <= n; i++) {
                c = substr(s, i, 1)
                if (q) { if (c == "'\''") q = 0 }
                else if (c == "'\''") q = 1
                else if (c == "\\") i++
            }
            return q
        }
        /^restart_script\(\)/ { exit }
        cont { cont = scan($0, 1); next }
        /^[a-z_][a-z_0-9]*=/ {
            eq = index($0, "=")
            k = substr($0, 1, eq - 1)
            v = substr($0, eq + 1)
            if (scan(v, 0)) { cont = 1; next }
            if (index(keys, " " k " ") == 0 || (k in seen)) next
            if (v !~ /^'\''[A-Za-z0-9_.:\/-]*'\''$/) next
            seen[k] = 1
            print k "=" substr(v, 2, length(v) - 2)
        }
    ' "$file_netfilter_hook")

    while IFS='=' read -r _ci_k _ci_v; do
        case "$_ci_k" in
            name_client)         h_name_client=$_ci_v ;;
            mode_proxy)          h_mode_proxy=$_ci_v ;;
            name_chain)          h_name_chain=$_ci_v ;;
            comment_tag)         h_comment_tag=$_ci_v ;;
            port_redirect)       h_port_redirect=$_ci_v ;;
            port_tproxy)         h_port_tproxy=$_ci_v ;;
            table_redirect)      h_table_redirect=$_ci_v ;;
            table_tproxy)        h_table_tproxy=$_ci_v ;;
            table_id)            h_table_id=$_ci_v ;;
            table_mark)          h_table_mark=$_ci_v ;;
            proxy_router)        h_proxy_router=$_ci_v ;;
            aghfix)              h_aghfix=$_ci_v ;;
            proxy_dns)           h_proxy_dns=$_ci_v ;;
            file_dns)            h_file_dns=$_ci_v ;;
            iptables_supported)  h_iptables_supported=$_ci_v ;;
            ip6tables_supported) h_ip6tables_supported=$_ci_v ;;
            policy_mark)         h_policy_mark=$_ci_v ;;
            policy_mark_full)    h_policy_mark_full=$_ci_v ;;
            custom_mark)         h_custom_mark=$_ci_v ;;
        esac
    done <<EOF_HOOK
$_ci_raw
EOF_HOOK

    [ -n "$h_name_client" ] && [ -n "$h_name_chain" ] && [ -n "$h_comment_tag" ] && \
        [ -n "$h_table_id" ] && [ -n "$h_table_mark" ]
}

# Есть ли в ядре живые правила XKeen, когда хук прочитать не удалось.
# Имя цепочки берём из файла автозапуска: в пустом хуке его нет.
_ci_live_rules() {
    _ci_lr_chain=$(_ci_initd_var name_chain)
    [ -n "$_ci_lr_chain" ] || _ci_lr_chain="xkeen"
    for _ci_lr_t in mangle nat; do
        [ "$(iptables -w -t "$_ci_lr_t" -S "$_ci_lr_chain" 2>/dev/null | wc -l)" -gt 1 ] && return 0
    done
    return 1
}

# Один прогон предиката цепочек: $1 бинарь, $2 таблица -> $_ci_why ("" = норма)
_ci_chains_probe() {
    _ci_why=""
    if [ "$("$1" -w -t "$2" -S "$h_name_chain" 2>/dev/null | wc -l)" -le 1 ]; then
        _ci_why="цепочка $h_name_chain пуста или отсутствует"
    elif ! "$1" -w -t "$2" -S PREROUTING 2>/dev/null | \
         grep -- "$h_comment_tag" | grep -qE -- "-j ${h_name_chain}(_force)?\$"; then
        _ci_why="из PREROUTING нет перехода в $h_name_chain"
    elif [ "$h_proxy_router" = "on" ] && \
         ! "$1" -w -t "$2" -S OUTPUT 2>/dev/null | grep -q -- "$h_comment_tag"; then
        _ci_why="из OUTPUT нет перехода в $h_name_chain (проксирование Entware)"
    fi
}

# $1 бинарь, $2 семейство, $3 таблица
_ci_chains() {
    _ci_try=0
    _ci_chains_probe "$1" "$3"
    # NDM пересобирает netfilter по своим событиям, хук возвращает правила
    # следом. Повторы отсекают попадание проверки в это окно.
    while [ -n "$_ci_why" ] && [ "$_ci_try" -lt 2 ]; do
        sleep 1
        _ci_try=$((_ci_try + 1))
        _ci_chains_probe "$1" "$3"
    done
    if [ -z "$_ci_why" ]; then
        _ci_line ok "$2 $3: цепочка $h_name_chain и переходы на месте"
    else
        _ci_line fail "$2 $3: $_ci_why" "xkeen -restart пересоберёт правила"
    fi
}

# Слушает ли ядро порты перехвата. Сразу после перезапуска сокет поднимается
# не мгновенно, поэтому несколько попыток.
_ci_ports() {
    _ci_try=0
    while :; do
        # Идиома та же, что в tests_ports_client (02_tests_xports.sh)
        _ci_listen=" $(netstat -ltunp 2>/dev/null | awk -v n="$h_name_client" '
            $NF ~ ("/" n "$") { p = $4; sub(/.*:/, "", p); printf "%s ", p }') "
        _ci_miss=""
        for _ci_p in "redirect:$h_port_redirect" "tproxy:$h_port_tproxy"; do
            [ -n "${_ci_p#*:}" ] || continue
            case "$_ci_listen" in
                *" ${_ci_p#*:} "*) ;;
                *) _ci_miss="$_ci_miss $_ci_p" ;;
            esac
        done
        [ -z "$_ci_miss" ] && break
        [ "$_ci_try" -ge 2 ] && break
        _ci_try=$((_ci_try + 1))
        sleep 1
    done

    for _ci_p in "redirect:$h_port_redirect" "tproxy:$h_port_tproxy"; do
        [ -n "${_ci_p#*:}" ] || continue
        case " $_ci_miss " in
            *" $_ci_p "*)
                _ci_line fail "ядро $h_name_client не слушает порт ${_ci_p#*:} (${_ci_p%%:*})" \
                    "Конфигурацию меняли без перезапуска? xkeen -restart" ;;
            *)
                _ci_line ok "ядро $h_name_client слушает порт ${_ci_p#*:} (${_ci_p%%:*})" ;;
        esac
    done
}

# Может ли configure_route создать правило fwmark для IPv$1 прямо сейчас.
# Повторяет check_default из configure_route хука: без маршрута по умолчанию
# в таблице политики правила нет штатно, и перезапуск этого не изменит.
_ci_can_route() {
    _ci_src="main"
    if [ -n "$h_policy_mark" ]; then
        _ci_pt=$(ip rule show 2>/dev/null | \
            awk -v policy="$h_policy_mark" '$0 ~ policy && /lookup/ && !/blackhole/ {print $(NF); exit}')
        [ -n "$_ci_pt" ] && _ci_src="$_ci_pt"
    fi
    if [ "$1" = "6" ] && ! ip -6 route show default 2>/dev/null | grep -q .; then
        return 0
    fi
    if [ "$_ci_src" = "main" ]; then
        ip -"$1" route show default 2>/dev/null | grep -q '^default'
    else
        ip -"$1" route show table "$_ci_src" 2>/dev/null | grep -E '^default ' | grep -vq 'unreachable'
    fi
}

# Маршруты для TProxy: $1 = 4|6. Условия те же, что в configure_route хука.
_ci_route() {
    if ip -"$1" rule show 2>/dev/null | grep -q "fwmark $h_table_mark lookup $h_table_id"; then
        if ip -"$1" route show table "$h_table_id" 2>/dev/null | grep -q '^local default dev lo'; then
            _ci_line ok "IPv$1 маршруты: fwmark $h_table_mark в таблицу $h_table_id, local default dev lo"
        else
            _ci_line fail "IPv$1 маршруты: в таблице $h_table_id нет local default dev lo" \
                "xkeen -restart пересоздаст маршруты"
        fi
    elif _ci_can_route "$1"; then
        _ci_line fail "IPv$1 маршруты: нет правила fwmark $h_table_mark в таблицу $h_table_id" \
            "xkeen -restart пересоздаст маршруты"
    else
        _ci_line warn "IPv$1 маршруты: правила fwmark нет, нет маршрута IPv$1 по умолчанию" \
            "Штатно, пока у выбранного подключения нет IPv$1. Перезапуск этого не изменит"
    fi
}

# Метка политики: совпадает ли запечённая в хук метка с меткой политики того
# же имени в роутере. Сравнивать с любой меткой нельзя: get_policy_mark
# выбирает политику по description, и метка чужой политики дала бы зелёный
# на удалённой своей.
_ci_policy() {
    if [ -z "$h_policy_mark" ] && [ -z "$h_policy_mark_full" ]; then
        _ci_line skip "политика роутера не используется: проксируется весь трафик LAN"
        return 0
    fi
    if ! command -v jq >/dev/null 2>&1; then
        _ci_line warn "jq недоступен, метки политик не проверены"
        return 0
    fi

    _ci_pjson=$(curl_api "127.0.0.1:79/rci/show/ip/policy" 2>/dev/null)
    if [ -z "$_ci_pjson" ]; then
        _ci_line warn "список политик из веб-интерфейса не получен, метки не проверены"
        return 0
    fi

    _ci_pname=$(_ci_initd_var name_policy)
    [ -n "$_ci_pname" ] || _ci_pname="xkeen"
    _ci_pname_full=$(_ci_initd_var name_policy_full)
    [ -n "$_ci_pname_full" ] || _ci_pname_full="xkeen_full"

    for _ci_pair in "$h_policy_mark|$_ci_pname" "$h_policy_mark_full|$_ci_pname_full"; do
        _ci_m="${_ci_pair%%|*}"
        [ -n "$_ci_m" ] || continue
        _ci_pn="${_ci_pair#*|}"
        _ci_now=$(printf '%s' "$_ci_pjson" | jq -r --arg n "$_ci_pn" '
            .[]? | select((.description // "" | ascii_downcase) == ($n | ascii_downcase)) | .mark // empty
        ' 2>/dev/null | head -1 | tr 'A-F' 'a-f')
        _ci_was=$(printf '%s' "${_ci_m#0x}" | tr 'A-F' 'a-f')
        if [ -z "$_ci_now" ]; then
            _ci_line fail "политики '$_ci_pn' в роутере нет: её удалили или переименовали" \
                "Создайте политику заново, затем xkeen -restart"
        elif [ "$_ci_now" = "$_ci_was" ]; then
            _ci_line ok "метка политики '$_ci_pn' совпадает с применённой ($_ci_m)"
        else
            _ci_line fail "метка политики '$_ci_pn' сменилась: в правилах $_ci_m, в роутере 0x$_ci_now" \
                "xkeen -restart подхватит актуальную метку"
        fi
    done
}

# Проверка прозрачного перехвата по слоям.
# Коды возврата: 0 — сбоев нет, 1 — сбой или прокси-клиент не запущен,
# 2 — идёт запуск, остановка или пересборка правил.
tests_intercept_check() {
    _ci_fail=0
    _ci_warn=0
    _ci_families=0
    # Каталог состояния уже создан и проверен в 01_info_common.sh
    # ($tmp_ram). Повторно звать _xkeen_secure_rundir нельзя: при неверных
    # правах она сносит каталог вместе с живыми замками.
    _ci_rundir="${tmp_ram%/*}"

    echo
    if _ci_busy; then
        echo -e "  Идёт запуск или остановка ${yellow}XKeen${reset}, повторите проверку через несколько секунд"
        return 2
    fi

    if ! _ci_read_hook; then
        if ! pidof xray >/dev/null 2>&1 && ! pidof mihomo >/dev/null 2>&1; then
            echo -e "  Прокси-клиент ${red}не запущен${reset}"
            return 1
        fi
        if _ci_live_rules; then
            # Правила в ядре есть, а хука нет: первая же пересборка netfilter
            # в NDM снимет перехват и вернуть его будет нечем.
            _ci_line fail "правила XKeen в ядре есть, а netfilter-хук пуст" \
                "Перехват исчезнет при первой пересборке правил роутером. xkeen -restart"
        elif [ ! -f "$_ci_rundir/ready" ]; then
            _ci_line fail "netfilter-хук пуст и флага ready нет: запуск не завершён" "xkeen -restart"
        else
            # В режиме Other configure_firewall не вызывается и хук остаётся
            # пустым (04_register_init.sh, proxy_start): это штатно.
            echo -e "  Режим ${light_blue}Other${reset}: прозрачный перехват не используется, проверять нечего"
            return 0
        fi
        echo
        echo -e "  Сбоев: ${red}$_ci_fail${reset}"
        return 1
    fi

    if [ -z "$h_port_tproxy" ] && [ -z "$h_port_redirect" ]; then
        echo -e "  Режим ${light_blue}${h_mode_proxy:-Other}${reset}: прозрачный перехват не используется, проверять нечего"
        return 0
    fi

    echo -e "  Проверка перехвата: ${yellow}$h_name_client${reset}, режим ${light_blue}$h_mode_proxy${reset}"
    echo
    if ! pidof "$h_name_client" >/dev/null 2>&1; then
        _ci_line fail "ядро $h_name_client не запущено, netfilter-хук остался от прошлого запуска" \
            "xkeen -start"
        echo
        echo -e "  Сбоев: ${red}$_ci_fail${reset}"
        return 1
    fi

    _ci_ports

    if [ -f "$_ci_rundir/ready" ]; then
        _ci_line ok "хук активен (флаг ready)"
    else
        # Без ready хук выходит первой же строкой: правила, которые стоят
        # сейчас, после ближайшего события NDM не вернутся.
        _ci_line fail "флага ready нет: запуск не завершён, хук не применяется" \
            "xkeen -restart"
    fi

    # Набор таблиц выводится из портов — как _xkeen_hook_tables в хуке.
    # В режиме TProxy таблица nat пуста штатно, проверять её нельзя.
    _ci_tables=""
    [ -n "$h_port_tproxy" ] && _ci_tables="$h_table_tproxy"
    [ -n "$h_port_redirect" ] && [ "$h_table_redirect" != "$h_table_tproxy" ] && \
        _ci_tables="$_ci_tables $h_table_redirect"

    # Правила DNS для AdGuard Home ставятся только по непустым меткам
    # (dns_redir хука): без них проверять нечего.
    _ci_dns_expected="no"
    if [ "$h_aghfix" = "on" ] && ! { [ "$h_file_dns" = "true" ] && [ "$h_proxy_dns" = "on" ]; } && \
       { [ -n "$h_policy_mark" ] || [ -n "$h_policy_mark_full" ] || \
         [ -n "$h_custom_mark" ] || [ -n "$h_user_policies" ]; }; then
        _ci_dns_expected="yes"
    fi

    for _ci_bin in iptables ip6tables; do
        if [ "$_ci_bin" = "iptables" ]; then
            [ "$h_iptables_supported" = "true" ] || continue
            _ci_fam="IPv4"
        else
            [ "$h_ip6tables_supported" = "true" ] || continue
            _ci_fam="IPv6"
        fi
        _ci_families=$((_ci_families + 1))
        for _ci_t in $_ci_tables; do
            _ci_chains "$_ci_bin" "$_ci_fam" "$_ci_t"
        done
        if [ "$_ci_dns_expected" = "yes" ]; then
            if ! "$_ci_bin" -w -t nat -nL _NDM_HOTSPOT_DNSREDIR >/dev/null 2>&1; then
                _ci_line warn "$_ci_fam nat: цепочки _NDM_HOTSPOT_DNSREDIR нет, правила DNS не проверены"
            elif "$_ci_bin" -w -t nat -S _NDM_HOTSPOT_DNSREDIR 2>/dev/null | grep -q -- "$h_comment_tag"; then
                _ci_line ok "$_ci_fam nat: правила DNS для AdGuard Home на месте"
            else
                _ci_line warn "$_ci_fam nat: в _NDM_HOTSPOT_DNSREDIR нет правил XKeen (aghfix)" \
                    "Клиенты в журнале AdGuard Home будут под адресом роутера. xkeen -restart"
            fi
        fi
    done

    if [ "$_ci_families" -eq 0 ]; then
        _ci_line warn "ни IPv4, ни IPv6 не отмечены поддерживаемыми в хуке: правила не проверены" \
            "xkeen -restart пересоберёт хук"
    fi

    if [ -n "$h_port_tproxy" ]; then
        [ "$h_iptables_supported" = "true" ] && _ci_route 4
        [ "$h_ip6tables_supported" = "true" ] && _ci_route 6
    fi

    _ci_policy

    echo
    # Состояние могло смениться прямо во время проверки: тогда вердикт
    # сложен из правил разных моментов и о нём честнее промолчать.
    if _ci_busy; then
        echo -e "  Во время проверки начался запуск или остановка ${yellow}XKeen${reset}, повторите проверку"
        return 2
    fi
    if [ "$_ci_fail" -gt 0 ]; then
        echo -e "  Сбоев: ${red}$_ci_fail${reset}, предупреждений: $_ci_warn"
        echo -e "  Выполните ${yellow}xkeen -restart${reset} и повторите проверку; не помогло — ${yellow}xkeen -diag${reset}"
        return 1
    fi
    echo -e "  ${green}Сбоев нет${reset}, предупреждений: $_ci_warn"
    echo -e "  ${italic}Проверены применённые правила, но не трафик и не доступность прокси-сервера${reset}"
    return 0
}
