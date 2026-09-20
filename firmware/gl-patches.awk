# Only exact supported inputs reach these edits. Each anchor must occur once.
BEGIN {
    if (target == "rtp") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1"
        anchor[2] = "cmd=\"$1\";shift"
        replacement[2] = "cmd=\"$1\";shift\n# Owned lifecycle events are handled by the daemon. Other policies still reconcile.\nif [ \"$cmd\" = interface_status_change ] && hs_owned \"$1\"; then\n    hs_event \"$1\"\n    exit 0\nfi\nhs_lock || exit 1\ntrap 'hs_unlock' EXIT\nif [ \"$cmd\" = interface_status_change ] && hs_owned \"$1\"; then\n    hs_event \"$1\"\n    exit 0\nfi\ncase \"$cmd\" in\n    hotswapper_prepare)\n        hs_request && hs_owned \"$1\" || exit 1\n        hs_invalidate_all\n        config_load network\n        mark=$(get_mark_of_interface \"$1\")\n        if [ -f \"$FILE_VPN_DNS_RULE\" ]; then\n            awk -v mark=\"$mark/$vpn_mark_mask\" 'index($0, \"--mark \" mark \" \")==0' \"$FILE_VPN_DNS_RULE\" > \"$FILE_VPN_DNS_RULE.hotswap\"\n            mv \"$FILE_VPN_DNS_RULE.hotswap\" \"$FILE_VPN_DNS_RULE\"\n        fi\n        load_vpn_instance_rule \"$1\"\n        # The raw return-zone row has no mark predicate, so deduplicate exact rows too.\n        awk '!seen[$0]++' \"$FILE_VPN_DNS_RULE\" > \"$FILE_VPN_DNS_RULE.hotswap\"\n        mv \"$FILE_VPN_DNS_RULE.hotswap\" \"$FILE_VPN_DNS_RULE\"\n        hs_prepare_dns \"$1\" \"$mark\" || exit 1\n        hs_unlock\n        /etc/init.d/dnsmasq reload || exit 1\n        exit 0\n        ;;\nesac\nhs_invalidate_all"
        anchor[3] = "    /etc/init.d/firewall reload 2>/dev/null &"
        replacement[3] = "    /etc/init.d/firewall reload 2>/dev/null"
        anchor[4] = "    /etc/init.d/dnsmasq restart >/dev/null 2>&1 &"
        replacement[4] = "    /etc/init.d/dnsmasq restart >/dev/null 2>&1"
        anchor[5] = "        while [ -f \"${LOCKFILE}\" ] && [ $count -le 30 ]; do"
        replacement[5] = "        # The shared descriptor lock replaces the old PID-file wait.\n        while false; do"
        anchor[6] = "    (/etc/init.d/gl-cloud stop; sleep 2; /etc/init.d/gl-cloud start) >/dev/null 2>&1 &"
        replacement[6] = "    (/etc/init.d/gl-cloud stop; sleep 2; /etc/init.d/gl-cloud start) 9>&- >/dev/null 2>&1 &"
        anchor[7] = "    pgrep -f '/usr/lib/gl_ddns/dynamic_dns_updater.sh' >/dev/null && /etc/init.d/gl_ddns restart >/dev/null 2>&1 &"
        replacement[7] = "    pgrep -f '/usr/lib/gl_ddns/dynamic_dns_updater.sh' >/dev/null && /etc/init.d/gl_ddns restart 9>&- >/dev/null 2>&1 &"
        count = 7
    }
    if (target == "instances") {
        anchor[1] = "        if not is_instance_config_used(instance, rules) then"
        replacement[1] = "        local owned = false\n        if via:match(\"^wgclient[123]$\") and tostring(instance.peer_id):match(\"^%d+$\") then\n            owned = os.execute(\"/root/hotswapper/gl-coordination.sh owned \" .. via .. \" peer_\" .. instance.peer_id) == 0\n        end\n        if not owned and not is_instance_config_used(instance, rules) then"
        count = 1
    }
    if (target == "setup") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1"
        anchor[2] = "uci -q del firewall.process_mark_dns"
        replacement[2] = "# Provider work can wait without holding the shared mutation lock.\nif hs_request && [ \"$operation\" = generate ] && [ -n \"$group_id\" ] && [ -n \"$client_id\" ]; then\n    update_provider_config \"$group_id\" \"$client_id\" \"$instance_name\"\n    HS_PROVIDER_DONE=1\nfi\nhs_lock || exit 1\nif hs_owned \"$instance_name\"; then\n    hs_request || exit 0\n    [ \"$HS_SLOT_IDENTITY\" = \"$(cat \"$HS_DIR/owned.$instance_name\")\" ] || exit 1\n    case \"$operation\" in\n        stop|clean)\n            identity=$(cat \"$HS_DIR/tunnel\")\n            policy=$(uci -q show route_policy | sed -n \"s/^route_policy\\.\\([^.=]*\\)\\.tunnel_id='${identity%%:*}'$/\\1/p\" | head -n 1)\n            [ \"$(uci -q get \"route_policy.$policy.via\")\" != \"$instance_name\" ] || exit 1\n            ;;\n    esac\nfi\nuci -q del firewall.process_mark_dns"
        anchor[3] = "    [ \"$instance_type\" = \"wgclient\" ] && update_provider_config $group_id $client_id ${instance_type}${index}"
        replacement[3] = "    [ \"$instance_type\" = \"wgclient\" ] && [ \"${HS_PROVIDER_DONE:-0}\" != 1 ] && update_provider_config $group_id $client_id ${instance_type}${index}"
        anchor[4] = "    uci -q delete network.${instance_type}${index}"
        replacement[4] = "    hs_owned \"${instance_type}${index}\" && ! hs_request && return 0\n    uci -q delete network.${instance_type}${index}"
        count = 4
    }
    if (target == "switch") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1"
        anchor[2] = "repoint_rule_to_iface() {"
        replacement[2] = "hs_stock_repoint_rule_to_iface() {"
        anchor[3] = "switch_tunnel() {"
        replacement[3] = "hs_stock_switch_tunnel() {"
        anchor[4] = "ensure_instance_exists() {"
        replacement[4] = "hs_stock_ensure_instance_exists() {"
        anchor[5] = "main() {"
        replacement[5] = "# Recheck under the shared lock, after every GL wait, before touching a slot.\nrepoint_rule_to_iface() (\n    hs_lock && hs_worker_allowed \"$1\" \"$4\" || return 1\n    hs_stock_repoint_rule_to_iface \"$@\"\n)\nswitch_tunnel() (\n    hs_lock && hs_worker_allowed \"$1\" \"$2\" || return 1\n    hs_stock_switch_tunnel \"$@\"\n)\nensure_instance_exists() (\n    hs_lock && hs_worker_allowed \"${tsw_tunnel_id:-}\" \"$1\" || return 1\n    hs_stock_ensure_instance_exists \"$@\"\n)\nmain() {"
        anchor[6] = "    load_tunnel_context \"$tunnel_id\" cfg_section via_type group_id current_iface shared_iface || exit 1"
        replacement[6] = "    hs_worker_allowed \"$tunnel_id\" || exit 0\n    load_tunnel_context \"$tunnel_id\" cfg_section via_type group_id current_iface shared_iface || exit 1"
        anchor[7] = "    ) &"
        replacement[7] = "    ) 9>&- &"
        count = 7
    }
    if (target == "proto") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1"
        anchor[2] = "\tip link del dev \"${interface}\" 2>/dev/null"
        replacement[2] = "\ths_lock || return 1\n\t[ \"$(uci -q get \"network.$interface.config\")\" = \"$config\" ] || return 1\n\t[ \"$hs_setup_identity\" = \"$(cat \"$HS_DIR/owned.$interface\" 2>/dev/null)\" ] || return 1\n\tif hs_owned \"$interface\" && ! hs_permit \"$interface\" up; then hs_wake; return 1; fi\n\tip link del dev \"${interface}\" 2>/dev/null"
        anchor[3] = "\tip link set up dev \"${interface}\""
        replacement[3] = "\ths_owned \"$interface\" && hs_ifindex \"$interface\"\n\tip link set up dev \"${interface}\""
        anchor[4] = "proto_wgclient_teardown() {"
        replacement[4] = "proto_wgclient_teardown() {\n    local hs_teardown_identity=\"$(cat \"$HS_DIR/owned.$1\" 2>/dev/null)\"\n    hs_lock || return 1\n    [ \"$hs_teardown_identity\" = \"$(cat \"$HS_DIR/owned.$1\" 2>/dev/null)\" ] || return 1\n    if hs_owned \"$1\" && ! hs_permit \"$1\" down; then hs_wake; return 1; fi"
        anchor[5] = "\tconfig_get config \"${interface}\" \"config\""
        replacement[5] = "\tconfig_get config \"${interface}\" \"config\"\n\tlocal hs_setup_identity=\"$(cat \"$HS_DIR/owned.$interface\" 2>/dev/null)\""
        anchor[6] = "\t) &"
        replacement[6] = "\t) 9>&- &"
        anchor[7] = "\t\t\t\"$interface\" \"${wg_cfg}_state\" 30 >/dev/null 2>&1 &"
        replacement[7] = "\t\t\t\"$interface\" \"${wg_cfg}_state\" 30 9>&- >/dev/null 2>&1 &"
        anchor[8] = "trigger_setup_failover() {"
        replacement[8] = "trigger_setup_failover() {\n    if hs_owned \"$interface\"; then hs_event \"$interface\"; return 0; fi"
        count = 8
    }
    if (target == "keyup") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1"
        anchor[2] = "\t\trm -f /tmp/wireguard/\"${ifname}\"_boot"
        replacement[2] = "        hs_lock || exit 1\n        if hs_owned \"$ifname\" && ! hs_peer_matches \"$ifname\"; then hs_wake; exit 0; fi\n\t\trm -f /tmp/wireguard/\"${ifname}\"_boot"
        count = 2
    }
    if (target == "keydown") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1\ncase \"$ACTION\" in\n    REKEY-TIMEOUT|REKEY-GIVEUP)\n        hs_lock || exit 1\n        if hs_owned \"$ifname\"; then hs_event \"$ifname\"; exit 0; fi\n        ;;\nesac"
        count = 1
    }
    if (target == "iface") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1\nif hs_owned \"$INTERFACE\"; then hs_event \"$INTERFACE\"; exit 0; fi"
        count = 1
    }
    if (target == "firewall_event") {
        anchor[1] = "#!/bin/sh"
        replacement[1] = "#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1\nif hs_owned \"$INTERFACE\"; then hs_event \"$INTERFACE\"; exit 0; fi\nhs_lock || exit 1\nif hs_owned \"$INTERFACE\"; then hs_event \"$INTERFACE\"; exit 0; fi\nhs_invalidate_all"
        anchor[2] = "    sleep 1 && fw3 -q reload&"
        replacement[2] = "    hs_unlock\n    (\n        HS_LOCKED=0; export HS_LOCKED\n        sleep 1\n        hs_lock || exit 1\n        if hs_owned \"$INTERFACE\"; then hs_event \"$INTERFACE\"; exit 0; fi\n        hs_invalidate_all\n        fw3 -q reload\n    ) 9>&- &"
        count = 2
    }
    if (target == "firewall") {
        anchor[1] = "QUIET=\"\""
        replacement[1] = "QUIET=\"\"\n. /root/hotswapper/gl-coordination.sh || exit 1\n# rc.common sources this before acquiring the procd service lock.\ncase \"$action\" in\n    start|stop|restart|reload|boot|shutdown) hs_lock || exit 1;;\nesac"
        anchor[2] = "\tfw3 restart"
        replacement[2] = "\ths_lock || return 1\n\ths_invalidate_all\n\tfw3 restart"
        anchor[3] = "\tfw3 ${QUIET} start"
        replacement[3] = "\ths_lock || return 1\n\ths_invalidate_all\n\tfw3 ${QUIET} start"
        anchor[4] = "\tfw3 flush"
        replacement[4] = "\ths_lock || return 1\n\ths_invalidate_all\n\tfw3 flush"
        anchor[5] = "\tfw3 reload"
        replacement[5] = "\ths_lock || return 1\n\ths_invalidate_all\n\tfw3 reload"
        count = 5
    }
    if (!count) exit 2
}
{
    matched=0
    for (i=1; i<=count; i++) if ($0 == anchor[i]) {
        seen[i]++; print replacement[i]; matched=1; break
    }
    if (!matched) print
}
END { for (i=1; i<=count; i++) if (seen[i] != 1) exit 3 }
