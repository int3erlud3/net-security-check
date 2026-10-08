#!/usr/bin/env bats
# Tests for bin/net-security-check. External commands (ip, ss, nft, iptables, ufw,
# firewall-cmd, getent, openssl, ping, hostname) are mocked; PATH contains only the
# mocks plus the coreutils the script needs (see nsc), so results do not depend on the host.

setup() {
  NSC="$BATS_TEST_DIRNAME/../bin/net-security-check"
  FIX="$BATS_TEST_DIRNAME/fixtures"
  MOCKS="$BATS_TEST_DIRNAME/mocks"
  MOCKBIN="$BATS_TEST_TMPDIR/bin"
  export MOCK_FIXTURES="$BATS_TEST_TMPDIR/fx"
  mkdir -p "$MOCKBIN" "$MOCK_FIXTURES"
  local tool
  for tool in bash env awk sed grep sort uniq paste tr wc head tail cat date timeout script sleep; do
    ln -s "$(command -v "$tool")" "$MOCKBIN/$tool"
  done
  mock hostname "testhost"
  unset NO_BANNER MOCK_PMTU MOCK_CERT_END MOCK_TLS_RC MOCK_TLS_LEGACY_RC

  # Hardened sysctl tree and a resolv.conf with two nameservers by default
  export NSC_PROC_SYS="$BATS_TEST_TMPDIR/proc_sys"
  export NSC_RESOLV_CONF="$BATS_TEST_TMPDIR/resolv.conf"
  printf 'search example.test\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n' >"$NSC_RESOLV_CONF"
  sysctl_set net.ipv4.ip_forward 0
  sysctl_set net.ipv6.conf.all.forwarding 0
  sysctl_set net.ipv4.conf.all.accept_redirects 0
  sysctl_set net.ipv4.conf.default.accept_redirects 0
  sysctl_set net.ipv6.conf.all.accept_redirects 0
  sysctl_set net.ipv4.conf.all.secure_redirects 0
  sysctl_set net.ipv4.conf.all.send_redirects 0
  sysctl_set net.ipv4.conf.all.accept_source_route 0
  sysctl_set net.ipv6.conf.all.accept_source_route 0
  sysctl_set net.ipv4.conf.all.rp_filter 1
  sysctl_set net.ipv4.tcp_syncookies 1
  sysctl_set net.ipv4.icmp_echo_ignore_broadcasts 1
  sysctl_set net.ipv4.icmp_ignore_bogus_error_responses 1
  sysctl_set net.ipv4.conf.all.log_martians 1
}

# mock NAME [OUTPUT [RC]]  - fake a command for any arguments
mock() {
  ln -sf "$MOCKS/mockcmd" "$MOCKBIN/$1"
  [[ $# -lt 2 ]] || printf '%s\n' "$2" >"$MOCK_FIXTURES/$1.out"
  [[ $# -lt 3 ]] || printf '%s\n' "$3" >"$MOCK_FIXTURES/$1.rc"
}

# mock_args NAME "ARGS" OUTPUT [RC] - fake a command for one specific argument list
mock_args() {
  ln -sf "$MOCKS/mockcmd" "$MOCKBIN/$1"
  local key
  key="$1__$(printf '%s' "$2" | tr -c 'A-Za-z0-9' '_')"
  printf '%s\n' "$3" >"$MOCK_FIXTURES/$key.out"
  [[ $# -lt 4 ]] || printf '%s\n' "$4" >"$MOCK_FIXTURES/$key.rc"
}

sysctl_set() {
  local f="$NSC_PROC_SYS/${1//.//}"
  mkdir -p "${f%/*}"
  printf '%s\n' "$2" >"$f"
}

# Run the script with a PATH that contains only the mocks and the needed coreutils.
nsc() { run env PATH="$MOCKBIN" "$NSC" "$@"; }


# ---- DNS -----------------------------------------------------------------------
@test "dns: two nameservers are OK and search domains are reported" {
  nsc --checks dns
  [ "$status" -eq 0 ]
  [[ "$output" == *"[OK  ] dns"* ]]
  [[ "$output" == *"2 nameservers: 10.0.0.2 10.0.0.3"* ]]
  [[ "$output" == *"search domains: example.test"* ]]
}

@test "dns: a single nameserver is a WARNING, none is CRITICAL" {
  printf 'nameserver 10.0.0.2\n' >"$NSC_RESOLV_CONF"
  nsc --checks dns
  [ "$status" -eq 1 ]
  [[ "$output" == *"only one nameserver"* ]]
  printf '# empty\n' >"$NSC_RESOLV_CONF"
  nsc --checks dns
  [ "$status" -eq 2 ]
}

@test "dns: systemd-resolved stub is recognised" {
  printf 'nameserver 127.0.0.53\noptions edns0 trust-ad\n' >"$NSC_RESOLV_CONF"
  nsc --checks dns
  [ "$status" -eq 0 ]
  [[ "$output" == *"systemd-resolved stub"* ]]
}

@test "dns: name resolution success and failure" {
  mock_args getent "ahosts www.example.test" "192.0.2.10      STREAM www.example.test"
  nsc --checks dns --dns-name www.example.test
  [ "$status" -eq 0 ]
  [[ "$output" == *"www.example.test resolves to 192.0.2.10"* ]]
  mock getent "" 2
  nsc --checks dns --dns-name nope.example.test
  [ "$status" -eq 2 ]
  [[ "$output" == *"cannot resolve nope.example.test"* ]]
}

# ---- routes / MTU ----------------------------------------------------------------
@test "routes: default route present, missing, and duplicated" {
  mock_args ip "-4 route show default" "default via 192.0.2.1 dev eth0 proto dhcp metric 100"
  mock_args ip "-6 route show default" ""
  nsc --checks routes
  [ "$status" -eq 0 ]
  [[ "$output" == *"IPv4 default: via 192.0.2.1 dev eth0"* ]]
  mock_args ip "-4 route show default" ""
  nsc --checks routes
  [ "$status" -eq 1 ]
  [[ "$output" == *"no IPv4 default route"* ]]
  mock_args ip "-4 route show default" $'default via 192.0.2.1 dev eth0 metric 100\ndefault via 198.51.100.1 dev eth1 metric 100'
  nsc --checks routes
  [ "$status" -eq 1 ]
  [[ "$output" == *"2 IPv4 default routes with equal metric"* ]]
}

@test "mtu: interface MTUs, below-1280 warning, down interfaces skipped" {
  mock_args ip "-o link show" "$(cat "$FIX/ip_link.txt")"
  nsc --checks mtu
  [ "$status" -eq 1 ]
  [[ "$output" == *"OK   eth0 mtu 1500"* ]]
  [[ "$output" == *"INFO wg0 mtu 1420"* ]]
  [[ "$output" == *"vlan9 mtu 1200 is below the IPv6 minimum"* ]]
  [[ "$output" != *"eth1"* ]]
  [[ "$output" != *" lo "* ]]
}

@test "mtu: path MTU discovery with ping -M do" {
  mock_args ip "-o link show" "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP"
  ln -s "$MOCKS/ping" "$MOCKBIN/ping"
  MOCK_PMTU=1500 nsc --checks mtu --target gw.example.test
  [ "$status" -eq 0 ]
  [[ "$output" == *"path MTU to gw.example.test is 1500"* ]]
  MOCK_PMTU=1420 nsc --checks mtu --target gw.example.test
  [ "$status" -eq 1 ]
  [[ "$output" == *"path MTU to gw.example.test is 1420 (< 1500)"* ]]
  nsc --checks mtu --target gw.example.test
  [ "$status" -eq 1 ]
  [[ "$output" == *"probe to gw.example.test failed"* ]]
}

# ---- ports / exposure -------------------------------------------------------------
@test "ports: listeners are listed with owning process and scope" {
  mock ss "$(cat "$FIX/ss_server.txt")"
  nsc --checks ports
  [ "$status" -eq 0 ]
  [[ "$output" == *"10 listening sockets: 7 on all interfaces, 2 on loopback, 1 on specific addresses"* ]]
  [[ "$output" =~ tcp\ +0\.0\.0\.0\ +22\ +all\ +sshd\[812\] ]]
  [[ "$output" =~ udp\ +127\.0\.0\.53\ +53\ +loopback\ +systemd-resolve\[500\] ]]
  [[ "$output" =~ udp\ +0\.0\.0\.0\ +5353\ +all\ +- ]]
}

@test "exposure: allowlist, critical and risky services on 0.0.0.0" {
  mock ss "$(cat "$FIX/ss_server.txt")"
  nsc --checks exposure --allow-ports 22,443/tcp,68/udp
  [ "$status" -eq 2 ]
  [[ "$output" == *"CRIT tcp/6379 (redis-server[930]) is exposed on all interfaces - service should never be network-reachable"* ]]
  [[ "$output" == *"WARN tcp/1521 (tnslsnr[1500]) is exposed on all interfaces - database/management service"* ]]
  [[ "$output" == *"WARN udp/5353 (-) is exposed on all interfaces and not in --allow-ports"* ]]
  [[ "$output" != *"tcp/22 "* ]]
  [[ "$output" != *"tcp/443"* ]]
  [[ "$output" != *"5432"* ]]
  [[ "$output" != *"9100"* ]]
}

@test "exposure: nothing unexpected is OK" {
  mock ss "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))"
  nsc --checks exposure
  [ "$status" -eq 0 ]
  [[ "$output" == *"no unexpected services"* ]]
}

# ---- firewall ---------------------------------------------------------------------
@test "firewall: nftables with policy drop is OK" {
  mock_args nft "list ruleset" "$(cat "$FIX/nft_drop.txt")"
  nsc --checks firewall
  [ "$status" -eq 0 ]
  [[ "$output" == *"nftables: 1 input chain(s), policy drop"* ]]
}

@test "firewall: nftables accept policy without drop rules is a WARNING" {
  mock_args nft "list ruleset" "$(cat "$FIX/nft_accept.txt")"
  nsc --checks firewall
  [ "$status" -eq 1 ]
  [[ "$output" == *"policy accept and no drop/reject rules"* ]]
}

@test "firewall: iptables INPUT DROP, ufw and firewalld summaries" {
  mock_args iptables "-S INPUT" $'-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT'
  nsc --checks firewall
  [ "$status" -eq 0 ]
  [[ "$output" == *"iptables: INPUT policy DROP, 2 rules"* ]]
  rm "$MOCKBIN/iptables"
  mock_args ufw "status verbose" "$(cat "$FIX/ufw_active.txt")"
  nsc --checks firewall
  [ "$status" -eq 0 ]
  [[ "$output" == *"ufw active (deny (incoming), allow (outgoing), disabled (routed)), 3 rules"* ]]
  rm "$MOCKBIN/ufw"
  mock_args firewall-cmd "--state" "running"
  mock_args firewall-cmd "--get-default-zone" "public"
  mock_args firewall-cmd "--list-all --zone=public" "$(cat "$FIX/firewalld_public.txt")"
  nsc --checks firewall
  [ "$status" -eq 0 ]
  [[ "$output" == *"firewalld running, default zone public (target default); services: dhcpv6-client ssh; ports: 443/tcp"* ]]
}

@test "firewall: none active is a WARNING; permission errors are reported as INFO" {
  nsc --checks firewall
  [ "$status" -eq 1 ]
  [[ "$output" == *"no active host firewall"* ]]
  mock nft "" 1
  printf 'Operation not permitted (you must be root)\n' >"$MOCK_FIXTURES/nft.err"
  nsc --checks firewall
  [[ "$output" == *"nftables: run as root to read the ruleset"* ]]
}

# ---- TLS ----------------------------------------------------------------------------
@test "tls: modern protocol and valid certificate are OK" {
  ln -s "$MOCKS/openssl" "$MOCKBIN/openssl"
  cp "$FIX/s_client_ok.txt" "$MOCK_FIXTURES/s_client.out"
  MOCK_CERT_END="$(date -u -d '+90 days' '+%b %e %H:%M:%S %Y GMT')" nsc --checks tls --tls www.example.test:443
  [ "$status" -eq 0 ]
  [[ "$output" == *"www.example.test:443: certificate valid for 89 days"* || "$output" == *"valid for 90 days"* ]]
  [[ "$output" == *"negotiated TLSv1.3"* ]]
}

@test "tls: expiring, expired, legacy protocols and verification errors" {
  ln -s "$MOCKS/openssl" "$MOCKBIN/openssl"
  sed -e 's/TLSv1.3/TLSv1.2/' -e 's/0 (ok)/19 (self-signed certificate in certificate chain)/' "$FIX/s_client_ok.txt" >"$MOCK_FIXTURES/s_client.out"
  MOCK_TLS_LEGACY_RC=0 MOCK_CERT_END="$(date -u -d '+5 days' '+%b %e %H:%M:%S %Y GMT')" nsc --checks tls --tls app.example.test:8443
  [ "$status" -eq 1 ]
  [[ "$output" == *"certificate expires in"* ]]
  [[ "$output" == *"certificate verification failed: 19 (self-signed"* ]]
  [[ "$output" == *"still accepts TLS 1.0"* ]]
  [[ "$output" == *"still accepts TLS 1.1"* ]]
  MOCK_CERT_END="$(date -u -d '-3 days' '+%b %e %H:%M:%S %Y GMT')" nsc --checks tls --tls app.example.test:8443
  [ "$status" -eq 2 ]
  [[ "$output" == *"certificate expired 3 days ago"* || "$output" == *"certificate expired 2 days ago"* ]]
  MOCK_TLS_RC=1 nsc --checks tls --tls down.example.test:443
  [ "$status" -eq 2 ]
  [[ "$output" == *"TLS handshake failed"* ]]
}

@test "tls: no targets is informational" {
  nsc --checks tls
  [ "$status" -eq 0 ]
  [[ "$output" == *"no --tls HOST:PORT targets given"* ]]
}

# ---- sysctl -------------------------------------------------------------------------
@test "sysctl: hardened values are OK" {
  nsc --checks sysctl
  [ "$status" -eq 0 ]
  [[ "$output" == *"network sysctl hardening as expected"* ]]
}

@test "sysctl: forwarding, redirects and rp_filter deviations are reported" {
  sysctl_set net.ipv4.ip_forward 1
  sysctl_set net.ipv4.conf.all.accept_redirects 1
  sysctl_set net.ipv4.conf.all.rp_filter 0
  sysctl_set net.ipv4.conf.all.log_martians 0
  nsc --checks sysctl
  [ "$status" -eq 1 ]
  [[ "$output" == *"WARN net.ipv4.ip_forward = 1, expected 0"* ]]
  [[ "$output" == *"WARN net.ipv4.conf.all.accept_redirects = 1"* ]]
  [[ "$output" == *"net.ipv4.conf.all.rp_filter = 0, expected 1 or 2"* ]]
  [[ "$output" == *"INFO net.ipv4.conf.all.log_martians = 0"* ]]
}

@test "sysctl: --allow-forwarding downgrades forwarding to INFO; rp_filter 2 is fine" {
  sysctl_set net.ipv4.ip_forward 1
  sysctl_set net.ipv4.conf.all.rp_filter 2
  nsc --checks sysctl --allow-forwarding
  [ "$status" -eq 0 ]
  [[ "$output" == *"INFO net.ipv4.ip_forward = 1 (forwarding allowed by --allow-forwarding)"* ]]
}

# ---- output / CLI -------------------------------------------------------------------
@test "json output is valid and contains listeners" {
  command -v jq >/dev/null 2>&1 || [ -x /usr/bin/jq ] || skip "jq not installed"
  mock ss "$(cat "$FIX/ss_server.txt")"
  nsc --checks dns,ports,exposure,sysctl --format json
  [ "$status" -eq 2 ]
  [ "$(/usr/bin/jq -r .status <<<"$output")" = CRIT ]
  [ "$(/usr/bin/jq -r .host <<<"$output")" = testhost ]
  [ "$(/usr/bin/jq -r '.checks | map(.check) | join(",")' <<<"$output")" = "dns,ports,exposure,sysctl" ]
  [ "$(/usr/bin/jq -r '.checks[1].listeners | length' <<<"$output")" = 10 ]
  [ "$(/usr/bin/jq -r '.checks[1].listeners[0].process' <<<"$output")" = "sshd[812]" ]
  [ "$(/usr/bin/jq -r '.checks[2].status' <<<"$output")" = CRIT ]
}

@test "all checks run by default and missing tools degrade gracefully" {
  nsc
  [ "$status" -eq 1 ]
  for c in dns routes mtu ports exposure firewall tls sysctl; do
    [[ "$output" == *"] $c"* ]] || { echo "missing $c"; return 1; }
  done
  [[ "$output" == *"ip (iproute2) not available"* ]]
  [[ "$output" == *"ss (iproute2) not available"* ]]
}

@test "read-only: only query commands are executed" {
  mock ss "$(cat "$FIX/ss_server.txt")"
  mock ip ""
  mock nft ""
  mock iptables ""
  mock ufw ""
  mock firewall-cmd "not running"
  nsc
  calls=$(cat "$MOCK_FIXTURES/calls.log")
  grep -q '^nft list ruleset$' <<<"$calls"
  grep -q '^iptables -S INPUT$' <<<"$calls"
  if grep -Eq ' (add|del|delete|flush|insert|replace|reload|enable|disable|allow|deny|set|-A|-D|-I|-F|-P)( |$)' <<<"$calls"; then
    echo "modifying command executed: $calls"
    return 1
  fi
}

@test "invalid arguments exit 3" {
  local bad
  for bad in "--checks dns,bogus" "--allow-ports 22,abc" "--allow-ports 70000" "--tls nohostport" \
    "--tls bad_host:443" "--tls host:99999" "--target -oProxyCommand=x" "--timeout 0" "--format xml" "--bogus"; do
    # shellcheck disable=SC2086
    run "$NSC" $bad
    [ "$status" -eq 3 ] || { echo "accepted: $bad"; return 1; }
  done
}

# ---- banner -------------------------------------------------------------------------
# script(1) runs the command on a pseudo-terminal, so stdout/stderr are a TTY.
on_tty() {
  command -v script >/dev/null || skip "script(1) not available"
  run script -qefc "$(printf '%q ' env PATH="$MOCKBIN" "$@")" /dev/null </dev/null
}

@test "banner is printed on an interactive terminal" {
  on_tty "$NSC" --checks sysctl
  [[ "$output" == *"Bastion Ops Toolkit"* ]]
  [[ "$output" == *"NET SECURITY CHECK"* ]]
}

@test "banner is not printed when stderr is not a terminal" {
  nsc --checks sysctl
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
}

@test "--no-banner and NO_BANNER=1 suppress the banner on a terminal" {
  on_tty "$NSC" --checks sysctl --no-banner
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
  on_tty env NO_BANNER=1 "$NSC" --checks sysctl
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
}

@test "JSON output never contains the banner, even on a terminal" {
  on_tty "$NSC" --checks sysctl --format json
  [ "$status" -eq 0 ]
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
}

@test "--help and --version show the banner on a terminal only" {
  on_tty "$NSC" --help
  [[ "$output" == *"Bastion Ops Toolkit"* ]]
  nsc --version
  [ "$output" = "net-security-check 1.0.0" ]
}

@test "README banner matches the runtime banner" {
  on_tty "$NSC" --version
  expected=$(awk -v fence='```' '$0 == fence "text" { on = 1; next } on && $0 == fence { exit } on' "$BATS_TEST_DIRNAME/../README.md")
  actual=$(printf '%s\n' "$output" | tr -d '\r')
  [ -n "$expected" ]
  [[ "$actual" == "$expected"* ]]
}
