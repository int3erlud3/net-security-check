# net-security-check

[![CI](https://github.com/int3erlud3/net-security-check/actions/workflows/ci.yml/badge.svg)](https://github.com/int3erlud3/net-security-check/actions/workflows/ci.yml)
[![ShellCheck](https://img.shields.io/badge/shellcheck-clean-brightgreen.svg)](https://www.shellcheck.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```text
            _                           _ _
   _ _  ___| |_ ___ ___ ___ __ _  _ _ _(_) |_ _  _
  | ' \/ -_)  _|___(_-</ -_) _| || | '_| |  _| || |
  |_||_\___|\__|   /__/\___\__|\_,_|_| |_|\__|\_, |
                                              |__/
      _           _
   __| |_  ___ __| |__
  / _| ' \/ -_) _| / /
  \__|_||_\___\__|_\_\

+====================================================================+
|  NET SECURITY CHECK  ::  Network Diagnostics & Exposure Audit      |
+--------------------------------------------------------------------+
|  DNS, routes, MTU, listeners, firewall, TLS and sysctl hardening   |
|  v1.0.0  -  Bastion Ops Toolkit  -  by int3erlud3                  |
+====================================================================+
```

A **read-only** network diagnostics and exposure audit for Linux servers in one Bash
script: is name resolution redundant, is routing sane, does the MTU fit the path,
**which services listen on all interfaces and who owns them**, is a host firewall
actually filtering, are TLS endpoints healthy, and is the kernel network stack hardened?
Text for humans, JSON for automation, Nagios-style exit codes for monitoring.

## Checks

| Check | What is evaluated |
|---|---|
| `dns` | nameservers in `resolv.conf` (none = CRIT, one = WARN), systemd-resolved stub, search domains, optional resolution test (`--dns-name`) |
| `routes` | IPv4 default route present, multiple default routes with equal metric, IPv6 default |
| `mtu` | MTU of all up interfaces (< 1280 = WARN), optional **path MTU discovery** with DF pings (`--target`) |
| `ports` | all TCP/UDP listeners with address, scope (all / loopback / address) and owning process (`ss -tulpn`) |
| `exposure` | services bound to `0.0.0.0` / `[::]` / `*` that are not in `--allow-ports`; Telnet, Docker API, Redis, Memcached, Elasticsearch, MongoDB, VNC, r-services = CRIT; databases (incl. Oracle 1521), SMB, NFS, RDP, ... = WARN |
| `firewall` | nftables input chains and policy, iptables `INPUT` policy, ufw default incoming, firewalld default zone/target, services and ports |
| `tls` | per `--tls host:port`: handshake, negotiated protocol, certificate expiry (`--cert-warn-days`), chain verification, whether TLS 1.0/1.1 are still accepted |
| `sysctl` | IP forwarding, ICMP redirects (accept/send/secure), source routing, `rp_filter`, SYN cookies, broadcast pings, bogus ICMP errors, martian logging |

## Safe by design

- **Read-only**: only query commands are executed (`ip ... show`, `ss`, `nft list ruleset`,
  `iptables -S`, `ufw status`, `firewall-cmd --state/--list-all`, `getent`, `openssl s_client`,
  `ping`). A test asserts that no modifying sub-command is ever called.
- No temporary files, no configuration changes, no daemons; strict validation of every
  host/port argument before it reaches a command line.
- Works without root (reduced detail: other users' processes and firewall rulesets are
  then reported as "run as root").

## Installation

```bash
git clone https://github.com/int3erlud3/net-security-check.git
sudo install -m 0755 net-security-check/bin/net-security-check /usr/local/bin/
```

Requirements: Bash 4.4+, iproute2 (`ip`, `ss`), coreutils; optional `openssl`, `ping`,
`nft`/`iptables`/`ufw`/`firewall-cmd`. Missing tools degrade a check to INFO instead of failing.

## Usage

```bash
sudo net-security-check                                   # all checks
sudo net-security-check --allow-ports 22,443/tcp,68/udp   # declare what is expected
net-security-check --checks dns,routes,mtu --dns-name example.com --target 192.0.2.1
net-security-check --checks tls --tls www.example.com:443 --tls mail.example.com:465
sudo net-security-check --format json | jq '.checks[] | select(.status != "OK")'
net-security-check --allow-forwarding     # container hosts / routers: forwarding is expected
```

Example (synthetic host):

```text
net-security-check 1.0.0 on db1  (2026-10-08 11:40 CEST)

[OK  ] dns
       OK   2 nameservers: 10.0.0.2 10.0.0.3
       INFO search domains: example.test
[OK  ] routes
       OK   IPv4 default: via 192.0.2.1 dev eth0 proto dhcp metric 100
[OK  ] mtu
       OK   eth0 mtu 1500
[OK  ] ports
       OK   10 listening sockets: 7 on all interfaces, 2 on loopback, 1 on specific addresses
       PROTO ADDRESS                      PORT   SCOPE     PROCESS
       tcp   0.0.0.0                      22     all       sshd[812]
       tcp   [::]                         22     all       sshd[812]
       tcp   0.0.0.0                      443    all       nginx[1020]
       tcp   127.0.0.1                    5432   loopback  postgres[900]
       tcp   *                            6379   all       redis-server[930]
       tcp   0.0.0.0                      1521   all       tnslsnr[1500]
       tcp   10.0.0.15                    9100   address   node_exporter[777]
       udp   127.0.0.53                   53     loopback  systemd-resolve[500]
       udp   0.0.0.0                      68     all       dhclient[650]
       udp   0.0.0.0                      5353   all       -
[CRIT] exposure
       CRIT tcp/6379 (redis-server[930]) is exposed on all interfaces - service should never be network-reachable
       WARN tcp/1521 (tnslsnr[1500]) is exposed on all interfaces - database/management service
       WARN udp/5353 (-) is exposed on all interfaces and not in --allow-ports
[OK  ] firewall
       OK   nftables: 1 input chain(s), policy drop, 4 rules
[WARN] sysctl
       WARN net.ipv4.conf.all.rp_filter = 0, expected 1 or 2: reverse path filtering (anti-spoofing)

OVERALL: CRIT
```

### Options

| Option | Default | Description |
|---|---|---|
| `--checks LIST` | all | `dns,routes,mtu,ports,exposure,firewall,tls,sysctl` |
| `--allow-ports LIST` | `22/tcp,68/udp,546/udp` | ports expected on all interfaces (`PORT` or `PORT/tcp\|udp`) |
| `--dns-name NAME` | – | resolve NAME as part of the DNS check |
| `--target HOST` | – | probe the path MTU towards HOST |
| `--tls HOST:PORT` | – | TLS endpoint to check (repeatable) |
| `--cert-warn-days N` | 21 | certificate expiry warning threshold |
| `--allow-forwarding` | off | IP forwarding is expected (router, Docker/Kubernetes host) |
| `--timeout SEC` | 5 | timeout for each network probe |
| `--format text\|json` | text | output format |
| `--no-banner` | | suppress the banner (also `NO_BANNER=1`) |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK (INFO findings do not change the exit code) |
| 1 | at least one WARNING |
| 2 | at least one CRITICAL finding |
| 3 | usage error |

The banner goes to **stderr** and only on interactive terminals – never under cron,
systemd or pipes, and never with `--format json`.

## Testing

```bash
make lint test      # ShellCheck + bats (30 tests)
```

All external commands are mocked ([`tests/mocks`](tests/mocks)); the tests run the script
with a `PATH` containing only the mocks and the required coreutils, so results never
depend on the machine running them. `/proc/sys` and `resolv.conf` are read from
fixture directories via `NSC_PROC_SYS` / `NSC_RESOLV_CONF`.

## License

[MIT](LICENSE)
