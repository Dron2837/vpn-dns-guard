#!/bin/bash
# NEVER run this script on a real VPN server.
set -Eeuo pipefail
if [[ ${GITHUB_ACTIONS:-} != true || ${VDNS_ALLOW_PRIVILEGED_TESTS:-} != 1 || $EUID -ne 0 ]]; then
  echo 'Refusing: this test requires an explicitly selected disposable GitHub Actions runner.' >&2
  exit 1
fi
VDNS_NET=amnezia-dns-vdns-test
VDNS_IMAGE=amnezia-vdns-fixture:integration
VDNS_AWG=vdns-fixture-awg
VDNS_WG=vdns-fixture-wg
cleanup() {
  result=$?
  if [[ $result -ne 0 ]]; then
    echo "Integration failed (exit $result); collecting test-only diagnostics."
    for container in "$VDNS_AWG" "$VDNS_WG"; do
      docker logs "$container" 2>&1 || true
      docker exec "$container" ip -4 address 2>&1 || true
      docker exec "$container" iptables -t nat -S 2>&1 || true
    done
    journalctl --no-pager -n 60 -u vpn-dns-guard.service -u vpn-dns-guard-adguard.service || true
  fi
  if command -v vpn-dns-guard >/dev/null; then vpn-dns-guard uninstall --restore-dns || true; fi
  docker rm -f "$VDNS_AWG" "$VDNS_WG" >/dev/null 2>&1 || true
  docker network rm "$VDNS_NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create --driver bridge "$VDNS_NET"
docker build -t "$VDNS_IMAGE" -f tests/Dockerfile tests
docker run -d --privileged --name "$VDNS_AWG" --network "$VDNS_NET" \
  -e VDNS_INTERFACE=awg0 -e VDNS_GATEWAY=10.66.1.1 -e VDNS_CLIENT=10.66.1.8 -e VDNS_SUBNET=10.66.1.0/24 "$VDNS_IMAGE"
docker run -d --privileged --name "$VDNS_WG" --network "$VDNS_NET" \
  -e VDNS_INTERFACE=wg0 -e VDNS_GATEWAY=10.67.1.1 -e VDNS_CLIENT=10.67.1.8 -e VDNS_SUBNET=10.67.1.0/24 "$VDNS_IMAGE"
for i in {1..15}; do
  if docker exec "$VDNS_AWG" ip netns exec client ip route show >/dev/null 2>&1 \
    && docker exec "$VDNS_WG" ip netns exec client ip route show >/dev/null 2>&1; then break; fi
  sleep 1
done
sh ./install.sh --network "$VDNS_NET"
vpn-dns-guard doctor
dns() {
  docker exec "$1" ip netns exec client dig +time=2 +tries=1 +short @1.1.1.1 "$2" "${3:-A}" "${4:-+notcp}"
}
for container in "$VDNS_AWG" "$VDNS_WG"; do
  [[ $(dns "$container" max.ru) == 0.0.0.0 ]]
  [[ $(dns "$container" gosuslugi.ru) == 0.0.0.0 ]]
  [[ $(dns "$container" alfabank.ru) == 0.0.0.0 ]]
  [[ $(dns "$container" max.ru AAAA) == :: ]]
  [[ $(dns "$container" max.ru A +tcp) == 0.0.0.0 ]]
  answer=$(dns "$container" example.com)
  [[ -n $answer && $answer != 0.0.0.0 ]]
done
# A repeated install must not duplicate rules or restart VPN containers.
before=$(docker inspect --format '{{.State.StartedAt}}' "$VDNS_AWG")
sh ./install.sh --network "$VDNS_NET"
[[ $(docker inspect --format '{{.State.StartedAt}}' "$VDNS_AWG") == "$before" ]]
# Stop only test-managed services. Guard must survive.
systemctl stop vpn-dns-guard.service vpn-dns-guard-adguard.service
nft list table inet vpn_dns_guard
if dns "$VDNS_AWG" example.com; then
  echo 'DNS unexpectedly succeeded with AdGuard stopped.' >&2; exit 1
fi
# Remove container-local redirect to exercise the separate host guard.
for proto in udp tcp; do
  docker exec "$VDNS_AWG" iptables -t nat -D PREROUTING -i awg0 -s 10.66.1.0/24 -p "$proto" --dport 53 -j VDNS_DNS
done
if dns "$VDNS_AWG" example.com; then
  echo 'Public DNS escaped the host guard.' >&2; exit 1
fi
systemctl start vpn-dns-guard-adguard.service vpn-dns-guard.service
for i in {1..40}; do
  answer=$(dns "$VDNS_AWG" max.ru 2>/dev/null || true)
  [[ $answer == 0.0.0.0 ]] && break
  sleep 1
done
[[ $answer == 0.0.0.0 ]]
# Only disposable fixture is restarted; interception must recover without leakage.
docker restart "$VDNS_AWG"
for i in {1..45}; do
  answer=$(dns "$VDNS_AWG" max.ru 2>/dev/null || true)
  [[ -z $answer || $answer == 0.0.0.0 ]] || { echo 'Leak after fixture restart.' >&2; exit 1; }
  [[ $answer == 0.0.0.0 ]] && break
  sleep 1
done
[[ $answer == 0.0.0.0 ]]
vpn-dns-guard uninstall --restore-dns
[[ -n $(dns "$VDNS_AWG" example.com) ]]
echo 'PASS: real DNS UDP/TCP/AAAA, strict failure, host guard, recreation, idempotence, explicit uninstall.'
