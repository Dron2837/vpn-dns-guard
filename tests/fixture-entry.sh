#!/bin/sh
set -eu
# Docker restart preserves the fixture filesystem, including /run/netns mounts.
# Recreate only this disposable test namespace and its veth pair.
ip netns del client 2>/dev/null || true
ip link del "$VDNS_INTERFACE" 2>/dev/null || true
ip netns add client
ip link add "$VDNS_INTERFACE" type veth peer name client0
ip address add "$VDNS_GATEWAY/24" dev "$VDNS_INTERFACE"
ip link set "$VDNS_INTERFACE" up
ip link set client0 netns client
ip netns exec client ip link set lo up
ip netns exec client ip address add "$VDNS_CLIENT/24" dev client0
ip netns exec client ip link set client0 up
ip netns exec client ip route add default via "$VDNS_GATEWAY"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -A POSTROUTING -s "$VDNS_SUBNET" -o eth0 -j MASQUERADE
exec tail -f /dev/null
