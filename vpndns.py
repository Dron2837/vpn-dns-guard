#!/usr/bin/env python3
"""VPN DNS Guard: a fail-closed DNS layer for existing Amnezia containers.

Standard library only. Supported installation target: Ubuntu 24.04 / Python
3.12, systemd, Docker bridge networks, IPv4 WG/AWG tunnels. No VPN restart.
"""
import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

VERSION = '0.1.0'
SCHEMA = 1
SOURCE = Path(__file__).resolve().parent
TABLE = 'vpn_dns_guard'
NAT_CHAIN = 'VDNS_DNS'
BEGIN = '! BEGIN VPN-DNS-GUARD MANAGED RULES'
END = '! END VPN-DNS-GUARD MANAGED RULES'
ACCOUNT = 'vdns-guard'
AGH_UNIT = 'vpn-dns-guard-adguard.service'
GUARD_UNIT = 'vpn-dns-guard-firewall.service'
MONITOR_UNIT = 'vpn-dns-guard.service'
UNITS = (AGH_UNIT, GUARD_UNIT, MONITOR_UNIT)
DEFAULT_GROUPS = ['services', 'banks', 'gosuslugi']
STOP = threading.Event()


class GuardError(RuntimeError):
    pass


def canonical_domain(value):
    value = value.strip().rstrip('.').lower()
    if not value or any(c in value for c in '/:@*^|\\ \t\r\n'):
        raise GuardError('Expected a domain name, not a URL, IP, wildcard or rule.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise GuardError('Use domain names; direct IP blocking is not supported.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as error:
        raise GuardError('Invalid domain.') from error
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        raise GuardError('Invalid domain name.')
    return value


def valid_name(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
        raise GuardError('Unexpected Docker object name.')
    return value


def valid_interface(value):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value):
        raise GuardError('Unexpected interface name.')
    return value


def read_json(path, default=None):
    if not path.exists() and default is not None:
        return default
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise GuardError('Cannot read valid JSON: ' + str(path)) from error


def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise GuardError('Refusing a symlink at a managed file: ' + str(path))
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(descriptor, mode) if hasattr(os, 'fchmod') else None
        content = text.encode('utf-8') if isinstance(text, str) else text
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2, ensure_ascii=True) + '\n')


class Paths:
    def __init__(self, root=Path('/')):
        self.root = Path(root)
        self.prefix = self.root / 'opt/vpn-dns-guard'
        self.app = self.prefix / 'app'
        self.binary = self.prefix / 'bin/AdGuardHome'
        self.data = self.root / 'var/lib/vpn-dns-guard'
        self.admin = self.root / 'var/lib/vpn-dns-guard-admin'
        self.state = self.admin / 'state.json'
        self.policy = self.admin / 'policy.json'
        self.credentials = self.admin / 'credentials.json'
        self.config = self.data / 'AdGuardHome.yaml'
        self.logs = self.root / 'var/log/vpn-dns-guard'
        self.backups = self.root / 'var/backups/vpn-dns-guard'
        self.units = self.root / 'etc/systemd/system'
        self.dropin = self.units / 'docker.service.d/90-vpn-dns-guard.conf'
        self.cli = self.root / 'usr/local/sbin/vpn-dns-guard'
        self.runtime = self.root / 'run/vpn-dns-guard'

    def prepare(self):
        for path, mode in ((self.prefix, 0o755), (self.app, 0o755), (self.binary.parent, 0o755),
                           (self.admin, 0o700), (self.data, 0o750), (self.logs, 0o750),
                           (self.backups, 0o700), (self.runtime, 0o700)):
            if path.is_symlink():
                raise GuardError('Managed directory is a symlink: ' + str(path))
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)


class Runner:
    def run(self, args, check=True, timeout=15, data=None):
        args = [str(arg) for arg in args]
        environment = None
        if args and args[0] == 'docker':
            # Never follow an owner's unrelated remote Docker context.
            args = ['docker', '--host', 'unix:///var/run/docker.sock', *args[1:]]
            environment = dict(os.environ)
            for variable in ('DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
                environment.pop(variable, None)
        try:
            result = subprocess.run(args, input=data, text=True,
                                    capture_output=True, timeout=timeout, env=environment)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GuardError('Command unavailable or timed out: ' + str(args[0])) from error
        if check and result.returncode:
            # Never dump docker inspect, credentials or API responses into logs.
            detail = result.stderr.strip()[:400] if str(args[0]) in ('nft', 'systemctl', 'systemd-analyze') else ''
            raise GuardError('Command failed (' + str(result.returncode) + '): ' + str(args[0]) + ('; ' + detail if detail else ''))
        return result

    def has(self, executable):
        return shutil.which(executable) is not None


class Api:
    def __init__(self, paths, state):
        self.paths, self.state = paths, state
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, endpoint, data=None, timeout=4):
        credentials = read_json(self.paths.credentials)
        token = base64.b64encode((credentials['username'] + ':' + credentials['password']).encode()).decode()
        request = urllib.request.Request('http://127.0.0.1:' + str(self.state['web_port']) + '/control/' + endpoint)
        request.add_header('Authorization', 'Basic ' + token)
        if data is not None:
            request.data = json.dumps(data).encode()
            request.add_header('Content-Type', 'application/json')
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read(2 * 1024 * 1024)
        except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
            raise GuardError('Local AdGuard API unavailable: ' + endpoint.split('?')[0]) from error
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except ValueError as error:
            if data is None:
                raise GuardError('Read API returned non-JSON: ' + endpoint) from error
            if raw.strip() not in (b'OK', b'OK.'):
                raise GuardError('Unexpected write API response: ' + endpoint)
            return raw.decode().strip()


def parse_interfaces(text):
    result, name = {}, None
    for line in text.splitlines():
        header = re.match(r'^\d+:\s+([^:@\s]+)(?:@[^:]+)?:', line)
        if header:
            name = header.group(1)
            result[name] = []
        inet = re.search(r'\binet\s+([0-9.]+/\d+)', line)
        if inet and name:
            result[name].append(str(ipaddress.IPv4Interface(inet.group(1))))
    return result


def discover(runner, selected_network=None):
    rows = runner.run(['docker', 'ps', '--format', '{{json .}}']).stdout.splitlines()
    candidates = []
    for row in rows:
        item = json.loads(row)
        name, image = item.get('Names', ''), item.get('Image', '')
        if not any(token in (name + ' ' + image).lower() for token in ('amnezia', 'wireguard', 'awg')):
            continue
        name = valid_name(name)
        addresses = parse_interfaces(runner.run(['docker', 'exec', name, 'ip', '-4', 'address', 'show']).stdout)
        tunnels = [(interface, values) for interface, values in addresses.items()
                   if re.fullmatch(r'(?:awg|wg)\d+', interface) and values]
        if not tunnels:
            continue  # DNS/XRay/other Amnezia components are not WG tunnels.
        if len(tunnels) != 1:
            raise GuardError('Expected one IPv4 WG/AWG tunnel in ' + name)
        interface, values = tunnels[0]
        if len(values) != 1:
            raise GuardError('Multiple tunnel addresses require explicit support: ' + name)
        connections = json.loads(runner.run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', name]).stdout)
        candidates.append({'name': name, 'interface': valid_interface(interface),
                           'subnet': str(ipaddress.IPv4Interface(values[0]).network), 'connections': connections})
    if not candidates:
        raise GuardError('No running Amnezia WG/AWG containers found. Install/configure Amnezia first.')
    common = set.intersection(*(set(target['connections']) for target in candidates))
    if selected_network:
        common &= {selected_network}
    preferred = [name for name in common if 'amnezia' in name.lower() and 'dns' in name.lower()]
    choices = preferred or [name for name in common if name != 'bridge'] or sorted(common)
    if len(choices) != 1:
        raise GuardError('Cannot choose a unique common bridge; specify --network. Candidates: ' + ', '.join(sorted(common)))
    network_name = valid_name(choices[0])
    names = sorted(set().union(*(set(target['connections']) for target in candidates)))
    networks = []
    for name in names:
        valid_name(name)
        info = json.loads(runner.run(['docker', 'network', 'inspect', name]).stdout)[0]
        if info.get('Driver') != 'bridge':
            raise GuardError('Only bridge-networked VPN containers are supported: ' + name)
        bridge = (info.get('Options') or {}).get('com.docker.network.bridge.name')
        if not bridge:
            bridge = 'docker0' if name == 'bridge' else 'br-' + info['Id'][:12]
        subnets = [str(ipaddress.ip_network(part['Subnet'])) for part in info.get('IPAM', {}).get('Config', [])
                   if part.get('Subnet') and ipaddress.ip_network(part['Subnet']).version == 4]
        if not subnets:
            raise GuardError('Bridge has no IPv4 subnet: ' + name)
        networks.append({'name': name, 'bridge': valid_interface(bridge), 'subnets': subnets})
    dns_network = next(network for network in networks if network['name'] == network_name)
    gateway = str(ipaddress.IPv4Address(candidates[0]['connections'][network_name]['Gateway']))
    targets = []
    for candidate in candidates:
        connection = candidate['connections'][network_name]
        if str(ipaddress.IPv4Address(connection['Gateway'])) != gateway:
            raise GuardError('VPN containers disagree about the DNS-network gateway.')
        targets.append({key: candidate[key] for key in ('name', 'interface', 'subnet')})
        targets[-1]['address'] = str(ipaddress.IPv4Address(connection['IPAddress']))
    return {'dns_network': network_name, 'dns_bridge': dns_network['bridge'], 'dns_address': gateway,
            'networks': networks, 'targets': targets}


def listeners(text):
    found = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or ':' not in parts[4]:
            continue
        address, port = parts[4].rsplit(':', 1)
        if port.isdigit():
            found.append((address.strip('[]').split('%')[0], int(port)))
    return found


def occupied(found, address, port):
    return any(p == port and host in (address, '0.0.0.0', '::', '*') for host, p in found)


def choose_web_port(found, requested=None):
    values = [requested] if requested else range(3000, 3100)
    for value in values:
        if value is not None and 1024 <= int(value) <= 65535 and not occupied(found, '127.0.0.1', int(value)):
            return int(value)
    raise GuardError('No free loopback web port (3000-3099); specify --web-port.')


def platform_info():
    info = {}
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                info[key] = value.strip('"')
    except OSError:
        pass
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    return info, arch


def available_memory():
    try:
        values = dict((line.split(':', 1)[0], int(line.split()[1])) for line in Path('/proc/meminfo').read_text().splitlines())
        return values['MemAvailable'] * 1024
    except (OSError, ValueError, KeyError):
        return 0


def verify_bundle(directory):
    checksum_path = directory / 'SHA256SUMS'
    if not checksum_path.is_file():
        raise GuardError('Package SHA256SUMS is missing; use a built release archive.')
    seen = set()
    for line in checksum_path.read_text().splitlines():
        digest, separator, relative = line.partition('  ')
        parts = PurePosixPath(relative).parts
        if not separator or not re.fullmatch(r'[0-9a-f]{64}', digest) or not parts or '..' in parts or relative.startswith('/') or '\\' in relative:
            raise GuardError('Invalid package checksum manifest.')
        path = directory.joinpath(*parts)
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise GuardError('Package checksum mismatch: ' + relative)
        seen.add(relative)
    required = {'vpndns.py', 'vpn-dns-guard', 'release.json', 'lists/services.txt', 'lists/banks.txt', 'lists/gosuslugi.txt'}
    if not required <= seen:
        raise GuardError('Package manifest omits required files.')
    return sorted(seen)


def group_domains(directory, group):
    if group not in DEFAULT_GROUPS:
        raise GuardError('Unknown list group: ' + group)
    path = directory / 'lists' / (group + '.txt')
    result = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            continue
        if not line.startswith('||') or not line.endswith('^'):
            raise GuardError('Unsupported rule in ' + path.name)
        result.append(canonical_domain(line[2:-1]))
    return result


def compile_rules(directory, policy):
    roots = set(policy.get('deny', []))
    for group in policy['groups']:
        roots.update(group_domains(directory, group))
    rules = ['||' + canonical_domain(root) + '^' for root in sorted(roots)]
    rules += ['@@||' + canonical_domain(root) + '^' for root in sorted(set(policy.get('allow', [])))]
    return rules


def without_managed(rules):
    if BEGIN not in rules and END not in rules:
        return list(rules)
    if rules.count(BEGIN) != 1 or rules.count(END) != 1 or rules.index(END) < rules.index(BEGIN):
        raise GuardError('Managed rule markers are damaged; existing rules were not overwritten.')
    return rules[:rules.index(BEGIN)] + rules[rules.index(END) + 1:]


def firewall_text(plan):
    address = str(ipaddress.IPv4Address(plan['dns_address']))
    sources = ', '.join(str(ipaddress.IPv4Address(target['address'])) for target in plan['targets'])
    bridges = ', '.join(json.dumps(valid_interface(network['bridge'])) for network in plan['networks'])
    subnets = ', '.join(sorted({str(ipaddress.IPv4Network(subnet)) for network in plan['networks'] for subnet in network['subnets']}))
    bridge = json.dumps(valid_interface(plan['dns_bridge']))
    return f'''table inet {TABLE} {{
  set vpn_sources {{ type ipv4_addr; elements = {{ {sources} }}; }}
  chain input {{
    type filter hook input priority -20; policy accept;
    ip daddr {address} iifname {bridge} ip saddr @vpn_sources meta l4proto {{ tcp, udp }} th dport 53 accept
    ip daddr {address} meta l4proto {{ tcp, udp }} th dport 53 counter drop
  }}
  chain forward {{
    type filter hook forward priority -20; policy accept;
    iifname {{ {bridges} }} meta l4proto {{ tcp, udp }} th dport 53 ct direction original counter drop
    ip saddr {{ {subnets} }} meta l4proto {{ tcp, udp }} th dport 53 ct direction original counter drop
  }}
}}
'''


def unit_texts(paths):
    python = '/usr/bin/python3 ' + str(paths.app / 'vpndns.py')
    return {
        GUARD_UNIT: f'''[Unit]
Description=VPN DNS Guard strict firewall
Before=docker.service {AGH_UNIT} {MONITOR_UNIT}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={python} guard
# No ExecStop: stopping a process must not open external DNS.
[Install]
WantedBy=multi-user.target
''',
        AGH_UNIT: f'''[Unit]
Description=Private AdGuard Home for VPN DNS Guard
Requires={GUARD_UNIT}
After=docker.service network-online.target {GUARD_UNIT}
Wants=network-online.target
[Service]
User={ACCOUNT}
Group={ACCOUNT}
ExecStartPre=/usr/bin/test -f {paths.config}
ExecStart={paths.binary} --no-check-update --config {paths.config} --work-dir {paths.data}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths={paths.data} {paths.logs}
UMask=0077
MemoryAccounting=true
MemoryHigh=128M
MemoryMax=192M
TasksMax=128
[Install]
WantedBy=multi-user.target
''',
        MONITOR_UNIT: f'''[Unit]
Description=VPN DNS Guard strict DNS supervisor
Requires={GUARD_UNIT}
Wants={AGH_UNIT}
After=docker.service {AGH_UNIT} {GUARD_UNIT}
[Service]
Type=simple
ExecStart={python} monitor
Restart=on-failure
RestartSec=5
TimeoutStopSec=45
RuntimeDirectory=vpn-dns-guard
RuntimeDirectoryMode=0700
Environment=DOCKER_CONFIG=/run/vpn-dns-guard/docker-config
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={paths.admin}
UMask=0077
MemoryAccounting=true
MemoryMax=96M
CPUWeight=50
[Install]
WantedBy=multi-user.target
'''}


class Guard:
    def __init__(self, paths=None, runner=None, directory=None, api_factory=None):
        self.p = paths or Paths()
        self.r = runner or Runner()
        self.directory = Path(directory or SOURCE)
        self.api_factory = api_factory or (lambda state: Api(self.p, state))

    def state(self):
        state = read_json(self.p.state)
        if state.get('schema') != SCHEMA or state.get('owner') != 'vpn-dns-guard':
            raise GuardError('Unsupported or unmanaged installation state.')
        return state

    def save(self, state):
        write_json(self.p.state, state)

    @contextlib.contextmanager
    def lock(self):
        import fcntl
        self.p.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(self.p.runtime / 'lock', 'a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def api(self, state):
        return self.api_factory(state)

    def preflight(self, network=None, web_port=None, resuming=False):
        info, arch = platform_info()
        if info.get('ID') != 'ubuntu' or info.get('VERSION_ID') != '24.04' or arch is None:
            raise GuardError('Supported: Ubuntu 24.04 LTS, amd64 or arm64.')
        if sys.version_info[:2] != (3, 12):
            raise GuardError('Use the Ubuntu 24.04 system Python 3.12.')
        required = ['docker', 'ip', 'ss', 'nft', 'systemctl', 'systemd-analyze', 'useradd', 'getent', 'runuser', 'chown']
        missing = [name for name in required if not self.r.has(name)]
        if missing:
            raise GuardError('Missing system tools: ' + ', '.join(missing) + '. No packages were installed automatically.')
        self.r.run(['docker', 'info', '--format', '{{.ServerVersion}}'])
        self.r.run(['nft', 'list', 'tables'])
        if not resuming:
            for legacy in ('codex-adguardhome.service', 'AdGuardHome.service', 'adguardhome.service'):
                if self.r.run(['systemctl', 'is-active', '--quiet', legacy], check=False).returncode == 0:
                    raise GuardError('Existing AdGuard installation detected (' + legacy + '). Automatic migration is intentionally refused.')
            if available_memory() < 256 * 1024 * 1024:
                raise GuardError('At least 256 MiB MemAvailable is required for installation.')
            if shutil.disk_usage('/').free < 512 * 1024 * 1024:
                raise GuardError('At least 512 MiB free disk space is required.')
        plan = discover(self.r, network)
        for target in plan['targets']:
            self.nat(target, '-S', 'PREROUTING')
            if not resuming and self.nat(target, '-S', NAT_CHAIN, check=False).returncode == 0:
                raise GuardError('Container chain name already exists; nothing overwritten: ' + target['name'])
        found = listeners(self.r.run(['ss', '-H', '-lntu']).stdout)
        if not resuming and occupied(found, plan['dns_address'], 53):
            raise GuardError('DNS bind address is occupied; no resolver was disabled.')
        return plan, (int(web_port) if resuming and web_port else choose_web_port(found, web_port)), arch

    def backup(self, label, state=None, extra=None):
        self.p.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder = Path(tempfile.mkdtemp(prefix=label + '-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-', dir=self.p.backups))
        folder.chmod(0o700)
        if state is not None:
            write_json(folder / 'state.json', state)
        for name, source in [('policy.json', self.p.policy), ('AdGuardHome.yaml', self.p.config)]:
            if source.is_file():
                atomic_write(folder / name, source.read_text())
        if extra is not None:
            write_json(folder / 'details.json', extra)
        return str(folder)

    def guard(self, state, replace=False):
        if not state.get('enabled'):
            return
        exists = self.r.run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0
        if exists and not replace:
            return
        script = ('delete table inet ' + TABLE + '\n' if exists else '') + firewall_text(state['plan'])
        self.r.run(['nft', '--check', '--file', '-'], data=script)
        self.r.run(['nft', '--file', '-'], data=script)

    def nat(self, target, *args, check=True):
        return self.r.run(['docker', 'exec', valid_name(target['name']), 'iptables', '-w', '3', '-t', 'nat', *args], check=check)

    @staticmethod
    def jump(target, proto):
        return ['PREROUTING', '-i', valid_interface(target['interface']), '-s', str(ipaddress.IPv4Network(target['subnet'])),
                '-p', proto, '--dport', '53', '-j', NAT_CHAIN]

    def redirect(self, target):
        if self.nat(target, '-S', NAT_CHAIN, check=False).returncode:
            self.nat(target, '-N', NAT_CHAIN)
        for proto in ('udp', 'tcp'):
            rule = [NAT_CHAIN, '-p', proto, '--dport', '53', '-j', 'DNAT', '--to-destination', self._dns_address + ':53']
            if self.nat(target, '-C', *rule, check=False).returncode:
                self.nat(target, '-A', *rule)
        for proto in ('udp', 'tcp'):
            rule = self.jump(target, proto)
            if self.nat(target, '-C', *rule, check=False).returncode:
                self.nat(target, '-I', rule[0], '1', *rule[1:])

    def remove_redirect(self, target):
        running = self.r.run(['docker', 'inspect', '--format', '{{.State.Running}}', target['name']], check=False)
        if running.returncode or running.stdout.strip() != 'true':
            return
        for proto in ('udp', 'tcp'):
            rule = self.jump(target, proto)
            while self.nat(target, '-C', *rule, check=False).returncode == 0:
                self.nat(target, '-D', *rule)
        if self.nat(target, '-S', NAT_CHAIN, check=False).returncode == 0:
            self.nat(target, '-F', NAT_CHAIN)
            self.nat(target, '-X', NAT_CHAIN)

    def refresh_addresses(self, state):
        targets = state['plan']['targets']
        fresh, changed = [], False
        for target in targets:
            result = self.r.run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', target['name']], check=False)
            if result.returncode:
                fresh.append(target)
                continue
            networks = json.loads(result.stdout)
            connection = networks.get(state['plan']['dns_network'])
            if not connection or connection.get('Gateway') != state['plan']['dns_address']:
                raise GuardError('VPN network topology changed; run check and review. Strict rules retained.')
            address = str(ipaddress.IPv4Address(connection['IPAddress']))
            if not any(ipaddress.IPv4Address(address) in ipaddress.IPv4Network(subnet) for network in state['plan']['networks'] for subnet in network['subnets']):
                raise GuardError('New container address is outside the discovered guarded networks.')
            fresh.append(dict(target, address=address))
            changed |= address != target['address']
        if changed:
            updated = dict(state, plan=dict(state['plan'], targets=fresh))
            self.guard(updated, replace=True)
            self.api(state).call('dns_config', {'allowed_clients': [target['address'] for target in fresh]})
            state['plan'] = updated['plan']
            self.save(state)

    def sync(self, state, initial=False):
        self._dns_address = state['plan']['dns_address']
        self.guard(state)
        previous = state.get('health', {})
        results = {}
        try:
            self.refresh_addresses(state)
        except (GuardError, ValueError, KeyError) as error:
            print('Address refresh needs review: ' + str(error), flush=True)
        for target in state['plan']['targets']:
            try:
                self.redirect(target)
                answer = self.r.run(['docker', 'exec', target['name'], 'nslookup', 'example.com', self._dns_address], timeout=8).stdout
                if not re.search(r'Name:\s+example\.com', answer):
                    raise GuardError('DNS response missing')
                results[target['name']] = 'filtered'
            except (GuardError, ValueError, KeyError) as error:
                results[target['name']] = 'strict DNS unavailable: ' + str(error)
            if previous.get(target['name']) != results[target['name']]:
                print(target['name'] + ': ' + results[target['name']], flush=True)
        state['health'] = results
        self.save(state)
        if initial and any(value != 'filtered' for value in results.values()):
            raise GuardError('Initial DNS test failed. Strict rules retained; rerun install after repair.')

    def stop_unit(self, unit):
        if unit not in UNITS:
            raise GuardError('Refusing to stop an unmanaged unit.')
        result = self.r.run(['systemctl', 'disable', '--now', unit], check=False, timeout=60)
        if result.returncode not in (0, 5):
            raise GuardError('Cannot stop managed unit: ' + unit)

    def seed_config(self, state, password_hash):
        if self.p.config.exists():
            return
        policy = read_json(self.p.policy)
        config = {
            # Pinned AdGuard v0.107.79 schema.  Omitting this runs legacy
            # migrations, which can replace current querylog/statistics flags.
            'schema_version': 34,
            'http': {'address': '127.0.0.1:' + str(state['web_port'])},
            'users': [{'name': 'admin', 'password': password_hash}],
            'dns': {'bind_hosts': [state['plan']['dns_address']], 'port': 53,
                    'allowed_clients': [target['address'] for target in state['plan']['targets']],
                    'upstream_dns': ['1.1.1.1', '1.0.0.1'], 'upstream_mode': 'load_balance',
                    'cache_size': 4194304, 'ratelimit': 0, 'use_private_ptr_resolvers': False},
            'querylog': {'enabled': False, 'file_enabled': False}, 'statistics': {'enabled': False},
            'filters': [], 'whitelist_filters': [],
            'user_rules': [BEGIN, *compile_rules(self.directory, policy), END],
            'filtering': {'protection_enabled': True, 'filtering_enabled': True},
            'dhcp': {'enabled': False}, 'tls': {'enabled': False},
            'log': {'enabled': True, 'file': str(self.p.logs / 'adguard.log'),
                    'max_size': 5, 'max_backups': 2, 'max_age': 3, 'compress': True, 'verbose': False}}
        # JSON is valid YAML; AdGuard rewrites it as native YAML on later saves.
        atomic_write(self.p.config, json.dumps(config, indent=2) + '\n')

    def apply_policy(self, state, policy=None, rollback_on_error=True):
        api = self.api(state)
        policy = policy or read_json(self.p.policy)
        before = api.call('filtering/status')
        old_policy = read_json(self.p.policy)
        managed = compile_rules(self.directory, policy)
        baseline = without_managed(before['user_rules'])
        backup = self.backup('policy', state, before)
        try:
            api.call('filtering/set_rules', {'rules': baseline + [BEGIN, *managed, END]})
            api.call('filtering/config', {'enabled': True, 'interval': before['interval']})
            api.call('protection', {'enabled': True, 'duration': 0})
            api.call('cache_clear', {})
            after = api.call('filtering/status')['user_rules']
            if without_managed(after) != baseline or after.count(BEGIN) != 1:
                raise GuardError('Policy verification failed.')
            for domain in policy.get('allow', []):
                result = api.call('filtering/check_host?' + urllib.parse.urlencode({'name': domain, 'qtype': 'A'}))
                if str(result.get('reason', '')).startswith('Filtered'):
                    raise GuardError('Allow rule did not take effect: ' + domain)
            write_json(self.p.policy, policy)
        except Exception:
            if rollback_on_error:
                api.call('filtering/set_rules', {'rules': before['user_rules']})
                api.call('cache_clear', {})
                write_json(self.p.policy, old_policy)
            raise
        return len(managed), backup

    def install_binary(self, state, archive=None):
        if self.p.binary.exists():
            expected = state.get('binary_sha256')
            if expected and hashlib.sha256(self.p.binary.read_bytes()).hexdigest() == expected:
                return
            raise GuardError('Existing managed binary has an unexpected checksum.')
        release = read_json(self.directory / 'release.json')
        arch, version = state['arch'], release['adguard_version']
        expected = release['archives'][arch]
        with tempfile.TemporaryDirectory(prefix='vdns-download-') as directory:
            downloaded = Path(directory) / 'AdGuardHome.tar.gz'
            if archive:
                shutil.copyfile(archive, downloaded)
            else:
                url = f'https://github.com/AdguardTeam/AdGuardHome/releases/download/{version}/AdGuardHome_linux_{arch}.tar.gz'
                with urllib.request.urlopen(url, timeout=30) as response, open(downloaded, 'wb') as output:
                    total = 0
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > 96 * 1024 * 1024:
                            raise GuardError('Unexpectedly large AdGuard archive.')
                        output.write(chunk)
            if hashlib.sha256(downloaded.read_bytes()).hexdigest() != expected:
                raise GuardError('AdGuard archive SHA256 mismatch; archive was not executed.')
            with tarfile.open(downloaded, 'r:gz') as archive_file:
                members = [member for member in archive_file.getmembers()
                           if PurePosixPath(member.name).parts == ('AdGuardHome', 'AdGuardHome')]
                if len(members) != 1 or not members[0].isfile() or members[0].size > 128 * 1024 * 1024:
                    raise GuardError('Unexpected AdGuard archive layout.')
                content = archive_file.extractfile(members[0]).read()
            temporary = self.p.binary.with_suffix('.new')
            temporary.write_bytes(content)
            temporary.chmod(0o755)
            state['binary_sha256'] = hashlib.sha256(content).hexdigest()
            state['adguard_version'] = version
            self.save(state)
            temporary.replace(self.p.binary)

    def prepare_account(self, state):
        result = self.r.run(['getent', 'passwd', ACCOUNT], check=False)
        if result.returncode:
            state['account_intended'] = True
            self.save(state)
            self.r.run(['useradd', '--system', '--user-group', '--home-dir', str(self.p.data),
                        '--no-create-home', '--shell', '/usr/sbin/nologin', ACCOUNT])
        else:
            parts = result.stdout.strip().split(':')
            if len(parts) != 7 or int(parts[2]) == 0 or parts[5] != str(self.p.data) or parts[6] != '/usr/sbin/nologin' or not state.get('account_intended'):
                raise GuardError('Existing service account is not owned by this installation.')

    def password_hash(self):
        if self.p.credentials.exists():
            credentials = read_json(self.p.credentials)
        else:
            credentials = {'username': 'admin', 'password': secrets.token_urlsafe(24)}
            write_json(self.p.credentials, credentials)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            import crypt
            if crypt.METHOD_BLOWFISH not in crypt.methods:
                raise GuardError('System crypt lacks bcrypt; no insecure password hash was substituted.')
            hashed = crypt.crypt(credentials['password'], crypt.mksalt(crypt.METHOD_BLOWFISH))
        if not hashed or not hashed.startswith(('$2a$', '$2b$', '$2y$')):
            raise GuardError('Cannot generate a valid bcrypt password hash.')
        return hashed

    def copy_application(self, files):
        if self.directory.resolve() != self.p.app.resolve():
            for relative in files + ['SHA256SUMS']:
                source = self.directory / relative
                target = self.p.app / relative
                atomic_write(target, source.read_bytes(), 0o755 if relative in ('vpn-dns-guard', 'install.sh') else 0o644)
        wrapper = '#!/bin/sh\nexec /usr/bin/python3 ' + str(self.p.app / 'vpndns.py') + ' "$@"\n'
        atomic_write(self.p.cli, wrapper, 0o755)

    def install(self, groups, network=None, web_port=None, archive=None):
        files = verify_bundle(self.directory)
        existing = self.p.state.exists()
        if existing:
            state = self.state()
            if state.get('version') != VERSION:
                raise GuardError('A different package version is installed. Automatic version migration is not supported in v0.1.')
            if state.get('phase') == 'uninstalled':
                state['enabled'] = True
            plan, _, arch = self.preflight(state['plan']['dns_network'], state['web_port'], resuming=True)
            if plan['dns_address'] != state['plan']['dns_address'] or plan['dns_bridge'] != state['plan']['dns_bridge']:
                raise GuardError('DNS bridge topology changed; automatic migration refused.')
            state['plan'] = plan
        else:
            admin_nonempty = self.p.admin.exists() and (self.p.admin.is_symlink() or any(self.p.admin.iterdir()))
            if self.p.prefix.exists() or self.p.data.exists() or admin_nonempty:
                raise GuardError('Unmanaged files at installation paths; no files were overwritten.')
            plan, port, arch = self.preflight(network, web_port)
            if self.r.run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0:
                raise GuardError('Managed firewall table name is already in use.')
            for unit in UNITS:
                if (self.p.units / unit).exists():
                    raise GuardError('Managed unit path is already in use: ' + unit)
            if self.p.dropin.exists() or self.p.cli.exists():
                raise GuardError('Managed launcher/drop-in path already exists.')
            self.p.admin.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.p.admin.chmod(0o700)
            state = {'schema': SCHEMA, 'owner': 'vpn-dns-guard', 'version': VERSION, 'enabled': True,
                     'phase': 'prepared', 'arch': arch, 'plan': plan, 'web_port': port, 'health': {}}
            self.save(state)
        self.p.prepare()
        self.copy_application(files)
        if not self.p.policy.exists():
            write_json(self.p.policy, {'groups': groups, 'deny': [], 'allow': []})
        try:
            self.install_binary(state, archive)
            self.prepare_account(state)
            self.seed_config(state, self.password_hash())
            self.r.run(['chown', '-R', ACCOUNT + ':' + ACCOUNT, str(self.p.data), str(self.p.logs)])
            self.r.run(['runuser', '-u', ACCOUNT, '--', str(self.p.binary), '--check-config', '--config', str(self.p.config), '--work-dir', str(self.p.data)])
            state['phase'] = 'configured'
            self.save(state)
            self.backup('pre-activation', state)
            for unit, text in unit_texts(self.p).items():
                atomic_write(self.p.units / unit, text, 0o644)
            self.guard(state, replace=True)
            state['phase'] = 'guarded'
            self.save(state)
            atomic_write(self.p.dropin, '[Service]\nExecStartPre=/usr/bin/python3 ' + str(self.p.app / 'vpndns.py') + ' guard\n', 0o644)
            for unit in UNITS:
                self.r.run(['systemd-analyze', 'verify', str(self.p.units / unit)])
            self.r.run(['systemctl', 'daemon-reload'])
            for unit in (GUARD_UNIT, AGH_UNIT):
                self.r.run(['systemctl', 'enable', '--now', unit])
            last_error = None
            for _ in range(20):
                try:
                    self.api(state).call('status', timeout=2)
                    last_error = None
                    break
                except GuardError as error:
                    last_error = error
                    time.sleep(0.5)
            if last_error:
                raise last_error
            policy = read_json(self.p.policy)
            policy['groups'] = groups
            self.api(state).call('dns_config', {'allowed_clients': [target['address'] for target in state['plan']['targets']]})
            self.apply_policy(state, policy, rollback_on_error=False)
            self.sync(state, initial=True)
            state['phase'] = 'active'
            state.pop('last_error', None)
            self.save(state)
            self.r.run(['systemctl', 'enable', '--now', MONITOR_UNIT])
            print('Installed: strict DNS interception active. No Docker/VPN/network restart.')
            print('Panel: 127.0.0.1:' + str(state['web_port']) + ' via SSH tunnel only.')
            print('Credentials: vpn-dns-guard credentials (owner console only).')
        except Exception as error:
            state['phase'] = 'failed'
            state['last_error'] = str(error)[:500]
            self.save(state)
            raise GuardError('Installation incomplete; any strict rules remain. Fix the cause and rerun the SAME install command. ' + str(error)) from error

    def monitor(self):
        signal.signal(signal.SIGTERM, lambda *_: STOP.set())
        signal.signal(signal.SIGINT, lambda *_: STOP.set())
        try:
            while not STOP.is_set():
                with self.lock():
                    state = self.state()
                    if not state.get('enabled'):
                        break
                    self.sync(state)
                STOP.wait(30)
        finally:
            print('Monitor stopped. Existing strict firewall and DNS redirects are retained.', flush=True)

    def change_domain(self, kind, operation, domain):
        domain = canonical_domain(domain)
        state = self.state()
        if not state.get('enabled'):
            raise GuardError('Installation is disabled.')
        policy = read_json(self.p.policy)
        field = 'deny' if kind == 'block' else 'allow'
        values = set(policy[field])
        if operation == 'add':
            values.add(domain)
        elif domain in values:
            values.remove(domain)
        else:
            raise GuardError('No such custom entry. To exempt a built-in blocked domain, use allow add.')
        policy[field] = sorted(values)
        count, backup = self.apply_policy(state, policy)
        print('Policy applied: ' + str(count) + ' managed rules. Backup: ' + backup)

    def uninstall(self, restore_dns=False):
        if not restore_dns:
            raise GuardError('Uninstall reopens the original DNS path. Explicitly pass --restore-dns.')
        state = self.state()
        self.backup('uninstall', state)
        state['enabled'] = False
        self.save(state)
        errors = []
        for target in state['plan']['targets']:
            try:
                self.remove_redirect(target)
            except GuardError as error:
                errors.append(str(error))
        if errors:
            raise GuardError('Strict host guard retained: cannot clean container rules. ' + '; '.join(errors))
        for unit in (AGH_UNIT, GUARD_UNIT):
            self.stop_unit(unit)
        if self.p.dropin.exists():
            self.p.dropin.unlink()
        for unit in UNITS:
            path = self.p.units / unit
            if path.exists():
                path.unlink()
        self.r.run(['systemctl', 'daemon-reload'])
        if self.r.run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0:
            self.r.run(['nft', 'delete', 'table', 'inet', TABLE])
        state['phase'] = 'uninstalled'
        self.save(state)
        print('Original DNS path restored explicitly. Data, backups, account and launcher retained.')

    def status(self):
        state = self.state()
        result = {key: state.get(key) for key in ('version', 'phase', 'enabled', 'health', 'web_port', 'last_error')}
        result['services'] = {unit: self.r.run(['systemctl', 'is-active', unit], check=False).stdout.strip() for unit in UNITS}
        result['guard_present'] = self.r.run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0
        result['available_memory_mib'] = available_memory() // (1024 * 1024)
        result['plan'] = state['plan']
        return result

    def doctor(self):
        state = self.state()
        api = self.api(state)
        status = self.status()
        try:
            current = api.call('filtering/status')
            protection = bool(api.call('status')['protection_enabled'])
        except GuardError as error:
            return {'status': status, 'api_error': str(error),
                    'notice': 'Strict rules are not removed by diagnostics.'}
        expected = compile_rules(self.directory, read_json(self.p.policy))
        managed = current['user_rules']
        ok = BEGIN in managed and END in managed
        if ok:
            ok = managed[managed.index(BEGIN) + 1:managed.index(END)] == expected
        return {'status': status, 'managed_rules_match': ok,
                'filtering_enabled': bool(current['enabled']),
                'protection_enabled': protection,
                'rules': len(expected), 'query_logs_expected': 'disabled',
                'notice': 'IPv4 plain DNS in discovered VPN tunnels only; no DoH/IP-traffic blocking.'}


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument('--version', action='version', version=VERSION)
    commands = root.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check', help='Read-only environment/topology checks')
    check.add_argument('--network')
    install = commands.add_parser('install', help='Install/resume an owned installation; strict mode only')
    install.add_argument('--strict', action='store_true', help='Explicit strict mode (also the default)')
    install.add_argument('--network')
    install.add_argument('--web-port', type=int)
    install.add_argument('--groups', default=','.join(DEFAULT_GROUPS))
    install.add_argument('--offline-archive', type=Path)
    for name in ('status', 'doctor', 'backup', 'credentials', 'guard', 'monitor', 'update-lists'):
        commands.add_parser(name)
    for name in ('block', 'allow'):
        action = commands.add_parser(name)
        action.add_argument('operation', choices=['add', 'remove'])
        action.add_argument('domain')
    uninstall = commands.add_parser('uninstall')
    uninstall.add_argument('--restore-dns', action='store_true')
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    if platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise GuardError('Run this command in the Ubuntu server owner console as root. No changes made.')
    os.umask(0o077)
    guard = Guard()
    if args.command == 'check':
        if guard.p.state.exists():
            print(json.dumps(guard.doctor(), indent=2))
        else:
            plan, port, arch = guard.preflight(args.network)
            print(json.dumps({'ready': True, 'arch': arch, 'web_port': port, 'plan': plan,
                              'default_groups': DEFAULT_GROUPS, 'strict': True}, indent=2))
    elif args.command == 'guard':
        # Must not depend on the Docker API: invoked BEFORE Docker starts.
        guard.guard(guard.state())
    elif args.command == 'monitor':
        guard.monitor()
    elif args.command in ('status', 'doctor'):
        print(json.dumps(getattr(guard, args.command)(), indent=2))
    elif args.command == 'credentials':
        print(json.dumps(read_json(guard.p.credentials), indent=2))
    elif args.command == 'uninstall':
        if not args.restore_dns:
            raise GuardError('Uninstall reopens the original DNS path. Explicitly pass --restore-dns.')
        # Stop the monitor before acquiring its lock. It deliberately retains rules.
        guard.stop_unit(MONITOR_UNIT)
        with guard.lock():
            guard.uninstall(args.restore_dns)
    else:
        with guard.lock():
            if args.command == 'install':
                groups = [group.strip() for group in args.groups.split(',') if group.strip()]
                if not groups or len(groups) != len(set(groups)) or any(group not in DEFAULT_GROUPS for group in groups):
                    raise GuardError('Choose distinct groups: services,banks,gosuslugi.')
                guard.install(groups, args.network, args.web_port, args.offline_archive)
            elif args.command in ('block', 'allow'):
                guard.change_domain(args.command, args.operation, args.domain)
            elif args.command == 'backup':
                print(guard.backup('manual', guard.state()))
            elif args.command == 'update-lists':
                count, location = guard.apply_policy(guard.state())
                print('Reapplied bundled lists: ' + str(count) + ' rules; backup ' + location)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (GuardError, ValueError, KeyError, OSError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
