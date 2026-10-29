import contextlib
import copy
import hashlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vpndns', ROOT / 'vpndns.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

ADDRS = {
    'fixture-awg': '1: lo: <LOOPBACK>\n    inet 127.0.0.1/8\n4: awg0: <UP>\n    inet 10.44.1.0/24\n',
    'fixture-wg': '1: lo: <LOOPBACK>\n    inet 127.0.0.1/8\n4: wg0: <UP>\n    inet 10.45.1.0/24\n',
    'amnezia-dns': '1: lo: <LOOPBACK>\n    inet 127.0.0.1/8\n2: eth0: <UP>\n    inet 172.28.77.254/24\n'}


def connection(address, name='amnezia-dns-net'):
    return {name: {'Gateway': '172.28.77.1', 'IPAddress': address},
            'bridge': {'Gateway': '172.19.0.1', 'IPAddress': '172.19.0.' + address.split('.')[-1]}}


class FakeApi:
    def __init__(self):
        self.rules = ['||unrelated.invalid^']
        self.enabled = True
        self.protection = True
        self.calls = []
        self.fail_once = None

    def call(self, endpoint, data=None, **kwargs):
        self.calls.append((endpoint, copy.deepcopy(data)))
        if endpoint == self.fail_once:
            self.fail_once = None
            raise v.GuardError('injected API failure')
        if endpoint == 'status':
            return {'protection_enabled': self.protection}
        if endpoint == 'filtering/status':
            return {'enabled': self.enabled, 'interval': 24, 'user_rules': self.rules.copy()}
        if endpoint == 'filtering/set_rules':
            self.rules = data['rules'].copy()
        elif endpoint == 'filtering/config':
            self.enabled = data['enabled']
        elif endpoint == 'protection':
            self.protection = data['enabled']
        elif endpoint in ('cache_clear', 'dns_config'):
            return 'OK'
        elif endpoint.startswith('filtering/check_host?'):
            query = v.urllib.parse.parse_qs(v.urllib.parse.urlsplit(endpoint).query)
            name = query['name'][0]
            allowed = [rule[4:-1] for rule in self.rules if rule.startswith('@@||')]
            blocked = [rule[2:-1] for rule in self.rules if rule.startswith('||')]
            is_allowed = any(name == root or name.endswith('.' + root) for root in allowed)
            is_blocked = any(name == root or name.endswith('.' + root) for root in blocked)
            return {'reason': 'NotFilteredWhiteList' if is_allowed else 'FilteredBlackList' if is_blocked else 'NotFilteredNotFound'}
        else:
            raise AssertionError(endpoint)


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.table = False
        self.nft_scripts = []
        self.health_fails = set()
        self.unit_states = {}
        self.missing_stop = False
        self.account = None
        self.targets = {'fixture-awg': '172.28.77.3', 'fixture-wg': '172.28.77.2'}
        self.nat_tables = {name: {'PREROUTING': [('preserve-existing-jump',)], 'UNRELATED': [('preserve-existing-rule',)]} for name in self.targets}

    def has(self, name):
        return True

    def run(self, args, check=True, timeout=15, data=None):
        args = [str(value) for value in args]
        self.calls.append(args)
        output, rc = '', 0
        if args[:2] == ['docker', 'ps']:
            output = '\n'.join(json.dumps({'Names': name, 'Image': 'amnezia-fixture'}) for name in list(self.targets) + ['amnezia-dns'])
        elif args[:2] == ['docker', 'info']:
            output = '28.0.0'
        elif args[:3] == ['docker', 'network', 'inspect']:
            name = args[3]
            output = json.dumps([{'Name': name, 'Id': 'abcd1234567890', 'Driver': 'bridge',
                                  'Options': {'com.docker.network.bridge.name': 'amn-test' if name != 'bridge' else 'docker0'},
                                  'IPAM': {'Config': [{'Subnet': '172.28.77.0/24' if name != 'bridge' else '172.19.0.0/16'}]}}])
        elif args[:2] == ['docker', 'inspect']:
            name = args[-1]
            if name not in self.targets:
                rc = 1
            elif '.State.Running' in args[3]:
                output = 'true\n'
            else:
                output = json.dumps(connection(self.targets[name]))
        elif args[:2] == ['docker', 'exec']:
            name = args[2]
            if args[3] == 'ip':
                output = ADDRS[name]
            elif args[3] == 'nslookup':
                if name in self.health_fails:
                    raise v.GuardError('simulated DNS outage')
                output = 'Name: example.com\nAddress: 192.0.2.80\n'
            elif args[3] == 'iptables':
                operation, rest = args[8], args[9:]
                name_chain = rest[0]
                table = self.nat_tables[name]
                if operation == '-S':
                    rc = int(name_chain not in table)
                elif operation == '-N':
                    table[name_chain] = []
                elif operation == '-C':
                    rc = int(tuple(rest[1:]) not in table.get(name_chain, []))
                elif operation == '-A':
                    table[name_chain].append(tuple(rest[1:]))
                elif operation == '-I':
                    table[name_chain].insert(int(rest[1]) - 1, tuple(rest[2:]))
                elif operation == '-D':
                    table[name_chain].remove(tuple(rest[1:]))
                elif operation == '-F':
                    table[name_chain].clear()
                elif operation == '-X':
                    del table[name_chain]
                else:
                    raise AssertionError(args)
            else:
                raise AssertionError(args)
        elif args[0] == 'nft':
            if args[1:3] == ['list', 'table']:
                rc = int(not self.table)
            elif args[1] == '--file':
                self.nft_scripts.append(data)
                self.table = True
            elif args[1:3] == ['delete', 'table']:
                self.table = False
        elif args[0] == 'systemctl':
            if args[1] == 'is-active':
                unit = args[-1]
                rc = 0 if self.unit_states.get(unit) == 'active' else 3
                output = 'active\n' if rc == 0 else 'inactive\n'
            elif args[1] == 'enable':
                self.unit_states[args[-1]] = 'active'
            elif args[1] == 'disable':
                self.unit_states[args[-1]] = 'inactive'
                if self.missing_stop:
                    rc = 5
        elif args[0] == 'ss':
            output = 'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n'
        elif args[0] == 'getent':
            if self.account is None:
                rc = 2
            else:
                output = self.account
        elif args[0] == 'useradd':
            home = args[args.index('--home-dir') + 1]
            self.account = 'vdns-guard:x:998:998::' + home + ':/usr/sbin/nologin\n'
        elif args[0] in ('systemd-analyze', 'runuser', 'chown'):
            pass
        else:
            raise AssertionError(args)
        result = subprocess.CompletedProcess(args, rc, output, '')
        if check and rc:
            raise v.GuardError('simulated command failure: ' + ' '.join(args))
        return result


class BasicTests(unittest.TestCase):
    def test_release_archive_contains_the_application(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([sys.executable, str(ROOT / 'build_release.py'), '--output', directory], check=True, capture_output=True)
            archive_path = Path(directory) / ('vpn-dns-guard-v' + v.VERSION + '.tar.gz')
            with tarfile.open(archive_path) as archive:
                names = set(archive.getnames())
            self.assertTrue({'vpn-dns-guard/vpndns.py', 'vpn-dns-guard/README.md',
                             'vpn-dns-guard/lists/services.txt', 'vpn-dns-guard/tests/test_guard.py'} <= names)
            self.assertGreater(len(v.verify_bundle(ROOT)), 10)

    def test_domain_validation_and_idna(self):
        self.assertEqual(v.canonical_domain('ПРИМЕР.РФ.'), 'xn--e1afmkfd.xn--p1ai')
        for value in ('http://a.ru', '1.1.1.1', 'a.ru\n||other.ru^', '*.a.ru', 'a..ru', '-x.ru', 'a.ru:53'):
            with self.subTest(value=value), self.assertRaises(v.GuardError):
                v.canonical_domain(value)

    def test_docker_context_cannot_redirect_privileged_operations(self):
        result = subprocess.CompletedProcess([], 0, '', '')
        with mock.patch.dict(v.os.environ, {'DOCKER_HOST': 'tcp://unrelated.invalid:2375', 'DOCKER_CONTEXT': 'unrelated'}), \
             mock.patch.object(v.subprocess, 'run', return_value=result) as run:
            v.Runner().run(['docker', 'ps'])
        args, kwargs = run.call_args
        self.assertEqual(args[0][:3], ['docker', '--host', 'unix:///var/run/docker.sock'])
        self.assertNotIn('DOCKER_CONTEXT', kwargs['env'])

    def test_atomic_copy_preserves_checksum_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample'
            original = b'one\r\ntwo\r\n'
            v.atomic_write(path, original)
            self.assertEqual(path.read_bytes(), original)

    def test_subnet_discovery_does_not_use_original_server(self):
        plan = v.discover(FakeRunner())
        self.assertEqual(plan['dns_address'], '172.28.77.1')
        self.assertEqual(plan['dns_bridge'], 'amn-test')
        self.assertEqual({target['subnet'] for target in plan['targets']}, {'10.44.1.0/24', '10.45.1.0/24'})
        self.assertEqual(len(plan['targets']), 2)  # Amnezia DNS component skipped.

    def test_port_conflicts_and_loopback_resolver(self):
        found = v.listeners('udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 4096 [::]:3000 [::]:*')
        self.assertFalse(v.occupied(found, '172.28.77.1', 53))
        self.assertEqual(v.choose_web_port(found), 3001)
        self.assertTrue(v.occupied([('0.0.0.0', 53)], '172.28.77.1', 53))

    def test_rule_markers_and_all_77_roots(self):
        policy = {'groups': v.DEFAULT_GROUPS, 'deny': [], 'allow': []}
        self.assertEqual(len(v.compile_rules(ROOT, policy)), 77)
        rules = ['before', v.BEGIN, 'owned', v.END, 'after']
        self.assertEqual(v.without_managed(rules), ['before', 'after'])
        with self.assertRaises(v.GuardError):
            v.without_managed([v.BEGIN, 'damaged'])

    def test_firewall_and_units_keep_strict_rules(self):
        text = v.firewall_text(v.discover(FakeRunner()))
        self.assertIn('ct direction original', text)
        self.assertNotIn('flush ruleset', text)
        self.assertIn('172.28.77.1', text)
        units = v.unit_texts(v.Paths())
        self.assertNotIn('ExecStop=', '\n'.join(line for line in units[v.GUARD_UNIT].splitlines() if not line.startswith('#')))
        self.assertIn('RuntimeDirectory=vpn-dns-guard', units[v.MONITOR_UNIT])
        self.assertNotIn('Restart=docker', ''.join(units.values()))


class StatefulTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = v.Paths(Path(self.temp.name))
        self.paths.prepare()
        self.runner = FakeRunner()
        self.api = FakeApi()
        self.guard = v.Guard(self.paths, self.runner, ROOT, lambda state: self.api)
        self.state = {'schema': 1, 'owner': 'vpn-dns-guard', 'version': v.VERSION, 'enabled': True,
                      'plan': v.discover(self.runner), 'web_port': 3000, 'health': {}, 'phase': 'active'}
        self.guard.save(self.state)
        v.write_json(self.paths.policy, {'groups': v.DEFAULT_GROUPS, 'deny': [], 'allow': []})

    def test_dns_outage_and_monitor_stop_do_not_open_public_dns(self):
        self.guard.sync(self.state, initial=True)
        snapshot = copy.deepcopy(self.runner.nat_tables)
        self.guard.sync(self.state)
        self.assertEqual(self.runner.nat_tables, snapshot)
        self.runner.health_fails.update(self.runner.targets)
        self.guard.sync(self.state)
        self.assertTrue(self.runner.table)
        self.assertEqual(self.runner.nat_tables, snapshot)
        self.assertTrue(all('unavailable' in result for result in self.state['health'].values()))
        self.runner.health_fails.clear()
        self.guard.sync(self.state)
        self.assertEqual(self.runner.nat_tables, snapshot)

    def test_recreation_recovers_rules_and_refreshes_address_acl(self):
        self.guard.sync(self.state, initial=True)
        self.runner.nat_tables['fixture-awg'] = {'PREROUTING': [('preserve-existing-jump',)], 'UNRELATED': [('preserve-existing-rule',)]}
        self.runner.targets['fixture-awg'] = '172.28.77.6'
        self.guard.sync(self.state, initial=True)
        self.assertIn(v.NAT_CHAIN, self.runner.nat_tables['fixture-awg'])
        self.assertEqual(self.state['plan']['targets'][0]['address'], '172.28.77.6')
        acl_calls = [data for endpoint, data in self.api.calls if endpoint == 'dns_config']
        self.assertIn('172.28.77.6', acl_calls[-1]['allowed_clients'])
        self.assertTrue(self.runner.table)

    def test_policy_whitelist_preservation_and_rollback(self):
        count, _ = self.guard.apply_policy(self.state)
        self.assertEqual(count, 77)
        before = self.api.rules.copy()
        self.guard.apply_policy(self.state)
        self.assertEqual(self.api.rules, before)
        self.guard.change_domain('allow', 'add', 'mail.ru')
        self.assertIn('@@||mail.ru^', self.api.rules)
        self.assertIn('||unrelated.invalid^', self.api.rules)
        before = self.api.rules.copy()
        self.api.fail_once = 'cache_clear'
        with self.assertRaises(v.GuardError):
            self.guard.change_domain('block', 'add', 'new.invalid')
        self.assertEqual(self.api.rules, before)
        self.assertNotIn('new.invalid', v.read_json(self.paths.policy)['deny'])

    def test_explicit_uninstall_only_and_preserve_other_rules(self):
        self.guard.sync(self.state, initial=True)
        self.paths.dropin.parent.mkdir(parents=True, exist_ok=True)
        self.paths.dropin.write_text('test-owned-dropin')
        with self.assertRaises(v.GuardError):
            self.guard.uninstall(False)
        self.assertTrue(self.runner.table)
        self.runner.missing_stop = True
        self.guard.uninstall(True)
        self.assertFalse(self.runner.table)
        for table in self.runner.nat_tables.values():
            self.assertEqual(table, {'PREROUTING': [('preserve-existing-jump',)], 'UNRELATED': [('preserve-existing-rule',)]})
        self.assertEqual(self.guard.state()['phase'], 'uninstalled')
        self.assertFalse(any('restart' in call for call in self.runner.calls))

    def test_json_seed_contains_rules_before_first_listener(self):
        v.write_json(self.paths.credentials, {'username': 'admin', 'password': 'test-only'})
        self.guard.seed_config(self.state, '$2b$12$test-placeholder-not-for-login')
        config = json.loads(self.paths.config.read_text())
        self.assertEqual(config['schema_version'], 34)
        self.assertEqual(config['http']['address'], '127.0.0.1:3000')
        self.assertEqual(config['dns']['bind_hosts'], ['172.28.77.1'])
        self.assertEqual(len(config['user_rules']), 79)
        self.assertFalse(config['querylog']['enabled'])
        self.assertFalse(config['statistics']['enabled'])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'not-json' if self.path.endswith('bad') else b'{"enabled":true}')
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'' if self.path.endswith('empty') else b'OK\n')
        try:
            cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        except OSError as error:
            raise unittest.SkipTest('Loopback socket unavailable: ' + str(error))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_real_http_plain_ok_empty_and_strict_get(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = v.Paths(Path(directory))
            paths.prepare()
            v.write_json(paths.credentials, {'username': 'test', 'password': 'test-only'})
            api = v.Api(paths, {'web_port': self.server.server_port})
            self.assertTrue(api.call('status')['enabled'])
            self.assertEqual(api.call('protection', {'enabled': True}), 'OK')
            self.assertIsNone(api.call('empty', {}))
            with self.assertRaises(v.GuardError): api.call('bad')


@unittest.skipUnless(platform.system() == 'Linux', 'Full filesystem install fixture uses Linux account paths')
class InstallLifecycleTests(unittest.TestCase):
    def test_interrupted_install_resume_then_idempotent_install(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = v.Paths(Path(directory))
            runner = FakeRunner()
            api = FakeApi()
            guard = v.Guard(paths, runner, ROOT, lambda state: api)
            def install_binary(state, archive=None):
                paths.binary.write_bytes(b'fixture binary')
                state['binary_sha256'] = hashlib.sha256(b'fixture binary').hexdigest()
                guard.save(state)
            guard.install_binary = install_binary
            guard.password_hash = lambda: '$2b$12$fixture-only'
            original_sync = guard.sync
            guard.sync = mock.Mock(side_effect=v.GuardError('injected interruption after guard activation'))
            with mock.patch.object(v, 'platform_info', return_value=({'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'amd64')), \
                 mock.patch.object(v, 'available_memory', return_value=400*1024*1024), \
                 mock.patch.object(v, 'verify_bundle', return_value=['vpndns.py','release.json','lists/services.txt','lists/banks.txt','lists/gosuslugi.txt']), \
                 mock.patch.object(guard, 'copy_application'):
                with self.assertRaises(v.GuardError): guard.install(v.DEFAULT_GROUPS)
                self.assertTrue(runner.table)
                self.assertEqual(guard.state()['phase'], 'failed')
                guard.sync = original_sync
                guard.install(v.DEFAULT_GROUPS)
                self.assertEqual(guard.state()['phase'], 'active')
                snapshot = copy.deepcopy(runner.nat_tables)
                guard.install(v.DEFAULT_GROUPS)
                self.assertEqual(runner.nat_tables, snapshot)
                self.assertFalse(any('restart' in call for call in runner.calls))


if __name__ == '__main__':
    unittest.main()
