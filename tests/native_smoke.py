import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

source = Path(__file__).resolve().parents[1]
binary = sys.argv[1]
sys.path.insert(0, str(source))
import vpndns as v

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

with tempfile.TemporaryDirectory(prefix='vdns-native-probe-') as temp:
    paths = v.Paths(Path(temp))
    paths.prepare()
    guard = v.Guard(paths, directory=source)
    state = {'web_port': free_port(), 'plan': {'dns_address': '127.0.0.1',
             'targets': [{'address': '127.0.0.1'}]}}
    v.write_json(paths.policy, {'groups': v.DEFAULT_GROUPS, 'deny': ['probe.invalid'], 'allow': []})
    guard.seed_config(state, guard.password_hash())
    config = json.loads(paths.config.read_text())
    config['dns']['port'] = free_port()
    v.write_json(paths.config, config)
    with (Path(temp) / 'probe.log').open('w') as log:
        process = subprocess.Popen([binary, '--no-check-update', '--config', str(paths.config),
                                    '--work-dir', str(paths.data)], stdout=log, stderr=log)
        try:
            api = v.Api(paths, state)
            for _ in range(40):
                if process.poll() is not None:
                    raise RuntimeError('Isolated AdGuard exited; inspect temporary test log.')
                try:
                    status = api.call('status')
                    break
                except v.GuardError:
                    time.sleep(0.25)
            else:
                raise RuntimeError('Isolated AdGuard API startup timeout.')
            assert status['protection_enabled']
            filters = api.call('filtering/status')
            assert filters['enabled']
            assert len(filters['user_rules']) == 80
            for name in ('max.ru', 'gosuslugi.ru', 'alfabank.ru', 'probe.invalid'):
                result = api.call('filtering/check_host?name=' + name + '&qtype=A')
                assert result['reason'].startswith('Filtered'), (name, result)
            assert api.call('querylog/config')['enabled'] is False
            assert api.call('stats/config')['enabled'] is False
            # Blocked UDP DNS is answered locally; no upstream query is needed.
            label = b''.join(bytes([len(part)]) + part.encode() for part in 'probe.invalid'.split('.')) + b'\0'
            packet = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + label + b'\x00\x01\x00\x01'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(packet, ('127.0.0.1', config['dns']['port']))
                response = sock.recv(4096)
                assert response[:2] == b'\x12\x34' and response[6:8] != b'\0\0'
                assert response[-4:] == b'\0\0\0\0'
            print('PASS: official native binary starts as current user on isolated loopback high ports;')
            print('authenticated API, initial block rules, protection, disabled logs/stats and real UDP blocking verified.')
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
