#!/usr/bin/env python3
"""Create reproducible release archives containing no machine-local secrets."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
EXCLUDED = {'.git', '__pycache__', 'dist', '.pytest_cache'}
ROOT_FILES = {'vpndns.py', 'vpn-dns-guard', 'release.json', 'build_release.py', 'install.sh', 'bootstrap.sh',
              'README.md', 'SOURCES.md', 'LICENSE', 'NOTICE', '.gitignore', 'TESTING.md', 'CHANGELOG.md', 'SECURITY.md'}


def build(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in ROOT.rglob('*') if path.is_file() and not (ROOT in destination.parents and destination in path.parents)
                   and not any(part in EXCLUDED for part in path.relative_to(ROOT).parts)
                   and path.name != 'SHA256SUMS'
                   and (path.relative_to(ROOT).as_posix() in ROOT_FILES
                        or (path.parent == ROOT / 'lists' and path.suffix == '.txt')
                        or (path.parent == ROOT / 'tests' and (path.suffix in ('.py', '.sh') or path.name == 'Dockerfile'))
                        or (path.parent == ROOT / '.github/workflows' and path.suffix == '.yml')))
    for path in files:
        if path.is_symlink() or path.suffix in ('.vpn', '.pub', '.pem', '.key') or 'credentials' in path.name:
            raise SystemExit('Refusing sensitive/unexpected release file: ' + str(path))
    manifest = ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.relative_to(ROOT).as_posix() + '\n' for path in files)
    (ROOT / 'SHA256SUMS').write_text(manifest, encoding='utf-8', newline='\n')
    files.append(ROOT / 'SHA256SUMS')
    version = json.loads((ROOT / 'release.json').read_text())['version']
    base = 'vpn-dns-guard-v' + version
    tar_path = destination / (base + '.tar.gz')
    with open(tar_path, 'wb') as output, gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for path in sorted(files):
                content = path.read_bytes()
                name = 'vpn-dns-guard/' + path.relative_to(ROOT).as_posix()
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mode = 0o755 if path.name in ('vpn-dns-guard', 'install.sh', 'bootstrap.sh') else 0o644
                archive.addfile(info, io.BytesIO(content))
    zip_path = destination / (base + '.zip')
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            name = 'vpn-dns-guard/' + path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if path.name in ('vpn-dns-guard', 'install.sh', 'bootstrap.sh') else 0o100644) << 16
            archive.writestr(info, path.read_bytes())
    for path in (tar_path, zip_path):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        path.with_name(path.name + '.sha256').write_text(digest + '  ' + path.name + '\n', encoding='ascii')
        print(str(path) + '  SHA256=' + digest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    build(parser.parse_args().output)
