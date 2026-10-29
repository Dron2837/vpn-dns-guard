#!/bin/sh
# Download a VERSIONED GitHub release from an explicitly selected repository.
# This file does not run anything until every release checksum is validated.
set -eu
umask 077
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run in the Ubuntu server owner console as root.' >&2
  exit 1
fi
if [ "$#" -ne 2 ]; then
  echo 'Usage: sh bootstrap.sh OWNER/REPOSITORY v0.1.0' >&2
  exit 1
fi
REPO=$1
TAG=$2
case "$REPO" in *[!A-Za-z0-9_.\/-]*|/*|*/|*/*/*|*/../*|../*) echo 'Invalid repository.' >&2; exit 1;; esac
case "$REPO" in */*) ;; *) echo 'Expected OWNER/REPOSITORY.' >&2; exit 1;; esac
case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo 'Use an explicit version tag.' >&2; exit 1;; esac
case "$TAG" in *[!A-Za-z0-9_.-]*) echo 'Invalid tag.' >&2; exit 1;; esac
for TOOL in curl python3 sha256sum; do
  command -v "$TOOL" >/dev/null || { echo "Missing: $TOOL" >&2; exit 1; }
done
VDG_TMP=$(mktemp -d /var/tmp/vpn-dns-guard-release.XXXXXXXX)
trap 'rm -rf -- "$VDG_TMP"' EXIT HUP INT TERM
ASSET="vpn-dns-guard-${TAG}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$TAG"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 180 "$BASE/$ASSET" -o "$VDG_TMP/$ASSET"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 30 "$BASE/$ASSET.sha256" -o "$VDG_TMP/$ASSET.sha256"
cd "$VDG_TMP"
# Validate the digest and expected basename without trusting paths in a manifest.
python3 - "$ASSET" <<'PY'
import hashlib,pathlib,re,sys,tarfile
asset=sys.argv[1]
line=pathlib.Path(asset+'.sha256').read_text().strip()
match=re.fullmatch(r'([0-9a-f]{64})  '+re.escape(asset),line)
if not match or hashlib.sha256(pathlib.Path(asset).read_bytes()).hexdigest()!=match.group(1):
    raise SystemExit('Release checksum mismatch; nothing executed.')
with tarfile.open(asset,'r:gz') as archive:
    members=archive.getmembers()
    for member in members:
        parts=pathlib.PurePosixPath(member.name).parts
        if not parts or parts[0]!='vpn-dns-guard' or '..' in parts or '\\' in member.name or not (member.isdir() or member.isfile()):
            raise SystemExit('Unsafe archive layout; nothing extracted.')
    archive.extractall('.',members=members,filter='data')
PY
sh ./vpn-dns-guard/install.sh
