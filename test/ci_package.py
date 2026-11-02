#!/usr/bin/env python3
"""Package only the executable, license, explicit runtime metadata and checksums."""
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    target = sys.argv[1]
    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
        raise ValueError('unsupported release target')
    binary = ROOT / 'target' / target / 'release/cap-server'
    license_file = ROOT / 'LICENSE'
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('invalid git SHA')
    ldd = subprocess.check_output(['ldd', str(binary)], text=True)
    if 'not found' in ldd:
        raise RuntimeError('unresolved shared library')
    metadata = {
        'target': target, 'git_sha': sha,
        'rust': subprocess.check_output(['rustc', '--version'], text=True).strip(),
        'runtime': 'GNU dynamically linked build on Ubuntu 24.04 (glibc 2.39). Not fully static. '
                   'Use Ubuntu 24.04 or a compatible newer glibc environment with the listed '
                   'shared libraries. Older distributions are not supported by this artifact; '
                   'rebuild there if required. Redis >=7 with ACL support is required at runtime.',
        'ldd': ldd,
    }
    files = {'cap-server': binary.read_bytes(), 'LICENSE': license_file.read_bytes(),
             'runtime.json': (json.dumps(metadata, indent=2) + '\n').encode()}
    files['SHA256SUMS'] = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n'
                                for name, data in files.items()).encode()
    out = ROOT / 'ci-artifacts'
    out.mkdir(exist_ok=True)
    archive = out / f'cap-server-{target}.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name == 'cap-server' else 0o644
            tar.addfile(info, io.BytesIO(data))
    archive.with_suffix('.gz.sha256').write_text(
        f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
    print('Packaged', archive.name, 'members:', ', '.join(files))


if __name__ == '__main__':
    main()
