"""Add the published PyPI hashes to a pinned requirements file (block 7 step c, docs/block-7-plan.md).

Usage:  python scripts/hash_requirements.py requirements.txt requirements-ci.txt

For every line "name==version" (with or without a "; marker"), this asks PyPI for the SHA-256 of every
file published for exactly that version and writes them under the pin as "--hash=sha256:..." lines.
Every file of the version is covered, so the same requirements file installs on Linux (Colab, CI) and on
Windows. pip then refuses any download whose hash is not listed.

It never changes a version. Comments and blank lines are kept. Old hashes are replaced, so the script can be
run again after a version change. Standard library only. It only reads from pypi.org over HTTPS.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import sys
import urllib.parse
from pathlib import Path

PYPI_HOST = "pypi.org"
PYPI_PATH = "/pypi/{name}/{version}/json"
# "name==version" with an optional "; marker". Anything else (ranges, URLs, options) is refused.
PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.!+_-]+)\s*(?P<marker>;.*)?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def published_hashes(name: str, version: str) -> list[str]:
    """SHA-256 of every file PyPI lists for exactly this version, sorted."""
    # The connection is fixed to HTTPS and the host pypi.org. Only the path comes from the pin, and the pin
    # already passed the PIN pattern, so it cannot point anywhere else.
    path = PYPI_PATH.format(name=urllib.parse.quote(name), version=urllib.parse.quote(version))
    # Explicit certificate and host-name check (also the default on Python 3.4.3 and later).
    # Semgrep's httpsconnection-detected rule warns that Pythons before 3.4.3 did not check certificates. We
    # run 3.11+, the certificate check is set explicitly here, and the host is fixed (Sam, 19 November 2026).
    # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
    connection = http.client.HTTPSConnection(PYPI_HOST, timeout=30, context=ssl.create_default_context())
    try:
        connection.request("GET", path, headers={"User-Agent": "hash-requirements-script"})
        response = connection.getresponse()
        if response.status != 200:
            raise SystemExit(f"PyPI answered {response.status} for {name}=={version}")
        release = json.load(response)
    finally:
        connection.close()
    if release["info"]["version"] != version:
        raise SystemExit(f"PyPI returned version {release['info']['version']} for {name}=={version}")
    hashes = sorted({file["digests"]["sha256"] for file in release["urls"]})
    if not hashes or not all(SHA256.match(h) for h in hashes):
        raise SystemExit(f"No usable SHA-256 hashes on PyPI for {name}=={version}")
    return hashes


def strip_hashes(lines: list[str]) -> list[str]:
    """Remove hash lines and line continuations written by an earlier run."""
    kept = []
    for line in lines:
        if line.strip().startswith("--hash="):
            continue
        kept.append(line.rstrip().removesuffix("\\").rstrip())
    return kept


def hash_file(path: Path) -> int:
    out, pins = [], 0
    for line in strip_hashes(path.read_text(encoding="utf-8").splitlines()):
        content = line.split("#", 1)[0].strip()
        if not content:
            out.append(line)
            continue
        match = PIN.match(content)
        if not match:
            raise SystemExit(f"{path}: not an exact pin, refusing to guess: {line!r}")
        hashes = published_hashes(match["name"], match["version"])
        out.append(f"{content} \\")
        out.extend(f"    --hash=sha256:{h} \\" for h in hashes[:-1])
        out.append(f"    --hash=sha256:{hashes[-1]}")
        pins += 1
    path.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    return pins


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for arg in sys.argv[1:]:
        print(f"{arg}: hashes added for {hash_file(Path(arg))} pins")
