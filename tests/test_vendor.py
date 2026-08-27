import hashlib
from pathlib import Path

import pyunidbg


def test_vendored_artifact_manifest() -> None:
    vendor = Path(pyunidbg.__file__).resolve().parent / "_vendor"
    for line in (vendor / "manifest.sha256").read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        path = vendor / relative
        assert path.is_file(), relative
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, relative
