from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

SOURCE = Path("/home/ujhhgtg/coding/wechatx_deobf/moduledata/x7_3.0")
SCRIPT = Path(__file__).parents[1] / "examples" / "wechatx_decryptor.py"
EXPECTED = {
    "C.dex": (871900, "c19f73b7b71e388efb435804dbd92e9bcd5b9ecd478cdd7af09c31f38cabc087"),
    "H_p.json": (60720, "caf77e71431ecb52abf2da26f9b2a22905987f0900433e3ceaa496fd6765c224"),
    "M.json": (43578, "dae818b3119c6b6af17afb631c19796336b405f685666d4106e3eb010cd716bc"),
    "P.json": (4586, "c285ac5ffd376b3209f48c55c6c280ed0f6e81b1c527c16961f36b36e5494edb"),
    "S.json": (314889, "3324fe4c4ccb6f51f538bf408ad80b263fe339149936c8ba8d372999711311ea"),
    "big.dex": (3172208, "d277feaa8aa6acf305f93277d6bfdc96105fca3b0440f817051c2abaa99637b2"),
    "load2.apk": (371859, "5a4b160635e731870c38bae36f2161b555f7d3282224e8e8bcd6a1278266e89a"),
    "load2_classes.dex": (862668, "ae795455cb8f3c9044fd34a37142225c7e70fb826b5ea7a3187857d9f04b478e"),
    "m1.dex": (551084, "76b7eb2b051c47c51f121f2e88998dabb6fe0f923e74ac974a02d21241fd8dd3"),
    "m2.dex": (335236, "b0a8e7807a669d21b32b610c696c0ac1573aef18105c32ed8d0e5797ae23cb67"),
    "m3.dex": (211156, "b589b3c2b94f53911cbee7a6f56f5318110870c2e38444ce0d03b0504e69ca13"),
}


@pytest.mark.skipif(not SOURCE.is_dir(), reason="local WeChatX proprietary fixtures are unavailable")
def test_wechatx_python_harness_matches_known_outputs(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source",
            str(SOURCE),
            "--work-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    output = tmp_path / "output"
    assert {path.name for path in output.iterdir()} == set(EXPECTED)
    for name, (size, expected_hash) in EXPECTED.items():
        data = (output / name).read_bytes()
        assert len(data) == size
        assert hashlib.sha256(data).hexdigest() == expected_hash
