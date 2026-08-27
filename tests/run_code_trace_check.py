from pathlib import Path

import pyunidbg

FIXTURE = Path(__file__).parent / "fixtures" / "libtrace.so"

with pyunidbg.AndroidEmulator("io.pyunidbg.code-trace") as emulator:
    module = emulator.load_library(FIXTURE)
    instructions = []
    trace = emulator.trace_code(
        lambda _emulator, address, _instruction: instructions.append(address),
        begin=module.base,
        end=module.base + module.size,
    )
    try:
        assert int(module.call_symbol("traced_add", 2, 3)) == 5
    finally:
        trace.stop()
    assert instructions
