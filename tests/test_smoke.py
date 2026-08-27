from pathlib import Path

import pyunidbg

FIXTURE = Path(__file__).parent / "fixtures" / "libadd.so"


def test_real_android_arm64_emulator() -> None:
    emulator = pyunidbg.AndroidEmulator("io.pyunidbg.test")
    try:
        assert emulator.java.is64Bit()

        allocation = emulator.memory.malloc(16)
        allocation.pointer.write(b"hello")
        allocation.pointer.write_u32(8, 0x12345678)
        assert allocation.pointer.read(5) == b"hello"
        assert allocation.pointer.read_u32(8) == 0x12345678

        module = emulator.load_library(FIXTURE)
        symbol = module.java.findSymbolByName("add_numbers")
        hits: list[int] = []
        module.add_breakpoint(
            int(symbol.getAddress()) - module.base,
            lambda _emulator, address, _context: not hits.append(address),
        )
        assert int(module.call_symbol("add_numbers", 20, 22)) == 42
        assert hits == [int(symbol.getAddress())]
        assert int(module.call_offset(int(symbol.getAddress()) - module.base, 3, 4)) == 7
        assert hits == [int(symbol.getAddress()), int(symbol.getAddress())]

        string = emulator.vm.string("hello")
        values = emulator.vm.array(string, emulator.vm.integer(7), emulator.vm.boolean(True))
        assert str(string.value) == "hello"
        assert len(values.value) == 3

        emulator.vm.set_jni(pyunidbg.JniHandler())
    finally:
        emulator.close()
        emulator.close()
