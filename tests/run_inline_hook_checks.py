from pathlib import Path

import pyunidbg

FIXTURE = Path(__file__).parent / "fixtures" / "libadd.so"


def main() -> None:
    with pyunidbg.AndroidEmulator("io.pyunidbg.debug-hook") as emulator:
        module = emulator.load_library(FIXTURE)
        debug_hook = emulator.hooks.debug(
            lambda *_args: None,
            lambda *_args: None,
            begin=module.base,
            end=module.base + module.size,
        )
        assert debug_hook.active
        debug_hook.close()

    with pyunidbg.AndroidEmulator("io.pyunidbg.dobby-replace") as emulator:
        module = emulator.load_library(FIXTURE)
        calls = []
        emulator.inline.dobby.replace(
            module.find_symbol("add_numbers"),
            lambda _emulator, context, _origin: calls.append(
                (context.long_arg(0), context.long_arg(1))
            )
            or pyunidbg.HookDecision.return_value(99),
        )
        assert int(module.call_symbol("add_numbers", 2, 3)) == 99
        assert calls == [(2, 3)]

    with pyunidbg.AndroidEmulator("io.pyunidbg.dobby-post") as emulator:
        module = emulator.load_library(FIXTURE)
        post = []
        emulator.inline.dobby.replace(
            module.find_symbol("add_numbers"),
            lambda _emulator, context, _origin: (
                pyunidbg.HookDecision.original(),
                (context.long_arg(0), context.long_arg(1)),
            ),
            post_call=lambda _emulator, context, state: post.append(
                (state, context.long_arg(0))
            ),
        )
        assert int(module.call_symbol("add_numbers", 4, 7)) == 11
        assert post == [((4, 7), 11)]

    with pyunidbg.AndroidEmulator("io.pyunidbg.hookzz") as emulator:
        module = emulator.load_library(FIXTURE)
        wrapped = []
        emulator.inline.hookzz.wrap(
            module.find_symbol("add_numbers"),
            lambda _emulator, context, _info: (
                context.long_arg(0),
                context.long_arg(1),
            ),
            after=lambda _emulator, context, _info, state: wrapped.append(
                (state, context.long_arg(0))
            ),
        )
        assert int(module.call_symbol("add_numbers", 6, 8)) == 14
        assert wrapped == [((6, 8), 14)]

    with pyunidbg.AndroidEmulator("io.pyunidbg.instrument") as emulator:
        module = emulator.load_library(FIXTURE)
        instrumented = []
        emulator.inline.dobby.instrument(
            module.find_symbol("add_numbers"),
            lambda _emulator, context, _info: instrumented.append(context.long_arg(0)),
        )
        assert int(module.call_symbol("add_numbers", 3, 5)) == 8
        assert instrumented == [3]

    with pyunidbg.AndroidEmulator("io.pyunidbg.whale") as emulator:
        module = emulator.load_library(FIXTURE)
        emulator.inline.whale.replace(
            module.find_symbol("add_numbers"),
            lambda _emulator, _context, _origin: pyunidbg.HookDecision.return_value(55),
        )
        assert int(module.call_symbol("add_numbers", 1, 2)) == 55

    with pyunidbg.AndroidEmulator("io.pyunidbg.xhook") as emulator:
        module = emulator.load_library(FIXTURE)
        value = emulator.memory.malloc(16)
        value.pointer.write(b"hello\0")
        assert int(module.call_symbol("call_strlen", value.pointer)) == 5
        seen = []
        emulator.inline.xhook.register(
            "libadd.so",
            "strlen",
            lambda _emulator, context, _origin: seen.append(
                context.pointer_arg(0).read(5)
            )
            or pyunidbg.HookDecision.return_value(77),
        )
        emulator.inline.xhook.refresh()
        assert int(module.call_symbol("call_strlen", value.pointer)) == 77
        assert seen == [b"hello"]

    with pyunidbg.AndroidEmulator("io.pyunidbg.svc-replace") as emulator:
        module = emulator.load_library(FIXTURE)
        service = emulator.register_svc(lambda _emulator: 88, name="replacement")
        emulator.inline.dobby.replace_svc(module.find_symbol("add_numbers"), service)
        assert int(module.call_symbol("add_numbers", 1, 2)) == 88

    with pyunidbg.AndroidEmulator("io.pyunidbg.inline-error") as emulator:
        module = emulator.load_library(FIXTURE)

        def fail(*_args):
            raise RuntimeError("inline hook boom")

        emulator.inline.dobby.replace(module.find_symbol("add_numbers"), fail)
        try:
            module.call_symbol("add_numbers", 1, 2)
        except RuntimeError as error:
            assert str(error) == "inline hook boom"
        else:
            raise AssertionError("inline callback error was not propagated")


if __name__ == "__main__":
    main()
