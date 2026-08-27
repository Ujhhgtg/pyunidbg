package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.hookzz.HookEntryInfo;

public interface InstrumentDelegate {
    void onInstrument(Emulator<?> emulator, RegisterContext context, HookEntryInfo info);
}
