package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.InstrumentCallback;

public final class BridgeInstrumentCallback extends InstrumentCallback<RegisterContext> {
    private final InstrumentDelegate delegate;

    public BridgeInstrumentCallback(InstrumentDelegate delegate) {
        this.delegate = delegate;
    }

    @Override
    public void dbiCall(Emulator<?> emulator, RegisterContext context, HookEntryInfo info) {
        delegate.onInstrument(emulator, context, info);
    }
}
