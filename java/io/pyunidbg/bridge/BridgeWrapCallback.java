package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.WrapCallback;

public final class BridgeWrapCallback extends WrapCallback<RegisterContext> {
    private final WrapDelegate delegate;

    public BridgeWrapCallback(WrapDelegate delegate) {
        this.delegate = delegate;
    }

    @Override
    public void preCall(Emulator<?> emulator, RegisterContext context, HookEntryInfo info) {
        long stateId = delegate.preCall(emulator, context, info);
        ((com.github.unidbg.hook.InvocationContext) context).push(Long.valueOf(stateId));
    }

    @Override
    public void postCall(Emulator<?> emulator, RegisterContext context, HookEntryInfo info) {
        long stateId = ((Number) ((com.github.unidbg.hook.InvocationContext) context).pop()).longValue();
        delegate.postCall(emulator, context, info, stateId);
    }
}
