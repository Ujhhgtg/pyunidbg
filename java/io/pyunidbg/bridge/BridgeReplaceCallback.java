package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;

public final class BridgeReplaceCallback extends ReplaceCallback {
    private final ReplaceDelegate delegate;

    public BridgeReplaceCallback(ReplaceDelegate delegate) {
        this.delegate = delegate;
    }

    @Override
    public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
        HookDecisionResult result = delegate.onCall(emulator, context, originFunction);
        context.push(Long.valueOf(result.stateId));
        return result.callOriginal
                ? HookStatus.RET(emulator, originFunction)
                : HookStatus.LR(emulator, result.returnValue);
    }

    @Override
    public void postCall(Emulator<?> emulator, HookContext context) {
        long stateId = ((Number) context.pop()).longValue();
        delegate.postCall(emulator, context, stateId);
    }
}
