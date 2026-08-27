package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.HookContext;

public interface ReplaceDelegate {
    HookDecisionResult onCall(Emulator<?> emulator, HookContext context, long originFunction);
    void postCall(Emulator<?> emulator, HookContext context, long stateId);
}
