package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.hookzz.HookEntryInfo;

public interface WrapDelegate {
    long preCall(Emulator<?> emulator, RegisterContext context, HookEntryInfo info);
    void postCall(Emulator<?> emulator, RegisterContext context, HookEntryInfo info, long stateId);
}
