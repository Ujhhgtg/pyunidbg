package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;

public interface SvcDelegate {
    long handle(Emulator<?> emulator);
    void handlePreCallback(Emulator<?> emulator);
    void handlePostCallback(Emulator<?> emulator);
}
