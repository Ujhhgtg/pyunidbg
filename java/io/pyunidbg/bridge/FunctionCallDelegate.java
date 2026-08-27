package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;

public interface FunctionCallDelegate {
    void onCall(Emulator<?> emulator, long callerAddress, long functionAddress);
    void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args);
}
