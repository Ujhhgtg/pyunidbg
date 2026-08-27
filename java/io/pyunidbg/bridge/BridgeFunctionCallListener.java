package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.FunctionCallListener;

public final class BridgeFunctionCallListener extends FunctionCallListener {
    private final FunctionCallDelegate delegate;

    public BridgeFunctionCallListener(FunctionCallDelegate delegate) {
        this.delegate = delegate;
    }

    @Override
    public void onCall(Emulator<?> emulator, long callerAddress, long functionAddress) {
        delegate.onCall(emulator, callerAddress, functionAddress);
    }

    @Override
    public void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args) {
        delegate.postCall(emulator, callerAddress, functionAddress, args);
    }
}
