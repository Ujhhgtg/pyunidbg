package io.pyunidbg.bridge;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;

public final class BridgeArm64Svc extends Arm64Svc {
    private final SvcDelegate delegate;

    public BridgeArm64Svc(String name, SvcDelegate delegate) {
        super(name);
        this.delegate = delegate;
    }

    @Override
    public long handle(Emulator<?> emulator) {
        return delegate.handle(emulator);
    }

    @Override
    public void handlePreCallback(Emulator<?> emulator) {
        delegate.handlePreCallback(emulator);
    }

    @Override
    public void handlePostCallback(Emulator<?> emulator) {
        delegate.handlePostCallback(emulator);
    }
}
