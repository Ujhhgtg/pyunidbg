package io.pyunidbg.bridge;

public final class HookDecisionResult {
    public final boolean callOriginal;
    public final long returnValue;
    public final long stateId;

    private HookDecisionResult(boolean callOriginal, long returnValue, long stateId) {
        this.callOriginal = callOriginal;
        this.returnValue = returnValue;
        this.stateId = stateId;
    }

    public static HookDecisionResult callOriginal() {
        return callOriginal(0);
    }

    public static HookDecisionResult callOriginal(long stateId) {
        return new HookDecisionResult(true, 0, stateId);
    }

    public static HookDecisionResult returnValue(long value) {
        return returnValue(value, 0);
    }

    public static HookDecisionResult returnValue(long value, long stateId) {
        return new HookDecisionResult(false, value, stateId);
    }
}
