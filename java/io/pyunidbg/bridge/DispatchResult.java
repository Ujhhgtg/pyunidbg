package io.pyunidbg.bridge;

public final class DispatchResult {
    private static final DispatchResult NOT_HANDLED = new DispatchResult(false, null);

    public final boolean handled;
    public final Object value;

    private DispatchResult(boolean handled, Object value) {
        this.handled = handled;
        this.value = value;
    }

    public static DispatchResult notHandled() {
        return NOT_HANDLED;
    }

    public static DispatchResult handledObject(Object value) {
        return new DispatchResult(true, value);
    }

    public static DispatchResult handledVoid() {
        return new DispatchResult(true, null);
    }

    public static DispatchResult handledBoolean(boolean value) {
        return new DispatchResult(true, Boolean.valueOf(value));
    }

    public static DispatchResult handledInt(int value) {
        return new DispatchResult(true, Integer.valueOf(value));
    }

    public static DispatchResult handledLong(long value) {
        return new DispatchResult(true, Long.valueOf(value));
    }

    public static DispatchResult handledFloat(float value) {
        return new DispatchResult(true, Float.valueOf(value));
    }

    public static DispatchResult handledDouble(double value) {
        return new DispatchResult(true, Double.valueOf(value));
    }

    public static DispatchResult handledChar(char value) {
        return new DispatchResult(true, Character.valueOf(value));
    }
}
