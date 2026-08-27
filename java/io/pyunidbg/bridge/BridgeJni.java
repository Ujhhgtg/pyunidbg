package io.pyunidbg.bridge;

import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VarArg;
import com.github.unidbg.linux.android.dvm.VaList;

public final class BridgeJni extends AbstractJni {
    private final JniDelegate delegate;
    private final JniFullDelegate fullDelegate;

    public BridgeJni(JniDelegate delegate) {
        if (delegate == null) {
            throw new NullPointerException("delegate");
        }
        this.delegate = delegate;
        this.fullDelegate = (JniFullDelegate) delegate;
    }

    private DispatchResult dispatch(String operation, BaseVM vm, Object target, String signature, Object args) {
        return fullDelegate.dispatch(operation, vm, target, signature, args, null);
    }

    private DispatchResult dispatchValue(String operation, BaseVM vm, Object target, String signature, Object value) {
        return fullDelegate.dispatch(operation, vm, target, signature, null, value);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = delegate.callObjectMethodV(vm, object, signature, args);
        return result.handled ? (DvmObject<?>) result.value : super.callObjectMethodV(vm, object, signature, args);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass clazz, String signature, VaList args) {
        DispatchResult result = delegate.callStaticObjectMethodV(vm, clazz, signature, args);
        return result.handled ? (DvmObject<?>) result.value : super.callStaticObjectMethodV(vm, clazz, signature, args);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass clazz, String signature, VaList args) {
        DispatchResult result = delegate.newObjectV(vm, clazz, signature, args);
        return result.handled ? (DvmObject<?>) result.value : super.newObjectV(vm, clazz, signature, args);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = delegate.callVoidMethodV(vm, object, signature, args);
        if (!result.handled) {
            super.callVoidMethodV(vm, object, signature, args);
        }
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = delegate.callBooleanMethodV(vm, object, signature, args);
        return result.handled ? ((Boolean) result.value).booleanValue() : super.callBooleanMethodV(vm, object, signature, args);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = delegate.callIntMethodV(vm, object, signature, args);
        return result.handled ? ((Number) result.value).intValue() : super.callIntMethodV(vm, object, signature, args);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = delegate.callLongMethodV(vm, object, signature, args);
        return result.handled ? ((Number) result.value).longValue() : super.callLongMethodV(vm, object, signature, args);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass clazz, String signature, VaList args) {
        DispatchResult result = delegate.callStaticLongMethodV(vm, clazz, signature, args);
        return result.handled ? ((Number) result.value).longValue() : super.callStaticLongMethodV(vm, clazz, signature, args);
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("call_static_float", vm, clazz, signature, args);
        return result.handled ? ((Number) result.value).floatValue() : super.callStaticFloatMethod(vm, clazz, signature, args);
    }

    @Override
    public double callStaticDoubleMethod(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("call_static_double", vm, clazz, signature, args);
        return result.handled ? ((Number) result.value).doubleValue() : super.callStaticDoubleMethod(vm, clazz, signature, args);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("call_static_void", vm, clazz, signature, args);
        if (!result.handled) super.callStaticVoidMethod(vm, clazz, signature, args);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass clazz, String signature, VaList args) {
        DispatchResult result = dispatch("call_static_void_v", vm, clazz, signature, args);
        if (!result.handled) super.callStaticVoidMethodV(vm, clazz, signature, args);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("call_static_boolean", vm, clazz, signature, args);
        return result.handled ? ((Boolean) result.value).booleanValue() : super.callStaticBooleanMethod(vm, clazz, signature, args);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass clazz, String signature, VaList args) {
        DispatchResult result = dispatch("call_static_boolean_v", vm, clazz, signature, args);
        return result.handled ? ((Boolean) result.value).booleanValue() : super.callStaticBooleanMethodV(vm, clazz, signature, args);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("call_static_int", vm, clazz, signature, args);
        return result.handled ? ((Number) result.value).intValue() : super.callStaticIntMethod(vm, clazz, signature, args);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass clazz, String signature, VaList args) {
        DispatchResult result = dispatch("call_static_int_v", vm, clazz, signature, args);
        return result.handled ? ((Number) result.value).intValue() : super.callStaticIntMethodV(vm, clazz, signature, args);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("call_static_long", vm, clazz, signature, args);
        return result.handled ? ((Number) result.value).longValue() : super.callStaticLongMethod(vm, clazz, signature, args);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("call_static_object", vm, clazz, signature, args);
        return result.handled ? (DvmObject<?>) result.value : super.callStaticObjectMethod(vm, clazz, signature, args);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass clazz, String signature, VarArg args) {
        DispatchResult result = dispatch("new_object", vm, clazz, signature, args);
        return result.handled ? (DvmObject<?>) result.value : super.newObject(vm, clazz, signature, args);
    }

    @Override
    public DvmObject<?> allocObject(BaseVM vm, DvmClass clazz, String signature) {
        DispatchResult result = dispatch("alloc_object", vm, clazz, signature, null);
        return result.handled ? (DvmObject<?>) result.value : super.allocObject(vm, clazz, signature);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> object, String signature, VarArg args) {
        DispatchResult result = dispatch("call_void", vm, object, signature, args);
        if (!result.handled) super.callVoidMethod(vm, object, signature, args);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> object, String signature, VarArg args) {
        DispatchResult result = dispatch("call_boolean", vm, object, signature, args);
        return result.handled ? ((Boolean) result.value).booleanValue() : super.callBooleanMethod(vm, object, signature, args);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> object, String signature, VarArg args) {
        DispatchResult result = dispatch("call_int", vm, object, signature, args);
        return result.handled ? ((Number) result.value).intValue() : super.callIntMethod(vm, object, signature, args);
    }

    @Override
    public double callDoubleMethod(BaseVM vm, DvmObject<?> object, String signature, VarArg args) {
        DispatchResult result = dispatch("call_double", vm, object, signature, args);
        return result.handled ? ((Number) result.value).doubleValue() : super.callDoubleMethod(vm, object, signature, args);
    }

    @Override
    public byte callByteMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = dispatch("call_byte_v", vm, object, signature, args);
        return result.handled ? ((Number) result.value).byteValue() : super.callByteMethodV(vm, object, signature, args);
    }

    @Override
    public short callShortMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = dispatch("call_short_v", vm, object, signature, args);
        return result.handled ? ((Number) result.value).shortValue() : super.callShortMethodV(vm, object, signature, args);
    }

    @Override
    public char callCharMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = dispatch("call_char_v", vm, object, signature, args);
        return result.handled ? ((Character) result.value).charValue() : super.callCharMethodV(vm, object, signature, args);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args) {
        DispatchResult result = dispatch("call_float_v", vm, object, signature, args);
        return result.handled ? ((Number) result.value).floatValue() : super.callFloatMethodV(vm, object, signature, args);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> object, String signature, VarArg args) {
        DispatchResult result = dispatch("call_object", vm, object, signature, args);
        return result.handled ? (DvmObject<?>) result.value : super.callObjectMethod(vm, object, signature, args);
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> object, String signature, VarArg args) {
        DispatchResult result = dispatch("call_long", vm, object, signature, args);
        return result.handled ? ((Number) result.value).longValue() : super.callLongMethod(vm, object, signature, args);
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass clazz, String signature) {
        DispatchResult result = dispatch("get_static_boolean_field", vm, clazz, signature, null);
        return result.handled ? ((Boolean) result.value).booleanValue() : super.getStaticBooleanField(vm, clazz, signature);
    }

    @Override
    public byte getStaticByteField(BaseVM vm, DvmClass clazz, String signature) {
        DispatchResult result = dispatch("get_static_byte_field", vm, clazz, signature, null);
        return result.handled ? ((Number) result.value).byteValue() : super.getStaticByteField(vm, clazz, signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass clazz, String signature) {
        DispatchResult result = dispatch("get_static_int_field", vm, clazz, signature, null);
        return result.handled ? ((Number) result.value).intValue() : super.getStaticIntField(vm, clazz, signature);
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass clazz, String signature) {
        DispatchResult result = dispatch("get_static_long_field", vm, clazz, signature, null);
        return result.handled ? ((Number) result.value).longValue() : super.getStaticLongField(vm, clazz, signature);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass clazz, String signature) {
        DispatchResult result = dispatch("get_static_object_field", vm, clazz, signature, null);
        return result.handled ? (DvmObject<?>) result.value : super.getStaticObjectField(vm, clazz, signature);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> object, String signature) {
        DispatchResult result = dispatch("get_boolean_field", vm, object, signature, null);
        return result.handled ? ((Boolean) result.value).booleanValue() : super.getBooleanField(vm, object, signature);
    }

    @Override
    public byte getByteField(BaseVM vm, DvmObject<?> object, String signature) {
        DispatchResult result = dispatch("get_byte_field", vm, object, signature, null);
        return result.handled ? ((Number) result.value).byteValue() : super.getByteField(vm, object, signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> object, String signature) {
        DispatchResult result = dispatch("get_int_field", vm, object, signature, null);
        return result.handled ? ((Number) result.value).intValue() : super.getIntField(vm, object, signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> object, String signature) {
        DispatchResult result = dispatch("get_long_field", vm, object, signature, null);
        return result.handled ? ((Number) result.value).longValue() : super.getLongField(vm, object, signature);
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> object, String signature) {
        DispatchResult result = dispatch("get_float_field", vm, object, signature, null);
        return result.handled ? ((Number) result.value).floatValue() : super.getFloatField(vm, object, signature);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> object, String signature) {
        DispatchResult result = dispatch("get_object_field", vm, object, signature, null);
        return result.handled ? (DvmObject<?>) result.value : super.getObjectField(vm, object, signature);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> object, String signature, boolean value) {
        DispatchResult result = dispatchValue("set_boolean_field", vm, object, signature, Boolean.valueOf(value));
        if (!result.handled) super.setBooleanField(vm, object, signature, value);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> object, String signature, int value) {
        DispatchResult result = dispatchValue("set_int_field", vm, object, signature, Integer.valueOf(value));
        if (!result.handled) super.setIntField(vm, object, signature, value);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> object, String signature, long value) {
        DispatchResult result = dispatchValue("set_long_field", vm, object, signature, Long.valueOf(value));
        if (!result.handled) super.setLongField(vm, object, signature, value);
    }

    @Override
    public void setFloatField(BaseVM vm, DvmObject<?> object, String signature, float value) {
        DispatchResult result = dispatchValue("set_float_field", vm, object, signature, Float.valueOf(value));
        if (!result.handled) super.setFloatField(vm, object, signature, value);
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> object, String signature, double value) {
        DispatchResult result = dispatchValue("set_double_field", vm, object, signature, Double.valueOf(value));
        if (!result.handled) super.setDoubleField(vm, object, signature, value);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> object, String signature, DvmObject<?> value) {
        DispatchResult result = dispatchValue("set_object_field", vm, object, signature, value);
        if (!result.handled) super.setObjectField(vm, object, signature, value);
    }

    @Override
    public void setStaticBooleanField(BaseVM vm, DvmClass clazz, String signature, boolean value) {
        DispatchResult result = dispatchValue("set_static_boolean_field", vm, clazz, signature, Boolean.valueOf(value));
        if (!result.handled) super.setStaticBooleanField(vm, clazz, signature, value);
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass clazz, String signature, int value) {
        DispatchResult result = dispatchValue("set_static_int_field", vm, clazz, signature, Integer.valueOf(value));
        if (!result.handled) super.setStaticIntField(vm, clazz, signature, value);
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass clazz, String signature, long value) {
        DispatchResult result = dispatchValue("set_static_long_field", vm, clazz, signature, Long.valueOf(value));
        if (!result.handled) super.setStaticLongField(vm, clazz, signature, value);
    }

    @Override
    public void setStaticFloatField(BaseVM vm, DvmClass clazz, String signature, float value) {
        DispatchResult result = dispatchValue("set_static_float_field", vm, clazz, signature, Float.valueOf(value));
        if (!result.handled) super.setStaticFloatField(vm, clazz, signature, value);
    }

    @Override
    public void setStaticDoubleField(BaseVM vm, DvmClass clazz, String signature, double value) {
        DispatchResult result = dispatchValue("set_static_double_field", vm, clazz, signature, Double.valueOf(value));
        if (!result.handled) super.setStaticDoubleField(vm, clazz, signature, value);
    }

    @Override
    public void setStaticObjectField(BaseVM vm, DvmClass clazz, String signature, DvmObject<?> value) {
        DispatchResult result = dispatchValue("set_static_object_field", vm, clazz, signature, value);
        if (!result.handled) super.setStaticObjectField(vm, clazz, signature, value);
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass clazz, String signature) {
        DispatchResult result = dispatch("to_reflected_method", vm, clazz, signature, null);
        return result.handled ? (DvmObject<?>) result.value : super.toReflectedMethod(vm, clazz, signature);
    }

    @Override
    public boolean acceptMethod(DvmClass clazz, String signature, boolean isStatic) {
        DispatchResult result = fullDelegate.dispatch("accept_method", null, clazz, signature, null, Boolean.valueOf(isStatic));
        return result.handled ? ((Boolean) result.value).booleanValue() : super.acceptMethod(clazz, signature, isStatic);
    }

    @Override
    public boolean acceptField(DvmClass clazz, String signature, boolean isStatic) {
        DispatchResult result = fullDelegate.dispatch("accept_field", null, clazz, signature, null, Boolean.valueOf(isStatic));
        return result.handled ? ((Boolean) result.value).booleanValue() : super.acceptField(clazz, signature, isStatic);
    }
}
