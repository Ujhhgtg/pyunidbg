package io.pyunidbg.bridge;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VaList;

public interface JniDelegate {
    DispatchResult callObjectMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args);
    DispatchResult callStaticObjectMethodV(BaseVM vm, DvmClass clazz, String signature, VaList args);
    DispatchResult newObjectV(BaseVM vm, DvmClass clazz, String signature, VaList args);
    DispatchResult callVoidMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args);
    DispatchResult callBooleanMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args);
    DispatchResult callIntMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args);
    DispatchResult callLongMethodV(BaseVM vm, DvmObject<?> object, String signature, VaList args);
    DispatchResult callStaticLongMethodV(BaseVM vm, DvmClass clazz, String signature, VaList args);
}
