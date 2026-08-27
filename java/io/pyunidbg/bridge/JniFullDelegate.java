package io.pyunidbg.bridge;

import com.github.unidbg.linux.android.dvm.BaseVM;

public interface JniFullDelegate {
    DispatchResult dispatch(
            String operation,
            BaseVM vm,
            Object target,
            String signature,
            Object args,
            Object value);
}
