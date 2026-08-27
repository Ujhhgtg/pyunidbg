from __future__ import annotations

import traceback
from typing import Any

import jpype

from .dvm import VM, DvmClass, DvmObject, VaList

NOT_HANDLED = object()


class JniHandler:
    def handle_jni(
        self,
        operation: str,
        vm: VM,
        target: DvmObject | DvmClass | None,
        signature: str,
        args: VaList | None,
        value: Any,
    ) -> Any:
        """Handle any unidbg Jni callback not represented by a named method.

        ``operation`` uses snake-case names such as ``call_static_float``,
        ``get_int_field``, ``set_static_object_field``, ``accept_method``, and
        ``to_reflected_method``. Return ``NOT_HANDLED`` to delegate to
        ``AbstractJni``.
        """
        return NOT_HANDLED

    def call_object_method(self, vm: VM, obj: DvmObject, signature: str, args: VaList) -> Any:
        return NOT_HANDLED

    def call_static_object_method(self, vm: VM, cls: DvmClass, signature: str, args: VaList) -> Any:
        return NOT_HANDLED

    def new_object(self, vm: VM, cls: DvmClass, signature: str, args: VaList) -> Any:
        return NOT_HANDLED

    def call_void_method(self, vm: VM, obj: DvmObject, signature: str, args: VaList) -> Any:
        return NOT_HANDLED

    def call_boolean_method(self, vm: VM, obj: DvmObject, signature: str, args: VaList) -> Any:
        return NOT_HANDLED

    def call_int_method(self, vm: VM, obj: DvmObject, signature: str, args: VaList) -> Any:
        return NOT_HANDLED

    def call_long_method(self, vm: VM, obj: DvmObject, signature: str, args: VaList) -> Any:
        return NOT_HANDLED

    def call_static_long_method(self, vm: VM, cls: DvmClass, signature: str, args: VaList) -> Any:
        return NOT_HANDLED


class _Delegate:
    def __init__(self, vm: VM, handler: JniHandler, result_class: Any):
        self.vm = vm
        self.handler = handler
        self.result = result_class

    def _object_result(self, value: Any) -> Any:
        if value is NOT_HANDLED:
            return self.result.notHandled()
        if isinstance(value, (DvmObject, DvmClass)):
            value = value.java
        if value is not None:
            value = jpype.JObject(value, jpype.JClass("java.lang.Object"))
        return self.result.handledObject(value)

    def _report_exception(self) -> None:
        import sys

        error = sys.exception()
        if error is not None:
            self.vm._emulator._capture_callback_error(error)
        traceback.print_exc()

    def callObjectMethodV(self, raw_vm: Any, raw_obj: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.call_object_method(
                self.vm, DvmObject(self.vm, raw_obj), str(signature), VaList(self.vm, raw_args)
            )
            return self._object_result(value)
        except BaseException:
            self._report_exception()
            raise

    def callStaticObjectMethodV(self, raw_vm: Any, raw_cls: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.call_static_object_method(
                self.vm, DvmClass(self.vm, raw_cls), str(signature), VaList(self.vm, raw_args)
            )
            return self._object_result(value)
        except BaseException:
            self._report_exception()
            raise

    def newObjectV(self, raw_vm: Any, raw_cls: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.new_object(
                self.vm, DvmClass(self.vm, raw_cls), str(signature), VaList(self.vm, raw_args)
            )
            return self._object_result(value)
        except BaseException:
            self._report_exception()
            raise

    def callVoidMethodV(self, raw_vm: Any, raw_obj: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.call_void_method(
                self.vm, DvmObject(self.vm, raw_obj), str(signature), VaList(self.vm, raw_args)
            )
            return self.result.notHandled() if value is NOT_HANDLED else self.result.handledVoid()
        except BaseException:
            self._report_exception()
            raise

    def callBooleanMethodV(self, raw_vm: Any, raw_obj: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.call_boolean_method(
                self.vm, DvmObject(self.vm, raw_obj), str(signature), VaList(self.vm, raw_args)
            )
            return self.result.notHandled() if value is NOT_HANDLED else self.result.handledBoolean(bool(value))
        except BaseException:
            self._report_exception()
            raise

    def callIntMethodV(self, raw_vm: Any, raw_obj: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.call_int_method(
                self.vm, DvmObject(self.vm, raw_obj), str(signature), VaList(self.vm, raw_args)
            )
            return self.result.notHandled() if value is NOT_HANDLED else self.result.handledInt(int(value))
        except BaseException:
            self._report_exception()
            raise

    def callLongMethodV(self, raw_vm: Any, raw_obj: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.call_long_method(
                self.vm, DvmObject(self.vm, raw_obj), str(signature), VaList(self.vm, raw_args)
            )
            return self.result.notHandled() if value is NOT_HANDLED else self.result.handledLong(int(value))
        except BaseException:
            self._report_exception()
            raise

    def callStaticLongMethodV(self, raw_vm: Any, raw_cls: Any, signature: str, raw_args: Any) -> Any:
        try:
            value = self.handler.call_static_long_method(
                self.vm, DvmClass(self.vm, raw_cls), str(signature), VaList(self.vm, raw_args)
            )
            return self.result.notHandled() if value is NOT_HANDLED else self.result.handledLong(int(value))
        except BaseException:
            self._report_exception()
            raise

    def dispatch(
        self,
        operation: str,
        raw_vm: Any,
        raw_target: Any,
        signature: str,
        raw_args: Any,
        raw_value: Any,
    ) -> Any:
        try:
            class_type = jpype.JClass("com.github.unidbg.linux.android.dvm.DvmClass")
            object_type = jpype.JClass("com.github.unidbg.linux.android.dvm.DvmObject")
            if raw_target is None:
                target = None
            elif isinstance(raw_target, class_type):
                target = DvmClass(self.vm, raw_target)
            elif isinstance(raw_target, object_type):
                target = DvmObject(self.vm, raw_target)
            else:
                target = raw_target
            args = None if raw_args is None else VaList(self.vm, raw_args)
            value = (
                DvmObject(self.vm, raw_value)
                if raw_value is not None and isinstance(raw_value, object_type)
                else raw_value
            )
            result = self.handler.handle_jni(
                str(operation), self.vm, target, str(signature), args, value
            )
            if result is NOT_HANDLED:
                return self.result.notHandled()
            operation = str(operation)
            if operation.startswith("set_") or operation in {
                "call_void",
                "call_static_void",
                "call_static_void_v",
            }:
                return self.result.handledVoid()
            if isinstance(result, (DvmObject, DvmClass)) or result is None:
                return self._object_result(result)
            if operation in {
                "call_static_boolean",
                "call_static_boolean_v",
                "call_boolean",
                "get_static_boolean_field",
                "get_boolean_field",
                "accept_method",
                "accept_field",
            }:
                return self.result.handledBoolean(bool(result))
            if operation in {"call_static_float", "call_float_v", "get_float_field"}:
                return self.result.handledFloat(float(result))
            if operation in {"call_static_double", "call_double"}:
                return self.result.handledDouble(float(result))
            if operation == "call_char_v":
                character = result if isinstance(result, str) else chr(int(result))
                if len(character) != 1:
                    raise ValueError("char JNI callbacks must return one character")
                return self.result.handledChar(character)
            if operation in {
                "call_static_long",
                "call_long",
                "get_static_long_field",
                "get_long_field",
            }:
                return self.result.handledLong(int(result))
            return self.result.handledInt(int(result))
        except BaseException:
            self._report_exception()
            raise


def make_bridge(vm: VM, handler: JniHandler) -> tuple[Any, tuple[Any, ...]]:
    if not isinstance(handler, JniHandler):
        raise TypeError("handler must be a JniHandler")
    cls = vm._emulator._class
    result_class = cls("io.pyunidbg.bridge.DispatchResult")
    delegate_impl = _Delegate(vm, handler, result_class)
    delegate = jpype.JProxy(
        [
            cls("io.pyunidbg.bridge.JniDelegate"),
            cls("io.pyunidbg.bridge.JniFullDelegate"),
        ],
        inst=delegate_impl,
    )
    bridge = cls("io.pyunidbg.bridge.BridgeJni")(delegate)
    return bridge, (bridge, delegate, delegate_impl, handler)
