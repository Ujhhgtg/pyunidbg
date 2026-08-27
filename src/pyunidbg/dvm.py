from __future__ import annotations

import builtins
from typing import Any

import jpype


def _unwrap(value: Any) -> Any:
    return value.java if hasattr(value, "java") else value


def _jarray(component: Any, value: Any) -> Any:
    factory: Any = jpype.JArray(component)
    return factory(value)


def _return_kind(signature: str) -> str:
    try:
        return signature.rsplit(")", 1)[1][0]
    except (IndexError, AttributeError) as exc:
        raise ValueError(f"invalid JNI method signature: {signature!r}") from exc


class VaList:
    def __init__(self, vm: VM, java: Any):
        self._vm = vm
        self.java = java

    def object(self, index: builtins.int) -> DvmObject | None:
        value = self.java.getObjectArg(index)
        return None if value is None else DvmObject(self._vm, value)

    def int(self, index: builtins.int) -> builtins.int:
        return int(self.java.getIntArg(index))

    def long(self, index: builtins.int) -> builtins.int:
        return int(self.java.getLongArg(index))

    def float(self, index: builtins.int) -> builtins.float:
        return float(self.java.getFloatArg(index))

    def double(self, index: builtins.int) -> builtins.float:
        return float(self.java.getDoubleArg(index))


class DvmObject:
    def __init__(self, vm: VM, java: Any):
        self._vm = vm
        self.java = java

    @property
    def value(self) -> Any:
        return self.java.getValue()

    @property
    def object_type(self) -> DvmClass:
        return DvmClass(self._vm, self.java.getObjectType())

    def call_jni(self, signature: str, *args: Any) -> Any:
        return self._call(signature, args)

    def _call(self, signature: str, args: tuple[Any, ...]) -> Any:
        array = self._vm._object_array(args)
        emulator = self._vm._emulator.java
        kind = _return_kind(signature)
        if kind == "V":
            self.java.callJniMethod(emulator, signature, array)
            self._vm._raise_callback_error()
            return None
        if kind == "Z":
            value = bool(self.java.callJniMethodBoolean(emulator, signature, array))
            self._vm._raise_callback_error()
            return value
        if kind in "BCSI":
            value = int(self.java.callJniMethodInt(emulator, signature, array))
            self._vm._raise_callback_error()
            return value
        if kind == "J":
            value = int(self.java.callJniMethodLong(emulator, signature, array))
            self._vm._raise_callback_error()
            return value
        value = self.java.callJniMethodObject(emulator, signature, array)
        self._vm._raise_callback_error()
        return None if value is None else DvmObject(self._vm, value)

    def __repr__(self) -> str:
        return f"DvmObject({self.java!s})"


class DvmClass(DvmObject):
    @property
    def name(self) -> str:
        return str(self.java.getClassName())

    def new_object(self, value: Any = None) -> DvmObject:
        object_class = self._vm._emulator._class("java.lang.Object")
        java_value = jpype.JObject(_unwrap(value), object_class)
        return DvmObject(self._vm, self.java.newObject(java_value))

    def call_static_jni(self, signature: str, *args: Any) -> Any:
        array = self._vm._object_array(args)
        emulator = self._vm._emulator.java
        kind = _return_kind(signature)
        if kind == "V":
            self.java.callStaticJniMethod(emulator, signature, array)
            self._vm._raise_callback_error()
            return None
        if kind == "Z":
            value = bool(self.java.callStaticJniMethodBoolean(emulator, signature, array))
            self._vm._raise_callback_error()
            return value
        if kind in "BCSI":
            value = int(self.java.callStaticJniMethodInt(emulator, signature, array))
            self._vm._raise_callback_error()
            return value
        if kind == "J":
            value = int(self.java.callStaticJniMethodLong(emulator, signature, array))
            self._vm._raise_callback_error()
            return value
        value = self.java.callStaticJniMethodObject(emulator, signature, array)
        self._vm._raise_callback_error()
        return None if value is None else DvmObject(self._vm, value)


class VM:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java
        self._jni_references: tuple[Any, ...] | None = None
        self._callback_error: BaseException | None = None

    def resolve_class(self, name: str, *parents: DvmClass) -> DvmClass:
        class_type = self._emulator._class("com.github.unidbg.linux.android.dvm.DvmClass")
        parent_array = _jarray(class_type, [_unwrap(parent) for parent in parents])
        return DvmClass(self, self.java.resolveClass(name, parent_array))

    def set_jni(self, handler: Any) -> None:
        from .jni import make_bridge

        bridge, references = make_bridge(self, handler)
        self.java.setJni(bridge)
        self._jni_references = references

    def set_asset_resolver(self, callback: Any) -> None:
        class Resolver:
            def resolveAsset(self, name: str) -> Any:
                value = callback(str(name))
                if value is None:
                    return None
                return _jarray(jpype.JByte, bytes(value))

        impl = Resolver()
        proxy = jpype.JProxy(
            self._emulator._class("com.github.unidbg.linux.android.dvm.apk.AssetResolver"), inst=impl
        )
        self.java.setAssetResolver(proxy)
        self._emulator._callback_refs.extend((impl, proxy, callback))

    @property
    def package_name(self) -> str | None:
        value = self.java.getPackageName()
        return None if value is None else str(value)

    @property
    def version_name(self) -> str | None:
        value = self.java.getVersionName()
        return None if value is None else str(value)

    @property
    def version_code(self) -> int:
        return int(self.java.getVersionCode())

    @property
    def manifest_xml(self) -> str | None:
        value = self.java.getManifestXml()
        return None if value is None else str(value)

    @property
    def signatures(self) -> tuple[Any, ...]:
        value = self.java.getSignatures()
        return () if value is None else tuple(value)

    def open_asset(self, name: str) -> builtins.bytes | None:
        value = self.java.openAsset(name)
        return None if value is None else bytes(value)

    def unzip(self, path: str) -> builtins.bytes | None:
        value = self.java.unzip(path)
        return None if value is None else bytes(value)

    def add_not_found_class(self, name: str) -> None:
        self.java.addNotFoundClass(name)

    def string(self, value: str) -> DvmObject:
        cls = self._emulator._class("com.github.unidbg.linux.android.dvm.StringObject")
        return DvmObject(self, cls(self.java, value))

    def bytes(self, value: builtins.bytes | bytearray | memoryview) -> DvmObject:
        cls = self._emulator._class("com.github.unidbg.linux.android.dvm.array.ByteArray")
        byte_array = _jarray(jpype.JByte, bytes(value))
        return DvmObject(self, cls(self.java, byte_array))

    def boolean(self, value: bool) -> DvmObject:
        cls = self._emulator._class("com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean")
        return DvmObject(self, cls.valueOf(self.java, bool(value)))

    def integer(self, value: int) -> DvmObject:
        cls = self._emulator._class("com.github.unidbg.linux.android.dvm.wrapper.DvmInteger")
        return DvmObject(self, cls.valueOf(self.java, int(value)))

    def array(self, *values: DvmObject) -> DvmObject:
        base = self._emulator._class("com.github.unidbg.linux.android.dvm.DvmObject")
        cls = self._emulator._class("com.github.unidbg.linux.android.dvm.array.ArrayObject")
        array = _jarray(base, [_unwrap(value) for value in values])
        return DvmObject(self, cls(array))

    def _object_array(self, values: tuple[Any, ...]) -> Any:
        object_class = self._emulator._class("java.lang.Object")
        converted = []
        for value in values:
            value = _unwrap(value)
            if isinstance(value, bool):
                value = jpype.JBoolean(value)
            elif isinstance(value, int):
                value = jpype.JLong(value)
            elif isinstance(value, float):
                value = jpype.JDouble(value)
            converted.append(value)
        return _jarray(object_class, converted)

    def _raise_callback_error(self) -> None:
        error = self._callback_error
        self._callback_error = None
        if error is not None:
            self._emulator._capture_callback_error(error)
        self._emulator._raise_callback_error()
