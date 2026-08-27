"""Python port of wechatx_deobf's Java DecryptorHarness.

The proprietary inputs are read from the sibling repository. Generated files
are written below ``--work-dir``; the source repository is never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import jpype

import pyunidbg

CORES = (
    "C",
    "M",
    "S",
    "H_p",
    "P",
    "14e777717682cce8a53cfcb34a22d65",
    "802766a4a4bd401c145a57463274d4dd",
    "a89eaf67dc796cb3af54d94fac0198b",
    "df4e6fd144fab2389ece8cb79eaa8f",
    "9816b5dfd637d3ce1473a9951b9e05",
)


def postprocess(capture_dir: Path, output_dir: Path) -> None:
    import msgpack

    output_dir.mkdir(parents=True, exist_ok=True)
    hp_path = capture_dir / "H_p_decrypted.bin"
    if hp_path.exists():
        data = hp_path.read_bytes()
        if data.startswith(b"\xda\xb9-"):
            data = data[3:]
        else:
            start = data.find(b"{")
            if start >= 0:
                data = data[start:]
        parsed = json.loads(data.decode("utf-8"))
        (output_dir / "H_p.json").write_text(
            json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {clean(key): clean(item) for key, item in value.items()}
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return value

    for core in ("M", "S", "P"):
        source = capture_dir / f"{core}_decrypted.bin"
        if source.exists():
            parsed = msgpack.unpackb(source.read_bytes(), raw=False, strict_map_key=False)
            (output_dir / f"{core}.json").write_text(
                json.dumps(clean(parsed), indent=2, ensure_ascii=False), encoding="utf-8"
            )

    dex_mappings = {
        "C_decrypted.dex": "C.dex",
        "14e777717682cce8a53cfcb34a22d65_decrypted.dex": "big.dex",
        "802766a4a4bd401c145a57463274d4dd_decrypted.dex": "m1.dex",
        "a89eaf67dc796cb3af54d94fac0198b_decrypted.dex": "m2.dex",
        "df4e6fd144fab2389ece8cb79eaa8f_decrypted.dex": "m3.dex",
    }
    for source_name, destination_name in dex_mappings.items():
        source = capture_dir / source_name
        if source.exists():
            shutil.copyfile(source, output_dir / destination_name)

    apk_source = capture_dir / "9816b5dfd637d3ce1473a9951b9e05_decrypted.bin"
    if apk_source.exists():
        apk_output = output_dir / "load2.apk"
        shutil.copyfile(apk_source, apk_output)
        with zipfile.ZipFile(apk_output) as archive:
            (output_dir / "load2_classes.dex").write_bytes(archive.read("classes.dex"))


def _bytes(value: Any) -> bytes:
    return bytes((int(item) & 0xFF) for item in value)


class DecryptorJni(pyunidbg.JniHandler):
    def __init__(self, core: str, rootfs: Path, module_dir: Path, capture_dir: Path):
        self.core = core
        self.rootfs = rootfs
        self.module_dir = module_dir
        self.capture_dir = capture_dir
        self.aes_key: Any = None
        self.aes_iv: Any = None

    @staticmethod
    def _j(name: str) -> Any:
        return pyunidbg.java_class(name)

    def _translate_path(self, value: str) -> str:
        path = str(value)
        if path.startswith("/") and not path.startswith("/home/") and "rootfs" not in path:
            return str(self.rootfs / path.lstrip("/"))
        return path

    def call_object_method(self, vm, obj, signature, args):  # noqa: C901, PLR0912
        print(f"  [JNI Call] Object Method: {signature}")
        if signature == "android/content/Context->getFilesDir()Ljava/io/File;":
            return vm.resolve_class("java/io/File").new_object(
                self._j("java.io.File")("/data/user/0/com.tencent.mm/files")
            )
        if signature == "android/content/Context->getPackageCodePath()Ljava/lang/String;":
            return vm.string("/data/app/com.tencent.mm/base.apk")
        if signature == "android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
            return vm.resolve_class("android/content/SharedPreferences").new_object()
        if signature == "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
            return args.object(1)
        if signature == "java/security/cert/CertificateFactory->generateCertificate(Ljava/io/InputStream;)Ljava/security/cert/Certificate;":
            certificate = obj.value.generateCertificate(args.object(0).value)
            return vm.resolve_class("java/security/cert/Certificate").new_object(certificate)
        if signature == "java/security/cert/Certificate->getPublicKey()Ljava/security/PublicKey;":
            return vm.resolve_class("java/security/Key").new_object(obj.value.getPublicKey())
        if signature in {
            "java/security/Key->getEncoded()[B",
            "javax/crypto/SecretKey->getEncoded()[B",
            "javax/crypto/SecretKeySpec->getEncoded()[B",
        }:
            return vm.bytes(_bytes(obj.value.getEncoded()))
        if signature == "java/security/Key->getAlgorithm()Ljava/lang/String;":
            return vm.string(str(obj.value.getAlgorithm()))
        if signature == "java/security/cert/Certificate->getEncoded()[B":
            try:
                return vm.bytes(_bytes(obj.value.getEncoded()))
            except Exception:
                return vm.bytes((self.module_dir / "534a9729a0c461cbd7a4379978fb742").read_bytes())
        if signature == "javax/crypto/Cipher->doFinal([B)[B":
            try:
                output = obj.value.doFinal(args.object(0).value)
                print(f"  Decryption successful! Size: {len(output)} bytes.")
                return vm.bytes(_bytes(output))
            except Exception as exc:
                print(f"  Decryption failed: {exc}", file=sys.stderr)
                return vm.bytes(b"")
        if signature == "java/security/MessageDigest->digest()[B":
            return vm.bytes(_bytes(obj.value.digest()))
        if signature == "java/io/File->getAbsolutePath()Ljava/lang/String;":
            return vm.string(str(obj.value.getAbsolutePath()))
        if signature == "java/lang/String->toCharArray()[C":
            return vm.bytes(str(obj.value).encode("utf-16le"))
        if signature == "java/lang/String->getBytes()[B":
            return vm.bytes(str(obj.value).encode())
        if signature == "java/lang/String->getBytes(Ljava/lang/String;)[B":
            charset = str(args.object(0).value).replace("UTF-8", "utf-8")
            return vm.bytes(str(obj.value).encode(charset))
        if signature == "javax/crypto/SecretKeyFactory->generateSecret(Ljava/security/spec/KeySpec;)Ljavax/crypto/SecretKey;":
            return vm.resolve_class("javax/crypto/SecretKey").new_object(
                obj.value.generateSecret(args.object(0).value)
            )
        if signature == "java/security/KeyFactory->generatePublic(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;":
            return vm.resolve_class("java/security/Key").new_object(
                obj.value.generatePublic(args.object(0).value)
            )
        if signature == "java/security/KeyFactory->generatePrivate(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;":
            return vm.resolve_class("java/security/Key").new_object(
                obj.value.generatePrivate(args.object(0).value)
            )
        if signature == "javax/crypto/KeyGenerator->generateKey()Ljavax/crypto/SecretKey;":
            return vm.resolve_class("javax/crypto/SecretKey").new_object(obj.value.generateKey())
        if signature == "java/nio/ByteBuffer->array()[B":
            return vm.bytes(_bytes(obj.value.array()))
        if signature == "java/util/zip/ZipEntry->getName()Ljava/lang/String;":
            return vm.string(str(obj.value.getName()))
        if signature == "java/util/jar/JarFile->getJarEntry(Ljava/lang/String;)Ljava/util/jar/JarEntry;":
            argument = args.object(0)
            entry = None if argument is None else obj.value.getJarEntry(str(argument.value))
            return None if entry is None else vm.resolve_class("java/util/jar/JarEntry").new_object(entry)
        if signature == "java/util/jar/JarFile->getEntry(Ljava/lang/String;)Ljava/util/zip/ZipEntry;":
            argument = args.object(0)
            entry = None if argument is None else obj.value.getJarEntry(str(argument.value))
            return None if entry is None else vm.resolve_class("java/util/jar/JarEntry").new_object(entry)
        if signature == "java/util/jar/JarFile->getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;":
            argument = args.object(0)
            stream = None if argument is None else obj.value.getInputStream(argument.value)
            return None if stream is None else vm.resolve_class("java/io/InputStream").new_object(stream)
        if signature == "java/util/jar/JarEntry->getCertificates()[Ljava/security/cert/Certificate;":
            certificates = obj.value.getCertificates()
            if certificates:
                cls = vm.resolve_class("java/security/cert/Certificate")
                return vm.array(*(cls.new_object(certificate) for certificate in certificates))
            factory = self._j("java.security.cert.CertificateFactory").getInstance("X.509")
            source = self._j("java.io.ByteArrayInputStream")(
                jpype.JArray(jpype.JByte)((self.module_dir / "wechatx_module_cert.der").read_bytes())
            )
            certificate = factory.generateCertificate(source)
            return vm.array(vm.resolve_class("java/security/cert/Certificate").new_object(certificate))
        if signature == "java/util/zip/ZipInputStream->getNextEntry()Ljava/util/zip/ZipEntry;":
            entry = obj.value.getNextEntry()
            return None if entry is None else vm.resolve_class("java/util/zip/ZipEntry").new_object(entry)
        if signature in {
            "dalvik/system/InMemoryDexClassLoader->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
            "java/lang/ClassLoader->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
        }:
            return vm.resolve_class("java/lang/Class").new_object()
        if signature == "java/io/ByteArrayOutputStream->toByteArray()[B":
            data = _bytes(obj.value.toByteArray())
            is_cert = data[:2] == b"\x30\x82"
            is_elf = data[:4] == b"\x7fELF"
            is_encrypted = data[:4] == b"\x97\xc4\x01\x30"
            if len(data) > 1000 and not (is_cert or is_elf or is_encrypted):
                target = self.capture_dir / f"{self.core}_decrypted.bin"
                target.write_bytes(data)
                print(f"  [JNI] saved {len(data)} bytes to {target}")
            return vm.bytes(data)
        return pyunidbg.NOT_HANDLED

    def call_static_object_method(self, vm, cls, signature, args):  # noqa: C901
        print(f"  [JNI Call] Static Object Method: {signature}")
        if signature == "java/lang/Integer->toHexString(I)Ljava/lang/String;":
            return vm.string(format(args.int(0) & 0xFF, "x"))
        if signature == "java/lang/Long->toHexString(J)Ljava/lang/String;":
            return vm.string(format(args.long(0) & 0xFFFFFFFFFFFFFFFF, "x"))
        if signature == "java/lang/Long->valueOf(J)Ljava/lang/Long;":
            return vm.resolve_class("java/lang/Long").new_object(self._j("java.lang.Long")(args.long(0)))
        if signature == "java/lang/Integer->valueOf(I)Ljava/lang/Integer;":
            return vm.integer(args.int(0))
        if signature == "java/lang/String->valueOf(J)Ljava/lang/String;":
            return vm.string(str(args.long(0)))
        if signature == "java/lang/String->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;":
            return vm.string("")
        factories = {
            "java/security/cert/CertificateFactory->getInstance(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;": (
                "java.security.cert.CertificateFactory", "java/security/cert/CertificateFactory"
            ),
            "java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;": (
                "java.security.MessageDigest", "java/security/MessageDigest"
            ),
            "java/security/Signature->getInstance(Ljava/lang/String;)Ljava/security/Signature;": (
                "java.security.Signature", "java/security/Signature"
            ),
            "javax/crypto/SecretKeyFactory->getInstance(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;": (
                "javax.crypto.SecretKeyFactory", "javax/crypto/SecretKeyFactory"
            ),
            "java/security/KeyFactory->getInstance(Ljava/lang/String;)Ljava/security/KeyFactory;": (
                "java.security.KeyFactory", "java/security/KeyFactory"
            ),
            "javax/crypto/KeyGenerator->getInstance(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;": (
                "javax.crypto.KeyGenerator", "javax/crypto/KeyGenerator"
            ),
        }
        if signature in factories:
            java_name, dvm_name = factories[signature]
            value = self._j(java_name).getInstance(str(args.object(0).value))
            return vm.resolve_class(dvm_name).new_object(value)
        if signature == "javax/crypto/Cipher->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;":
            transformation = str(args.object(0).value).replace("PKCS7Padding", "PKCS5Padding")
            value = self._j("javax.crypto.Cipher").getInstance(transformation)
            return vm.resolve_class("javax/crypto/Cipher").new_object(value)
        if signature in {
            "java/security/SecureRandom->getInstance(Ljava/lang/String;)Ljava/security/SecureRandom;",
            "java/security/SecureRandom->getInstance()Ljava/security/SecureRandom;",
        }:
            return vm.resolve_class("java/security/SecureRandom").new_object(
                self._j("java.security.SecureRandom")()
            )
        if signature == "java/nio/ByteBuffer->wrap([B)Ljava/nio/ByteBuffer;":
            argument = args.object(0)
            if argument is None:
                return pyunidbg.NOT_HANDLED
            return vm.resolve_class("java/nio/ByteBuffer").new_object(
                self._j("java.nio.ByteBuffer").wrap(argument.value)
            )
        return pyunidbg.NOT_HANDLED

    def new_object(self, vm, cls, signature, args):  # noqa: C901, PLR0912
        print(f"  [JNI Call] New Object: {signature}")
        if signature == "java/io/File-><init>(Ljava/lang/String;)V":
            return cls.new_object(self._j("java.io.File")(self._translate_path(str(args.object(0).value))))
        if signature == "java/io/File-><init>(Ljava/lang/String;Ljava/lang/String;)V":
            return cls.new_object(
                self._j("java.io.File")(
                    self._translate_path(str(args.object(0).value)), str(args.object(1).value)
                )
            )
        if signature == "java/util/jar/JarFile-><init>(Ljava/lang/String;)V":
            return cls.new_object(self._j("java.util.jar.JarFile")(self._translate_path(str(args.object(0).value))))
        if signature == "java/io/FileInputStream-><init>(Ljava/lang/String;)V":
            return cls.new_object(self._j("java.io.FileInputStream")(self._translate_path(str(args.object(0).value))))
        if signature == "java/io/FileInputStream-><init>(Ljava/io/File;)V":
            return cls.new_object(self._j("java.io.FileInputStream")(args.object(0).value))
        if signature == "java/io/ByteArrayOutputStream-><init>()V":
            return cls.new_object(self._j("java.io.ByteArrayOutputStream")())
        if signature in {
            "java/io/FileOutputStream-><init>(Ljava/lang/String;)V",
            "java/io/FileOutputStream-><init>(Ljava/lang/String;Z)V",
        }:
            append = signature.endswith(";Z)V") and args.int(1) != 0
            return cls.new_object(
                self._j("java.io.FileOutputStream")(
                    self._translate_path(str(args.object(0).value)), append
                )
            )
        if signature in {
            "java/io/FileOutputStream-><init>(Ljava/io/File;)V",
            "java/io/FileOutputStream-><init>(Ljava/io/File;Z)V",
        }:
            append = signature.endswith(";Z)V") and args.int(1) != 0
            return cls.new_object(self._j("java.io.FileOutputStream")(args.object(0).value, append))
        if signature == "java/io/BufferedInputStream-><init>(Ljava/io/InputStream;)V":
            return cls.new_object(self._j("java.io.BufferedInputStream")(args.object(0).value))
        if signature == "java/io/BufferedInputStream-><init>(Ljava/io/InputStream;I)V":
            return cls.new_object(self._j("java.io.BufferedInputStream")(args.object(0).value, args.int(1)))
        if signature == "java/io/ByteArrayInputStream-><init>([B)V":
            return cls.new_object(self._j("java.io.ByteArrayInputStream")(args.object(0).value))
        if signature == "java/util/zip/CRC32-><init>()V":
            return cls.new_object(self._j("java.util.zip.CRC32")())
        if signature in {
            "javax/crypto/spec/SecretKeySpec-><init>([BLjava/lang/String;)V",
            "javax/crypto/spec/SecretKeySpec-><init>([BIILjava/lang/String;)V",
        }:
            key = args.object(0).value
            if len(key) == 0:
                key = jpype.JArray(jpype.JByte)(bytes(16))
            self.aes_key = key
            algorithm_index = 3 if "BIIL" in signature else 1
            if "BIIL" in signature:
                value = self._j("javax.crypto.spec.SecretKeySpec")(
                    key, args.int(1), args.int(2), str(args.object(3).value)
                )
            else:
                value = self._j("javax.crypto.spec.SecretKeySpec")(key, str(args.object(algorithm_index).value))
            return cls.new_object(value)
        if signature == "javax/crypto/spec/IvParameterSpec-><init>([B)V":
            self.aes_iv = args.object(0).value
            return cls.new_object(self._j("javax.crypto.spec.IvParameterSpec")(self.aes_iv))
        if signature.startswith("javax/crypto/spec/PBEKeySpec-><init>([C"):
            raw = _bytes(args.object(0).value)
            password = self._j("java.lang.String")(
                jpype.JArray(jpype.JByte)(raw), self._j("java.nio.charset.StandardCharsets").UTF_16LE
            ).toCharArray()
            pbe = self._j("javax.crypto.spec.PBEKeySpec")
            if signature == "javax/crypto/spec/PBEKeySpec-><init>([C)V":
                value = pbe(password)
            else:
                salt = args.object(1).value
                iterations = args.int(2)
                key_length = args.int(3) if signature.endswith("[C[BII)V") else 128
                value = pbe(password, salt, iterations, key_length)
            return cls.new_object(value)
        if signature == "javax/crypto/spec/PBEParameterSpec-><init>([BI)V":
            return cls.new_object(self._j("javax.crypto.spec.PBEParameterSpec")(args.object(0).value, args.int(1)))
        if signature == "java/security/spec/X509EncodedKeySpec-><init>([B)V":
            return cls.new_object(self._j("java.security.spec.X509EncodedKeySpec")(args.object(0).value))
        if signature == "java/security/spec/PKCS8EncodedKeySpec-><init>([B)V":
            return cls.new_object(self._j("java.security.spec.PKCS8EncodedKeySpec")(args.object(0).value))
        if signature == "java/security/SecureRandom-><init>()V":
            return cls.new_object(self._j("java.security.SecureRandom")())
        if signature == "javax/crypto/CipherInputStream-><init>(Ljava/io/InputStream;Ljavax/crypto/Cipher;)V":
            return cls.new_object(self._j("javax.crypto.CipherInputStream")(args.object(0).value, args.object(1).value))
        if signature == "java/util/zip/ZipInputStream-><init>(Ljava/io/InputStream;)V":
            return cls.new_object(self._j("java.util.zip.ZipInputStream")(args.object(0).value))
        if signature in {
            "java/io/BufferedWriter-><init>(Ljava/io/Writer;)V",
            "java/io/PrintWriter-><init>(Ljava/io/Writer;)V",
        }:
            return cls.new_object()
        if signature == "java/lang/Float-><init>(F)V":
            return cls.new_object(self._j("java.lang.Float")(args.float(0)))
        if signature == "java/lang/Double-><init>(D)V":
            return cls.new_object(self._j("java.lang.Double")(args.double(0)))
        if signature == "dalvik/system/InMemoryDexClassLoader-><init>(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V":
            buffer = args.object(0).value
            data = jpype.JArray(jpype.JByte)(int(buffer.remaining()))
            buffer.get(data)
            target = self.capture_dir / f"{self.core}_decrypted.dex"
            target.write_bytes(_bytes(data))
            print(f"  [JNI] InMemoryDexClassLoader saved {len(data)} bytes to {target}")
            return cls.new_object()
        return pyunidbg.NOT_HANDLED

    def call_void_method(self, vm, obj, signature, args):  # noqa: C901
        if signature.startswith("javax/crypto/Cipher->init("):
            try:
                mode = args.int(0)
                key = args.object(1).value
                self.aes_key = key.getEncoded() if str(key.getAlgorithm()) == "AES" else self.aes_key
                try:
                    parameters = args.object(2)
                except Exception:
                    parameters = None
                if parameters is None:
                    obj.value.init(mode, key)
                else:
                    obj.value.init(mode, key, parameters.value)
                    if isinstance(parameters.value, self._j("javax.crypto.spec.IvParameterSpec")):
                        self.aes_iv = parameters.value.getIV()
            except Exception as exc:
                print(f"  [JNI] Cipher.init failed: {exc}", file=sys.stderr)
            return None
        if signature == "java/security/MessageDigest->update([B)V":
            obj.value.update(args.object(0).value)
            return None
        if signature == "java/util/zip/CRC32->update([B)V":
            obj.value.update(args.object(0).value)
            return None
        if signature == "java/util/zip/CRC32->update([BII)V":
            obj.value.update(args.object(0).value, args.int(1), args.int(2))
            return None
        if signature == "java/util/zip/CRC32->reset()V":
            obj.value.reset()
            return None
        if signature in {
            "java/security/Signature->initVerify(Ljava/security/PublicKey;)V",
            "java/security/Signature->update([B)V",
            "java/security/Signature->update([BII)V",
        }:
            return None
        if signature in {
            "java/util/jar/JarFile->close()V",
            "java/util/zip/ZipFile->close()V",
            "java/io/InputStream->close()V",
            "java/util/zip/ZipInputStream->close()V",
        } or signature.endswith("OutputStream->close()V"):
            obj.value.close()
            return None
        if signature == "java/util/zip/ZipInputStream->closeEntry()V":
            obj.value.closeEntry()
            return None
        if signature.endswith("OutputStream->write([BII)V"):
            obj.value.write(args.object(0).value, args.int(1), args.int(2))
            return None
        if signature.endswith("OutputStream->write([B)V"):
            obj.value.write(args.object(0).value)
            return None
        return pyunidbg.NOT_HANDLED

    def call_boolean_method(self, vm, obj, signature, args):
        if signature == "java/security/Signature->verify([B)Z":
            return True
        if signature == "java/lang/Boolean->booleanValue()Z":
            return bool(obj.value)
        file_methods = {
            "java/io/File->createNewFile()Z": "createNewFile",
            "java/io/File->delete()Z": "delete",
            "java/io/File->mkdirs()Z": "mkdirs",
            "java/io/File->mkdir()Z": "mkdirs",
            "java/io/File->exists()Z": "exists",
            "java/io/File->isDirectory()Z": "isDirectory",
            "java/io/File->isFile()Z": "isFile",
        }
        method = file_methods.get(signature)
        return bool(getattr(obj.value, method)()) if method else pyunidbg.NOT_HANDLED

    def call_int_method(self, vm, obj, signature, args):
        if signature.startswith("javax/crypto/CipherInputStream->read(") or signature.startswith(
            "javax/crypto/CipherInputStream->available("
        ):
            return int(obj.value.read(args.object(0).value)) if "read([B)" in signature else int(obj.value.available())
        if signature == "java/util/zip/ZipInputStream->read([B)I":
            return int(obj.value.read(args.object(0).value))
        if signature == "java/io/InputStream->available()I":
            return int(obj.value.available())
        if signature == "java/io/InputStream->read([B)I":
            return int(obj.value.read(args.object(0).value))
        return pyunidbg.NOT_HANDLED

    def call_long_method(self, vm, obj, signature, args):
        methods = {
            "java/io/File->length()J": "length",
            "java/util/zip/CRC32->getValue()J": "getValue",
            "java/util/zip/ZipEntry->getCrc()J": "getCrc",
            "java/util/zip/ZipEntry->getSize()J": "getSize",
            "java/util/zip/ZipEntry->getCompressedSize()J": "getCompressedSize",
        }
        method = methods.get(signature)
        return int(getattr(obj.value, method)()) if method else pyunidbg.NOT_HANDLED

    def call_static_long_method(self, vm, cls, signature, args):
        if signature == "java/lang/System->currentTimeMillis()J":
            return int(time.time() * 1000)
        if signature == "java/lang/Long->parseLong(Ljava/lang/String;I)J":
            return int(str(args.object(0).value), args.int(1))
        if signature == "java/lang/Long->parseLong(Ljava/lang/String;)J":
            return int(str(args.object(0).value))
        return pyunidbg.NOT_HANDLED


class DecryptorHarness:
    def __init__(self, core: str, source_module_dir: Path, work_dir: Path):
        self.core = core
        self.source_module_dir = source_module_dir
        self.rootfs = work_dir / "rootfs" / core
        self.capture_dir = work_dir / "captures"
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.bss_state_address = 0

    @staticmethod
    def _unpadded_md5(value: str) -> str:
        return "".join(format(byte, "x") for byte in hashlib.md5(value.encode()).digest())

    def setup_filesystem(self) -> None:
        target = self.rootfs / "data/user/0/com.tencent.mm/files/x7_3.0"
        target.mkdir(parents=True, exist_ok=True)
        apk_dir = self.rootfs / "data/app/com.tencent.mm"
        apk_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(apk_dir / "base.apk", "w") as archive:
            archive.writestr("classes.dex", b"dummy dex content")
        core_md5 = self._unpadded_md5(self.core)
        for source in self.source_module_dir.iterdir():
            if not source.is_file():
                continue
            names = {
                self.core: core_md5,
                f"{self.core}_c": f"{core_md5}_c",
                f"{self.core}_s": f"{core_md5}_s",
            }
            shutil.copy2(source, target / names.get(source.name, source.name))
        loader = self.source_module_dir / "dc7be70f1898d3a58965a919740f97"
        if loader.exists():
            shutil.copy2(loader, target / "53d9ad931411c35b69e2f990832d78fc")
        (target / "53d9ad931411c35b69e2f990832d78fc_s").write_bytes(bytes(256))
        for source in self.source_module_dir.iterdir():
            if not source.is_file() or "_" in source.name:
                continue
            destination = core_md5 if source.name == self.core else source.name
            signature = target / f"{destination}_s"
            if not signature.exists():
                signature.write_bytes(bytes(256))
            main = target / destination
            companion = target / f"{destination}_c"
            if not companion.exists() and main.exists() and main.read_bytes()[:4] == b"\x97\xc4\x01\x30":
                shutil.copy2(main, companion)

    def _install_hooks(self, emulator: pyunidbg.AndroidEmulator, module: pyunidbg.Module) -> None:
        fake = emulator.memory.malloc(0x40)
        fake.pointer.write(bytes(0x40))
        fake.pointer.write_u32(0x20, -1, signed=True)
        fake_address = int(fake.pointer)
        arm64 = pyunidbg.java_class("unicorn.Arm64Const")

        def msgpack_guard(emu, address, context):
            output = context.pointer_arg(0)
            source = context.pointer_arg(1)
            magic = b"" if source is None else source.read(4)
            if magic in {b"\x7fELF", bytes(4)}:
                if output is not None:
                    output.write_u64(0x18, fake_address)
                context.set_pc(context.lr)
            return True

        module.add_breakpoint(0x4094C, msgpack_guard)

        def key_entry(emu, address, context):
            pointer = context.pointer_arg(0)
            self.bss_state_address = 0 if pointer is None else int(pointer)
            return True

        module.add_breakpoint(0x2BED8, key_entry)

        def skip_pbe(emu, address, context):
            context.write_register(int(arm64.UC_ARM64_REG_X0), 1)
            context.set_pc(context.lr)
            return True

        module.add_breakpoint(0x4C19C, skip_pbe)

    def run(self) -> None:
        self.setup_filesystem()
        with pyunidbg.AndroidEmulator(
            "com.tencent.mm", api_level=23, root_dir=self.rootfs, verbose=False
        ) as emulator:
            vm = emulator.vm
            handler = DecryptorJni(self.core, self.rootfs, self.source_module_dir, self.capture_dir)
            vm.set_jni(handler)

            input_stream = vm.resolve_class("java/io/InputStream")
            vm.resolve_class("java/io/FileInputStream", input_stream)
            vm.resolve_class("java/io/ByteArrayInputStream", input_stream)
            filter_stream = vm.resolve_class("java/io/FilterInputStream", input_stream)
            vm.resolve_class("java/io/BufferedInputStream", filter_stream)
            vm.resolve_class("javax/crypto/CipherInputStream", filter_stream)
            zip_file = vm.resolve_class("java/util/zip/ZipFile")
            vm.resolve_class("java/util/jar/JarFile", zip_file)
            zip_entry = vm.resolve_class("java/util/zip/ZipEntry")
            vm.resolve_class("java/util/jar/JarEntry", zip_entry)
            output_stream = vm.resolve_class("java/io/OutputStream")
            vm.resolve_class("java/io/ByteArrayOutputStream", output_stream)
            vm.resolve_class("java/io/FileOutputStream", output_stream)
            vm.resolve_class("com/android/xc/Wrapper/HookWrapper_s")

            module = emulator.load_library(self.source_module_dir / "libwxcoreloader.so")
            self._install_hooks(emulator, module)
            module.call_jni_on_load()

            loader = vm.resolve_class("com/android/x/xposed/hook/WxCoreLoader")
            context = vm.resolve_class("android/content/Context").new_object()
            args0 = vm.array(
                context,
                context,
                vm.string("/data/user/0/com.tencent.mm/files/x7_3.0"),
                vm.string("release"),
                vm.string(self.core),
                vm.integer(1),
                vm.string("/data/app/com.tencent.mm/base.apk"),
            )
            loader.call_static_jni("CallMethod(I[Ljava/lang/Object;)Ljava/lang/Object;", 0, args0)
            if self.bss_state_address:
                emulator.memory.write(self.bss_state_address + 0x20, b"\0")
            args1 = vm.array(
                vm.resolve_class("java/lang/ClassLoader").new_object(),
                vm.string("com.android.xc.Wrapper.HookWrapper"),
                vm.boolean(True),
                vm.boolean(True),
            )
            loader.call_static_jni("CallMethod(I[Ljava/lang/Object;)Ljava/lang/Object;", 1, args1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("/home/ujhhgtg/coding/wechatx_deobf/moduledata/x7_3.0"),
    )
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--core", action="append", choices=CORES)
    options = parser.parse_args()
    options.work_dir.mkdir(parents=True, exist_ok=True)
    successes = 0
    selected = tuple(options.core) if options.core else CORES
    for core in selected:
        print(f"\n{'=' * 40}\nProcessing core: {core}\n{'=' * 40}")
        try:
            DecryptorHarness(core, options.source, options.work_dir).run()
            successes += 1
        except Exception:
            print(f"Error processing core: {core}", file=sys.stderr)
            import traceback

            traceback.print_exc()
    postprocess(options.work_dir / "captures", options.work_dir / "output")
    print(f"\nDone! Successfully processed {successes} / {len(selected)} cores.")
    return 0 if successes == len(selected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
