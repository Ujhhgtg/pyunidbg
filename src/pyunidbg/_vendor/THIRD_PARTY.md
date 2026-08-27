# Bundled third-party components

The `jars/` and `native/` directories contain the pinned Java and Linux x86_64
runtime used by pyunidbg. Exact file hashes are recorded in `manifest.sha256`.

- unidbg 0.9.9: Apache-2.0, https://github.com/zhkl0228/unidbg
- Unicorn Java bindings 1.0.15: GPL-2.0, https://github.com/zhkl0228/unicorn
- Capstone Java bindings 3.1.8: BSD-3-Clause, https://github.com/zhkl0228/capstone
- Keystone Java bindings 0.9.7: GPL-2.0, https://github.com/zhkl0228/keystone
- demumble 1.0.4: Apache-2.0, https://github.com/zhkl0228/demumble
- native-lib-loader 2.3.5: BSD-2-Clause, https://github.com/scijava/native-lib-loader
- JNA 5.10.0: LGPL-2.1-or-later OR Apache-2.0
- apk-parser 2.6.10: Apache-2.0
- Apache Commons Codec 1.21.0: Apache-2.0
- Apache Commons Collections 4.5.0: Apache-2.0
- Apache Commons IO 2.21.0: Apache-2.0
- fastjson 1.2.83: Apache-2.0
- SLF4J API 2.0.16 and Simple 2.0.9: MIT

License and notice resources embedded by upstream remain inside each JAR. The
`pyunidbg-bridge.jar` file is compiled from this repository's `java/` sources.
