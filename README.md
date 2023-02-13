1. 不想写 CI，release 是我本地编译并上传的
2. 搜索算法是抄的 frida-dexdump，主要是想练习 rust
3. 没有用 frida，所以不会被检测

# 用法
1. 上传到 /data/local/tmp
2. chmod +x ./panda-dex-dumper 设置可执行权限
3. ./panda-dex-dumper -p $(pidof com.xxx)
4. dex 默认输出路径: /data/local/tmp/panda

# 编译
不想编译可以去 release 直接下载

```bash
# 安装工具链
rustup target add aarch64-linux-android

# 编译
cargo build --target aarch64-linux-android
```

ndk 配置
ndk 需要 r22b，r22b 以上的版本目前(2023.2.13)不能用。

`~/.cargo/config` 文件添加以下内容(不存在则创建), 注意内容中的替换路径。
```bash
[target.aarch64-linux-android]
ar = "android-ndk-r22b/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
linker = "android-ndk-r22b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
rustflags = ["-L", "android-ndk-r22b/toolchains/llvm/prebuilt/linux-x86_64/lib/gcc/aarch64-linux-android/4.9.x", "-L", "android-ndk-r22b/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/21"]
```

