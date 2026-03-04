# BCC 错误排查指南

## 错误：`undefined symbol: bpf_module_create_b`

这是 BCC Python 绑定与系统库版本不匹配导致的。

---

## 1. 检查当前 BCC 版本

```bash
# 检查系统 BCC 库版本
dpkg -l | grep -E "bcc|bpfcc"

# 检查 Python BCC 模块位置
python3 -c "import bcc; print(bcc.__file__)"

# 检查库文件
ls -la /usr/lib/python3/dist-packages/bcc/
ls -la /usr/local/lib/libbcc.so*
```

---

## 2. 解决方案

### 方案 A：完全重装 BCC（推荐）

```bash
# 1. 卸载现有 BCC
sudo apt-get remove --purge -y bpfcc-tools libbpfcc-dev bcc-tools
sudo pip3 uninstall -y bcc

# 2. 清理残留
sudo rm -rf /usr/lib/python3*/dist-packages/bcc*
sudo rm -f /usr/local/lib/libbcc*

# 3. 重新安装
sudo apt-get update
sudo apt-get install -y bpfcc-tools libbpfcc-dev

# 4. 验证
python3 -c "import bcc; print(bcc.__version__)"
```

### 方案 B：使用虚拟环境隔离

```bash
cd /home/zh/evpm

# 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 只安装 Python 包（不安装 bcc，使用系统的）
pip install rich prometheus-client flask flask-cors

# 运行（使用系统 bcc）
sudo $(which python3) -m evpm check
```

### 方案 C：从源码编译最新版

```bash
# 安装编译依赖
sudo apt-get install -y git build-essential cmake \
    libllvm-12-dev llvm-12-dev libclang-12-dev \
    libelf-dev python3-dev

# 克隆源码
cd /tmp
git clone https://github.com/iovisor/bcc.git
cd bcc

# 检出稳定版本
git checkout v0.29.1

# 编译
mkdir build && cd build
cmake ..
make -j$(nproc)

# 安装
sudo make install

# 安装 Python 绑定
cd src/python
sudo python3 setup.py install

# 验证
python3 -c "import bcc; print(bcc.__version__)"
```

---

## 3. 快速修复脚本

```bash
#!/bin/bash
# fix_bcc.sh - 快速修复 BCC 问题

echo "Fixing BCC installation..."

# 卸载冲突版本
sudo pip3 uninstall -y bcc 2>/dev/null
sudo apt-get remove --purge -y bpfcc-tools 2>/dev/null

# 重新安装
sudo apt-get update
sudo apt-get install -y bpfcc-tools libbpfcc-dev

# 创建符号链接（如果需要）
if [ -f /usr/lib/x86_64-linux-gnu/libbcc.so.0 ]; then
    sudo ln -sf /usr/lib/x86_64-linux-gnu/libbcc.so.0 /usr/local/lib/libbcc.so.0
fi

# 更新库缓存
sudo ldconfig

# 验证
echo "Testing BCC installation..."
python3 -c "from bcc import BPF; print('✓ BCC is working!')"
```

---

## 4. 环境特定问题

### Ubuntu 20.04+
```bash
# 使用官方仓库
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | \
    sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install -y bcc-tools libbcc-examples python3-bcc
```

### Ubuntu 18.04
```bash
# 必须使用较新版本
sudo apt-get install -y bpfcc-tools
# 或者从源码编译
```

---

## 5. 验证修复

```bash
# 测试 1：导入 BCC
python3 -c "from bcc import BPF; print('✓ Import OK')"

# 测试 2：加载简单程序
sudo python3 -c "
from bcc import BPF
BPF(text='int hello(void *ctx) { return 0; }')
print('✓ BPF program loading OK')
"

# 测试 3：运行 eVPM 检查
cd /home/zh/evpm
sudo evpm check
```

---

## 6. 如果仍有问题

1. **检查内核版本**: `uname -r` (需要 5.8+)
2. **检查 BTF 支持**: `ls /sys/kernel/btf/vmlinux`
3. **检查内核头文件**: `ls /usr/src/linux-headers-$(uname -r)`
4. **查看详细错误**: `sudo strace -e openat python3 -c "from bcc import BPF" 2>&1 | grep -i bcc`

---

## 最可能的原因

你的系统上同时存在：
1. 通过 `apt` 安装的 BCC (`/usr/lib/python3/dist-packages/bcc`)
2. 通过 `pip` 安装的 BCC (`/usr/local/lib/python3.8/dist-packages/bcc`)
3. 不同版本的共享库 (`/usr/local/lib/libbcc.so.0` vs `/usr/lib/x86_64-linux-gnu/libbcc.so.0`)

**解决方案**：完全卸载所有版本，只使用 apt 安装。
