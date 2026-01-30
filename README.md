# API 哈希随机化工具

> **基于 Huntress 研究的 Shellcode 特征修改工具**

⚠️ **免责声明**: 
- 本工具仅用于授权的安全研究和渗透测试
- **不保证**能绕过任何特定的安全产品
- 实际检测结果取决于多种因素（引擎版本、签名更新、启发式分析等）
- 使用者需对合法性和后果负责

## 🎯 功能特性

| 技术 | 作用 | 说明 |
|------|------|------|
| **API 哈希随机化** | 修改哈希值特征 | 随机化 ROR 值并重算哈希 |
| **DLL 名称大写化** | 修改栈字符串 | LoadLibraryA 不区分大小写 |
| **CLD 指令移动** | 修改首指令 | 只替换不插入,保持大小 |
| **ToUpper 变形** | 修改指令特征 | SUB→XOR,功能等价 |

**目的**: 修改 shellcode 的已知静态特征，用于研究和学习目的。

---

## 🚀 快速开始

### 安装

```bash
pip install pefile
python dll_parser.py -v
```

### 使用

```bash
# 生成测试 shellcode
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin

# 推荐用法 (应用所有技术)
python apihash_zero_detection.py -a x64 -i beacon.bin \
  --uppercase-dlls --transform-toupper

# 完整特征修改
python apihash_zero_detection.py -a x64 -i calc.bin --zero-detection -v

# 测试 shellcode (确保功能正常)
shellcode_load.exe calc_0x82.bin
```

### 原始脚本 (兼容)

```bash
python apihashreplace.py 64 beacon.bin
```

---

## 📁 项目结构

```
├── apihash_zero_detection.py   # ⭐ 主脚本
├── apihash_lists.py            # API 列表模块
├── dll_parser.py               # DLL 解析工具
├── apihashreplace.py           # 原始脚本
├── rorHashingDetection.yara    # YARA 检测规则
│
├── 零检测使用指南.md           # 详细使用指南
├── YARA绕过指南.md             # YARA 绕过详解
├── 动态DLL解析指南.md          # DLL 解析功能
├── 脚本执行关系说明.md         # 脚本依赖关系
├── 项目总结.md                 # 项目概览
└── dll_cache.json              # API 缓存 (自动生成)
```

---

## ⚠️ 注意事项

1. **只支持 raw 格式** - 不要使用编码器
2. **必须测试功能** - 修改后在隔离环境验证 shellcode 仍然正常工作
3. **大小不变** - 修改后 shellcode 大小应与原始相同
4. **CLD 可能跳过** - 如果没有 NOP 可替换
5. **不保证绕过** - 这是学习和研究工具，不是万能绕过方案

---

## 🔗 参考资源

- **原始文章**: [Huntress Blog - Hackers No Hashing](https://www.huntress.com/blog/hackers-no-hashing-randomizing-api-hashes-to-evade-cobalt-strike-shellcode-detection)
- **原始项目**: [embee-research/Randomise-api-hashes-cobalt-strike](https://github.com/embee-research/Randomise-api-hashes-cobalt-strike)

---

## 📝 更新日志

### v2.2 (2026-01-30)
- ✅ 更新为准确的技术说明

### v2.1 (2026-01-29)
- ✅ 新增 ToUpper 函数变形（指令特征修改）
- ✅ CLD 移动改为安全替换策略
- ✅ 扩展 DLL 名称支持 (12 种)
- ✅ 完善完整性验证

### v2.0
- ✅ 新增动态 DLL 解析
- ✅ 新增 DLL 名称大写化
- ✅ 新增 CLD 指令移动

### v1.0
- 原始 API 哈希随机化脚本

---

*最后更新: 2026-01-30*
