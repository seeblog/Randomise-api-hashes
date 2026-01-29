# 动态 DLL 解析 - 快速开始指南

## 🎯 优势

使用动态 DLL 解析替代硬编码 API 列表:

- ✅ **减小体积**: 从 67KB 减少到 <10KB
- ✅ **自动适应**: 自动适应不同 Windows 版本
- ✅ **支持任意 DLL**: 轻松添加新的 DLL
- ✅ **易于维护**: 无需手动更新 API 列表

---

## 📦 安装

### 1. 安装依赖

```bash
pip install pefile
```

### 2. 生成 API 缓存

```bash
# 解析默认 DLL (kernel32, ws2_32, wininet, dnsapi)
python dll_parser.py

# 或解析更多 DLL
python dll_parser.py -d kernel32.dll ntdll.dll advapi32.dll ws2_32.dll wininet.dll

# 详细输出
python dll_parser.py -v
```

输出示例:
```
[INFO] 解析 4 个 DLL...
[INFO] ✓ kernel32.dll: 1624 个导出函数
[INFO] ✓ ws2_32.dll: 215 个导出函数
[INFO] ✓ wininet.dll: 368 个导出函数
[INFO] ✓ dnsapi.dll: 234 个导出函数
[INFO] ✓ 缓存已保存: dll_cache.json

============================================================
DLL 导出函数统计
============================================================
kernel32.dll         :  1624 个导出函数
ws2_32.dll           :   215 个导出函数
wininet.dll          :   368 个导出函数
dnsapi.dll           :   234 个导出函数
============================================================
总计: 4 个 DLL, 2441 个导出函数
缓存文件: dll_cache.json
============================================================
```

---

## 🚀 使用

### 方法 1: 自动加载 (推荐)

```bash
# 直接使用零检测脚本
# API 列表会自动从缓存加载
python apihash_zero_detection.py -a x64 -i beacon.bin --zero-detection
```

### 方法 2: 测试 API 列表

```bash
# 测试 API 列表加载
python apihash_lists.py

# 输出:
# 测试动态 API 列表加载...
# ============================================================
# [INFO] 从缓存加载 API 列表: dll_cache.json
# 
# API 列表统计:
# ============================================================
# kernel32.dll         :  1624 个 API
# ws2_32.dll           :   215 个 API
# wininet.dll          :   368 个 API
# dnsapi.dll           :   234 个 API
# 
# 示例 API (kernel32.dll 前 10 个):
# ============================================================
#   1. AcquireSRWLockExclusive
#   2. AcquireSRWLockShared
#   3. ActivateActCtx
#   ...
```

---

## 📁 文件说明

### 核心文件

1. **`dll_parser.py`** - DLL 解析模块
   - 使用 pefile 库解析 DLL
   - 提取导出函数列表
   - 支持缓存

2. **`apihash_lists.py`** - API 列表模块 (动态版本)
   - 加载 DLL 导出函数
   - 提供缓存机制
   - 兼容原始脚本

3. **`dll_cache.json`** - 缓存文件 (自动生成)
   - 存储解析结果
   - 加速后续加载
   - 可以删除后重新生成

### 使用流程

```
1. 安装 pefile
   ↓
2. 运行 dll_parser.py 生成缓存
   ↓
3. 使用 apihash_zero_detection.py
   (自动从缓存加载 API 列表)
```

---

## 🔧 高级用法

### 添加更多 DLL

```bash
# 解析更多 DLL
python dll_parser.py -d \
  kernel32.dll \
  ntdll.dll \
  advapi32.dll \
  ws2_32.dll \
  wininet.dll \
  winhttp.dll \
  user32.dll \
  shell32.dll
```

### 强制刷新缓存

```bash
# 重新解析并覆盖缓存
python dll_parser.py -f
```

### 自定义缓存文件

```bash
# 使用自定义缓存文件名
python dll_parser.py -o my_cache.json
```

### 在代码中使用

```python
from apihash_lists import load_api_lists, get_api_list

# 加载所有 DLL
dll_exports = load_api_lists(verbose=True)

# 获取特定 DLL 的 API
kernel32_apis = get_api_list('kernel32.dll')
print(f"kernel32.dll 有 {len(kernel32_apis)} 个 API")

# 遍历所有 API
for dll_name, api_list in dll_exports.items():
    print(f"{dll_name}: {len(api_list)} APIs")
    for api in api_list[:5]:  # 显示前 5 个
        print(f"  - {api}")
```

---

## 🐛 故障排除

### 问题 1: "需要安装 pefile 库"

**解决**:
```bash
pip install pefile
```

### 问题 2: "DLL 不存在"

**原因**: 某些 DLL 可能在你的系统上不存在

**解决**: 只解析存在的 DLL
```bash
# 检查 System32 目录
dir C:\Windows\System32\*.dll

# 只解析存在的 DLL
python dll_parser.py -d kernel32.dll ws2_32.dll
```

### 问题 3: "API 列表为空"

**原因**: 缓存文件损坏或未生成

**解决**:
```bash
# 删除缓存并重新生成
del dll_cache.json
python dll_parser.py -v
```

### 问题 4: "非 Windows 系统"

**原因**: DLL 解析需要 Windows 系统

**解决**: 
- 在 Windows 上运行
- 或使用 Wine (Linux/Mac)
- 或从 Windows 机器复制 `dll_cache.json`

---

## 📊 性能对比

| 指标 | 硬编码版本 | 动态解析版本 |
|------|-----------|-------------|
| 脚本大小 | 67KB | <10KB |
| 首次加载 | 即时 | 2-5秒 (解析) |
| 后续加载 | 即时 | 即时 (缓存) |
| 维护成本 | 高 (手动更新) | 低 (自动) |
| 扩展性 | 低 (硬编码) | 高 (任意DLL) |
| 适应性 | 低 (固定版本) | 高 (自动适应) |

---

## ✅ 检查清单

### 初次设置
- [ ] 安装 pefile: `pip install pefile`
- [ ] 生成缓存: `python dll_parser.py`
- [ ] 验证缓存: `python apihash_lists.py`
- [ ] 测试脚本: `python apihash_zero_detection.py -h`

### 日常使用
- [ ] 直接使用零检测脚本
- [ ] API 列表自动加载
- [ ] 无需手动操作

### 更新维护
- [ ] Windows 更新后重新生成缓存
- [ ] 添加新 DLL 时运行 `dll_parser.py -d ...`
- [ ] 定期检查缓存文件大小

---

## 🎓 总结

**优势**:
- ✅ 无需硬编码 67KB 的 API 列表
- ✅ 自动适应系统版本
- ✅ 支持任意 DLL
- ✅ 易于维护和扩展

**使用简单**:
1. `pip install pefile`
2. `python dll_parser.py`
3. `python apihash_zero_detection.py -a x64 -i beacon.bin --zero-detection`

**完成!** 🎉

---

*最后更新: 2026-01-28*
