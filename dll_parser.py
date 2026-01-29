#!/usr/bin/env python3
"""
动态 DLL 解析模块
使用 pefile 库从系统 DLL 中提取导出函数

替代硬编码的 API 列表,支持任意 DLL
"""

import os
import sys
import logging
from pathlib import Path

try:
    import pefile
except ImportError:
    print("错误: 需要安装 pefile 库")
    print("请运行: pip install pefile")
    sys.exit(1)

logger = logging.getLogger(__name__)


def parse_dll_exports(dll_path, verbose=False):
    """
    从 DLL 文件中提取所有导出函数
    
    Args:
        dll_path: DLL 文件路径
        verbose: 详细输出
    
    Returns:
        导出函数名称列表
    """
    try:
        if verbose:
            logger.debug(f"解析 DLL: {dll_path}")
        
        pe = pefile.PE(dll_path)
        exports = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        # 导出函数名称通常是 ASCII
                        func_name = exp.name.decode('utf-8')
                        exports.append(func_name)
                    except UnicodeDecodeError:
                        # 跳过无法解码的名称
                        if verbose:
                            logger.warning(f"跳过无法解码的导出: {exp.name}")
                        continue
        
        if verbose:
            logger.debug(f"  找到 {len(exports)} 个导出函数")
        
        pe.close()
        return exports
    
    except pefile.PEFormatError as e:
        logger.error(f"PE 格式错误: {dll_path} - {e}")
        return []
    except Exception as e:
        logger.error(f"解析 {dll_path} 失败: {e}")
        return []


def get_system32_path():
    """获取 System32 目录路径"""
    if os.name == 'nt':  # Windows
        return os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
    else:
        # Linux/Mac 下可能需要 Wine
        logger.warning("非 Windows 系统,DLL 解析可能失败")
        return None


def load_dll_exports(dll_names, verbose=False):
    """
    加载多个 DLL 的导出函数
    
    Args:
        dll_names: DLL 名称列表 (如 ['kernel32.dll', 'ntdll.dll'])
        verbose: 详细输出
    
    Returns:
        字典 {dll_name: [export_list]}
    """
    system32 = get_system32_path()
    if not system32:
        logger.error("无法确定 System32 路径")
        return {}
    
    dll_exports = {}
    
    for dll_name in dll_names:
        dll_path = os.path.join(system32, dll_name)
        
        if not os.path.exists(dll_path):
            logger.warning(f"DLL 不存在: {dll_path}")
            dll_exports[dll_name] = []
            continue
        
        exports = parse_dll_exports(dll_path, verbose)
        dll_exports[dll_name] = exports
        
        if verbose:
            logger.info(f"✓ {dll_name}: {len(exports)} 个导出函数")
    
    return dll_exports


def get_common_dlls():
    """返回常用的 DLL 列表"""
    return [
        'kernel32.dll',
        'ntdll.dll',
        'advapi32.dll',
        'ws2_32.dll',
        'wininet.dll',
        'winhttp.dll',
        'dnsapi.dll',
        'user32.dll',
        'shell32.dll',
        'ole32.dll',
        'crypt32.dll',
        'psapi.dll',
    ]


def cache_dll_exports(dll_names=None, cache_file='dll_cache.json', force_refresh=False):
    """
    缓存 DLL 导出函数到文件
    
    Args:
        dll_names: DLL 列表 (None 则使用常用 DLL)
        cache_file: 缓存文件路径
        force_refresh: 强制刷新缓存
    
    Returns:
        导出函数字典
    """
    import json
    
    cache_path = Path(cache_file)
    
    # 如果缓存存在且不强制刷新,直接加载
    if cache_path.exists() and not force_refresh:
        logger.info(f"从缓存加载: {cache_file}")
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    # 否则重新解析
    if dll_names is None:
        dll_names = get_common_dlls()
    
    logger.info(f"解析 {len(dll_names)} 个 DLL...")
    dll_exports = load_dll_exports(dll_names, verbose=True)
    
    # 保存缓存
    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump(dll_exports, f, indent=2)
    
    logger.info(f"✓ 缓存已保存: {cache_file}")
    
    return dll_exports


# ============================================================================
# 命令行工具
# ============================================================================

def main():
    """命令行工具 - 测试 DLL 解析"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DLL 导出函数解析工具')
    parser.add_argument('-d', '--dll', nargs='+',
                        help='DLL 名称列表 (默认: 常用 DLL)')
    parser.add_argument('-o', '--output',
                        help='输出缓存文件 (默认: dll_cache.json)')
    parser.add_argument('-f', '--force', action='store_true',
                        help='强制刷新缓存')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='详细输出')
    
    args = parser.parse_args()
    
    # 设置日志
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='[%(levelname)s] %(message)s'
    )
    
    # 解析 DLL
    dll_names = args.dll if args.dll else get_common_dlls()
    cache_file = args.output if args.output else 'dll_cache.json'
    
    dll_exports = cache_dll_exports(dll_names, cache_file, args.force)
    
    # 统计
    print("\n" + "=" * 60)
    print("DLL 导出函数统计")
    print("=" * 60)
    
    total_exports = 0
    for dll_name, exports in dll_exports.items():
        count = len(exports)
        total_exports += count
        print(f"{dll_name:20s} : {count:5d} 个导出函数")
    
    print("=" * 60)
    print(f"总计: {len(dll_exports)} 个 DLL, {total_exports} 个导出函数")
    print(f"缓存文件: {cache_file}")
    print("=" * 60)
    
    # 显示示例
    if args.verbose and dll_exports:
        print("\n示例导出函数 (前 10 个):")
        first_dll = list(dll_exports.keys())[0]
        for i, func in enumerate(dll_exports[first_dll][:10], 1):
            print(f"  {i}. {func}")


if __name__ == "__main__":
    main()
