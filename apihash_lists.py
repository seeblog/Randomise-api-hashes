#!/usr/bin/env python3
"""
API 列表模块 - 动态解析版本
使用 dll_parser 模块动态加载 DLL 导出函数

优势:
1. 无需硬编码 67KB 的 API 列表
2. 自动适应系统版本
3. 支持任意 DLL
4. 易于维护
"""

import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# 尝试导入动态解析模块
try:
    from dll_parser import load_dll_exports, cache_dll_exports, get_common_dlls
    DYNAMIC_PARSING_AVAILABLE = True
except ImportError:
    logger.warning("dll_parser 模块不可用,将使用空列表")
    DYNAMIC_PARSING_AVAILABLE = False

# 默认 DLL 列表
# 策略: 使用缓存中的所有 DLL (如果缓存存在)
# 否则使用原始的 4 个 DLL (兼容性)
DEFAULT_DLLS = [
    'kernel32.dll',   # 核心 Windows API
    'ntdll.dll',      # 系统调用
    'advapi32.dll',   # 注册表/安全
    'ws2_32.dll',     # 网络 (Winsock)
    'wininet.dll',    # Internet (HTTP/FTP)
    'winhttp.dll',    # HTTP 客户端
    'dnsapi.dll',     # DNS 查询
    'user32.dll',     # GUI/窗口
    'shell32.dll',    # Shell 操作
    'ole32.dll',      # COM
    'crypt32.dll',    # 加密
    'psapi.dll',      # 进程信息
]

# 最小 DLL 列表 (原始 4 个,用于快速加载)
MINIMAL_DLLS = [
    'kernel32.dll',
    'ws2_32.dll',
    'wininet.dll',
    'dnsapi.dll',
]

# 全局缓存
_dll_exports_cache = None


def load_api_lists(dll_names=None, use_cache=True, verbose=False, minimal=False):
    """
    加载 API 列表
    
    Args:
        dll_names: DLL 名称列表 (None 则自动选择)
        use_cache: 是否使用缓存
        verbose: 详细输出
        minimal: 是否使用最小 DLL 列表 (仅 4 个原始 DLL)
    
    Returns:
        字典 {dll_name: [api_list]}
    """
    global _dll_exports_cache
    
    # 如果已有缓存,直接返回
    if use_cache and _dll_exports_cache is not None:
        return _dll_exports_cache
    
    if not DYNAMIC_PARSING_AVAILABLE:
        logger.error("动态解析不可用,请安装 pefile: pip install pefile")
        return {
            'kernel32.dll': [],
            'ws2_32.dll': [],
            'wininet.dll': [],
            'dnsapi.dll': [],
        }
    
    # 智能选择 DLL 列表
    if dll_names is None:
        # 如果指定最小模式,使用原始 4 个 DLL
        if minimal:
            dll_names = MINIMAL_DLLS
            if verbose:
                logger.info("使用最小 DLL 列表 (4 个)")
        else:
            # 否则使用完整列表 (12 个)
            dll_names = DEFAULT_DLLS
            if verbose:
                logger.info("使用完整 DLL 列表 (12 个)")
    
    # 尝试从缓存文件加载
    cache_file = Path(__file__).parent / 'dll_cache.json'
    
    if cache_file.exists() and use_cache:
        if verbose:
            logger.info(f"从缓存加载 API 列表: {cache_file}")
        
        try:
            _dll_exports_cache = cache_dll_exports(
                dll_names, 
                str(cache_file), 
                force_refresh=False
            )
            return _dll_exports_cache
        except Exception as e:
            logger.warning(f"加载缓存失败: {e}, 将重新解析")
    
    # 重新解析
    if verbose:
        logger.info(f"动态解析 {len(dll_names)} 个 DLL...")
    
    _dll_exports_cache = load_dll_exports(dll_names, verbose=verbose)
    
    # 保存缓存
    try:
        import json
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(_dll_exports_cache, f, indent=2)
        if verbose:
            logger.info(f"✓ 缓存已保存: {cache_file}")
    except Exception as e:
        logger.warning(f"保存缓存失败: {e}")
    
    return _dll_exports_cache


def get_api_list(dll_name):
    """
    获取指定 DLL 的 API 列表
    
    Args:
        dll_name: DLL 名称 (如 'kernel32.dll')
    
    Returns:
        API 列表
    """
    dll_exports = load_api_lists()
    return dll_exports.get(dll_name, [])


# 兼容性: 提供与原始脚本相同的变量名
def _init_lists():
    """初始化 API 列表 (兼容性)"""
    dll_exports = load_api_lists(verbose=False)
    
    return (
        dll_exports.get('kernel32.dll', []),
        dll_exports.get('ws2_32.dll', []),
        dll_exports.get('wininet.dll', []),
        dll_exports.get('dnsapi.dll', []),
    )


# 延迟加载 (仅在实际使用时加载)
k32_list = None
ws2_list = None
winnet_list = None
dnsapi_list = None


def ensure_lists_loaded():
    """确保 API 列表已加载"""
    global k32_list, ws2_list, winnet_list, dnsapi_list
    
    if k32_list is None:
        k32_list, ws2_list, winnet_list, dnsapi_list = _init_lists()


# 自动加载 (如果需要立即可用)
if os.environ.get('APIHASH_AUTOLOAD', '1') == '1':
    try:
        ensure_lists_loaded()
    except Exception as e:
        logger.warning(f"自动加载 API 列表失败: {e}")


# ============================================================================
# 测试代码
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    
    print("测试动态 API 列表加载...")
    print("=" * 60)
    
    # 加载 API 列表
    dll_exports = load_api_lists(verbose=True)
    
    # 显示统计
    print("\nAPI 列表统计:")
    print("=" * 60)
    for dll_name, api_list in dll_exports.items():
        print(f"{dll_name:20s} : {len(api_list):5d} 个 API")
    
    # 显示示例
    print("\n示例 API (kernel32.dll 前 10 个):")
    print("=" * 60)
    k32 = dll_exports.get('kernel32.dll', [])
    for i, api in enumerate(k32[:10], 1):
        print(f"  {i}. {api}")
    
    print("\n✓ 测试完成!")

