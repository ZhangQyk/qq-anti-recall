#!/usr/bin/env python3
"""
Universal libkernel.so Anti-Recall Patcher
===========================================
基于 QAuxiliary NtRecallMsgHook.cc 的 AOB 特征码，自动适配所有版本。
将 RecallC2cSysMsg 和 RecallGroupSysMsg 函数入口替换为 RET，
使撤回通知直接被丢弃，实现"纯防撤回、无灰字"。

用法:
    python3 patch_libkernel.py <libkernel.so> [output.so]
    python3 patch_libkernel.py libkernel.so
    python3 patch_libkernel.py libkernel.so libkernel_patched.so
"""

import struct
import sys
import os
import shutil
from typing import Optional, Tuple, List

# ═══════════════════════════════════════════════════════════════════════
# ARM64 工具函数
# ═══════════════════════════════════════════════════════════════════════

RET_INSTRUCTION = struct.pack('<I', 0xD65F03C0)  # ARM64 RET


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def is_stp_x29_x30(inst: int) -> bool:
    """
    判断是否是 stp x29, x30, [sp, ...] 系列指令（含 offset / pre-index / post-index）。
    不依赖 imm7 的具体值，只检查操作码和寄存器编号。

    ARM64 STP 64-bit 编码:
      [31:30] = 10  (opc for STP)
      [26]    = 0   (integer variant)
      [25:23] = 001
      [22]    = 0   (store, not load)
      [14:10] = Rt2
      [9:5]   = Rn
      [4:0]   = Rt
    """
    # 必须是 STP (不是 LDP): bit 22 = 0
    if (inst >> 22) & 1:
        return False
    # 必须是 64-bit STP: bits [31:30] = 10
    if (inst >> 30) & 3 != 0b10:
        return False
    # Rt = x29 (bits [4:0] = 29)
    if (inst & 0x1F) != 29:
        return False
    # Rn = sp (bits [9:5] = 31, x31 = sp)
    if ((inst >> 5) & 0x1F) != 31:
        return False
    # Rt2 = x30 (bits [14:10] = 30)
    if ((inst >> 10) & 0x1F) != 30:
        return False
    return True


def is_valid_function_prologue(data: bytes, offset: int) -> bool:
    """检查 offset 处是否是有效的 ARM64 函数序言 (stp x29, x30, ...)"""
    if offset < 0 or offset + 4 > len(data):
        return False
    inst = read_u32(data, offset)
    return is_stp_x29_x30(inst)


def disasm_one(inst: int) -> str:
    """单条 ARM64 指令的简单反汇编"""
    if inst == 0xD65F03C0:
        return "ret"
    if is_stp_x29_x30(inst):
        # 提取 imm7（bits [21:15]），无符号
        imm7 = (inst >> 15) & 0x7F
        imm = imm7 * 8
        # 检查是否有 pre-index (bit 24 = 1) 或 post-index
        if ((inst >> 24) & 1):
            # 7-bit signed: 如果是负数，需要转换
            if imm7 & 0x40:  # sign bit
                imm7_signed = imm7 - 128
                imm = imm7_signed * 8
            return f"stp x29, x30, [sp, #{imm:#x}]!"
        else:
            return f"stp x29, x30, [sp, #{imm:#x}]"
    return f".inst {inst:#010x}"


# ═══════════════════════════════════════════════════════════════════════
# AOB 扫描器
# ═══════════════════════════════════════════════════════════════════════

def aob_scan(data: bytes, pattern: bytes, mask: bytes, step: int = 4) -> List[int]:
    """AOB 扫描，返回所有匹配偏移列表"""
    results = []
    pat_len = len(pattern)
    mask_len = len(mask)
    assert pat_len == mask_len, f"Pattern length {pat_len} != mask length {mask_len}"

    for i in range(0, len(data) - pat_len + 1, step):
        match = True
        for j in range(pat_len):
            if mask[j] == 0x00:  # wildcard
                continue
            if data[i + j] != pattern[j]:
                match = False
                break
        if match:
            results.append(i)
    return results


# ═══════════════════════════════════════════════════════════════════════
# 特征码定义（来自 NtRecallMsgHook.cc）
# ═══════════════════════════════════════════════════════════════════════

# RecallC2cSysMsg
# AOB:  09 8d 40 f8 ?? 03 00 aa 21 00 80 52 f3 03 02 aa 29 ?? 40 f9
# 验证器: stp x29,x30 序言
# 候选偏移: -0x20, -0x24, -0x28, -0x3c
C2C_PATTERN = bytes([0x09, 0x8d, 0x40, 0xf8, 0x00, 0x03, 0x00, 0xaa,
                      0x21, 0x00, 0x80, 0x52, 0xf3, 0x03, 0x02, 0xaa,
                      0x29, 0x00, 0x40, 0xf9])
C2C_MASK    = bytes([0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0x00, 0xff, 0xff])
C2C_CANDIDATE_OFFSETS = [-0x3c, -0x28, -0x24, -0x20]  # 按优先级排序

# RecallGroupSysMsg (QQ >= 9.2.20)
# AOB:  09 8d 40 f8 29 95 40 f9 ?? ?? 00 94 ?? 04 00 36 ?? 02 40 f9 61 00 80 52
GROUP_V2_PATTERN = bytes([0x09, 0x8d, 0x40, 0xf8, 0x29, 0x95, 0x40, 0xf9,
                           0x00, 0x00, 0x00, 0x94, 0x00, 0x04, 0x00, 0x36,
                           0x00, 0x02, 0x40, 0xf9, 0x61, 0x00, 0x80, 0x52])
GROUP_V2_MASK    = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff,
                           0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
GROUP_V2_CANDIDATE_OFFSETS = [-0x44]  # 只有一个候选

# RecallGroupSysMsg (QQ < 9.2.20)
# AOB:  28 00 40 f9 61 00 80 52 09 8d 40 f8 29 ?? 40 f9
GROUP_V1_PATTERN = bytes([0x28, 0x00, 0x40, 0xf9, 0x61, 0x00, 0x80, 0x52,
                           0x09, 0x8d, 0x40, 0xf8, 0x29, 0x00, 0x40, 0xf9])
GROUP_V1_MASK    = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff])
GROUP_V1_CANDIDATE_OFFSETS = [-0x18, -0x24, -0x28]  # 按优先级排序


# ═══════════════════════════════════════════════════════════════════════
# 搜索函数
# ═══════════════════════════════════════════════════════════════════════

def find_function_entry(data: bytes, pattern: bytes, mask: bytes,
                        candidate_offsets: List[int],
                        function_name: str) -> Optional[int]:
    """
    扫描特征码 → 从候选偏移中找到第一个有效的函数序言。
    返回函数入口偏移，或 None。
    """
    matches = aob_scan(data, pattern, mask, step=4)
    if not matches:
        print(f"  [✗] 特征码未匹配，可能版本不支持")
        return None

    print(f"  [✓] 特征码匹配成功 ({len(matches)} 处)")

    for match_off in matches:
        for offset in candidate_offsets:
            candidate = match_off + offset
            if candidate < 0 or candidate + 4 > len(data):
                continue
            if is_valid_function_prologue(data, candidate):
                inst = read_u32(data, candidate)
                print(f"  [✓] 函数入口: 0x{candidate:08x}  "
                      f"(match=0x{match_off:08x}, offset={offset:#x}, "
                      f"序言: {disasm_one(inst)})")
                return candidate

    # 如果所有候选偏移都失败，尝试扩大搜索范围
    print(f"  [!] 候选偏移均未命中，扩大搜索范围...")
    for match_off in matches:
        # 向前搜索最多 0x60 字节
        for back in range(0x10, 0x60, 4):
            candidate = match_off - back
            if candidate < 0:
                break
            if is_valid_function_prologue(data, candidate):
                inst = read_u32(data, candidate)
                print(f"  [✓] 函数入口: 0x{candidate:08x}  "
                      f"(match=0x{match_off:08x}, offset={-back:#x}, "
                      f"序言: {disasm_one(inst)})")
                return candidate

    print(f"  [✗] 未找到有效函数序言")
    return None


# ═══════════════════════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════════════════════

def hexdump_line(data: bytes, offset: int, length: int = 32) -> str:
    """返回一行 hexdump"""
    chunk = data[offset:offset + length]
    hex_str = ' '.join(f'{b:02x}' for b in chunk)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    return f"  0x{offset:08x}:  {hex_str:<48s}  {ascii_str}"


def patch_file(input_path: str, output_path: str) -> bool:
    """对 libkernel.so 执行防撤回 patch"""
    print("=" * 70)
    print("  Universal libkernel.so Anti-Recall Patcher")
    print("  基于 QAuxiliary NtRecallMsgHook.cc 特征码")
    print("=" * 70)

    # 读取文件
    print(f"\n[1] 读取文件: {input_path}")
    try:
        with open(input_path, 'rb') as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print(f"  [✗] 文件不存在: {input_path}")
        return False

    file_size = len(data)
    print(f"  [✓] 大小: {file_size:,} bytes ({file_size / 1024 / 1024:.1f} MB)")

    # 检查 ELF 头
    if data[:4] != b'\x7fELF':
        print(f"  [✗] 不是有效的 ELF 文件 (magic: {data[:4].hex()})")
        return False
    ei_class = data[4]  # 1=32bit, 2=64bit
    if ei_class != 2:
        print(f"  [✗] 不是 64 位 ELF (class={ei_class})")
        return False
    print(f"  [✓] ARM64 ELF 文件")

    # ── 搜索 RecallC2cSysMsg ──
    print(f"\n[2] 搜索 RecallC2cSysMsg...")
    c2c_entry = find_function_entry(data, C2C_PATTERN, C2C_MASK,
                                     C2C_CANDIDATE_OFFSETS, "RecallC2cSysMsg")

    # ── 搜索 RecallGroupSysMsg ──
    print(f"\n[3] 搜索 RecallGroupSysMsg...")
    # 先尝试 v2 (QQ >= 9.2.20)
    print(f"  [-] 尝试 v2 特征码 (QQ >= 9.2.20)...")
    group_entry = find_function_entry(data, GROUP_V2_PATTERN, GROUP_V2_MASK,
                                       GROUP_V2_CANDIDATE_OFFSETS,
                                       "RecallGroupSysMsg")
    # 如果 v2 失败，尝试 v1 (QQ < 9.2.20)
    if group_entry is None:
        print(f"\n  [-] 尝试 v1 特征码 (QQ < 9.2.20)...")
        group_entry = find_function_entry(data, GROUP_V1_PATTERN, GROUP_V1_MASK,
                                           GROUP_V1_CANDIDATE_OFFSETS,
                                           "RecallGroupSysMsg")

    # ── 检查结果 ──
    if c2c_entry is None and group_entry is None:
        print(f"\n{'='*70}")
        print("  [✗] 两个函数均未找到，无法 patch")
        print("  可能原因: QQ 版本过新，特征码已失效")
        print(f"{'='*70}")
        return False

    # ── 执行 Patch ──
    print(f"\n[4] 执行 Patch...")
    patches = []
    if c2c_entry is not None:
        patches.append(("RecallC2cSysMsg", c2c_entry))
    if group_entry is not None:
        patches.append(("RecallGroupSysMsg", group_entry))

    for name, offset in patches:
        old_inst = read_u32(data, offset)
        print(f"\n  {name}:")
        print(f"    Offset:     0x{offset:08x}")
        print(f"    Before:     {old_inst:#010x}  ({disasm_one(old_inst)})")

        # 写入 RET
        data[offset:offset + 4] = RET_INSTRUCTION

        new_inst = read_u32(data, offset)
        print(f"    After:      {new_inst:#010x}  ({disasm_one(new_inst)})")
        assert new_inst == 0xD65F03C0, f"Patch 验证失败: {name}"

        # 显示上下文
        print(f"    Context:")
        for line_off in range(offset - 16, offset + 20, 16):
            if line_off >= 0 and line_off + 16 <= len(data):
                prefix = "    " if line_off != offset else " >>> "
                print(f"{prefix}{hexdump_line(data, line_off, 16)}")

    # ── 写入文件 ──
    print(f"\n[5] 写入输出文件: {output_path}")
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(data)

    out_size = os.path.getsize(output_path)
    assert out_size == file_size, f"输出文件大小不一致: {out_size} != {file_size}"
    print(f"  [✓] 大小: {out_size:,} bytes (与原始一致)")

    # ── 最终验证 ──
    print(f"\n[6] 最终验证...")
    with open(output_path, 'rb') as f:
        verify_data = f.read()
    all_ok = True
    for name, offset in patches:
        inst = read_u32(verify_data, offset)
        if inst == 0xD65F03C0:
            print(f"  [✓] {name} @ 0x{offset:08x}: RET")
        else:
            print(f"  [✗] {name} @ 0x{offset:08x}: {inst:#010x} (期望 RET)")
            all_ok = False

    # ── 总结 ──
    print(f"\n{'='*70}")
    if all_ok:
        print(f"  ✓ Patch 成功!")
        print(f"  ✓ 输出: {output_path}")
        print(f"  ✓ 已 patch {len(patches)}/2 个函数:")
        for name, offset in patches:
            print(f"      - {name} @ 0x{offset:08x}")
        if len(patches) < 2:
            missing = [n for n in ["RecallC2cSysMsg", "RecallGroupSysMsg"]
                       if n not in dict(patches)]
            print(f"  ⚠ 未找到: {', '.join(missing)}")
            print(f"    可能该版本不包含此函数，或特征码需要更新")
        print(f"\n  使用方法: 将 patched 文件替换 APK 中的 lib/arm64-v8a/libkernel.so")
        print(f"            然后重新签名 APK")
    else:
        print(f"  ✗ 验证失败，请检查输出文件")
    print(f"{'='*70}")

    return all_ok


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    input_path = sys.argv[1]
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    else:
        dir_name = os.path.dirname(input_path) or '.'
        base_name = os.path.basename(input_path)
        name, ext = os.path.splitext(base_name)
        output_path = os.path.join(dir_name, f"{name}_patched{ext}")

    success = patch_file(input_path, output_path)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()