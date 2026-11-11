#!/usr/bin/env python3
"""Profile-only AES body decoding and PE reconstruction.

Adapted from the original ga-static-decrypt Python implementation, snapshot
59646549820cf32b66a07b46335fd844d42291bc. Recovery, scanning, native helpers and
profile generation are deliberately absent. Use ../decrypt.py as the CLI.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
import re
import struct
import time
from pathlib import Path
try:
    from Crypto.Cipher import AES as _CryptoAES
except ImportError:
    _CryptoAES = None

KONN = 1313754955

PACKED_PAYLOAD_OFF = 4096

KEY_LEN = 240

MAX_SPAN = 4096

def aes_master_from_inverse_schedule(schedule: bytes) -> bytes:
    """Recover the 32-byte AES-256 key from KONN's 240-byte inverse schedule."""
    if len(schedule) != KEY_LEN:
        raise ValueError(f'AES inverse schedule must be {KEY_LEN} bytes')

    def xtime(value: int) -> int:
        return (value << 1 ^ (283 if value & 128 else 0)) & 255

    def mix_word(word: int) -> int:
        a, b, c, d = word.to_bytes(4, 'big')
        return int.from_bytes(bytes((xtime(a) ^ xtime(b) ^ b ^ c ^ d, a ^ xtime(b) ^ xtime(c) ^ c ^ d, a ^ b ^ xtime(c) ^ xtime(d) ^ d, xtime(a) ^ a ^ b ^ c ^ xtime(d))), 'big')
    words = struct.unpack('<60I', schedule)
    master = struct.pack('>8I', *words[56:60], *(mix_word(word) for word in words[52:56]))
    sbox = bytes.fromhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')
    forward = list(struct.unpack('>8I', master))
    rcon = 1
    for index in range(8, 60):
        value = forward[-1]
        if index % 8 == 0:
            value = (value << 8 | value >> 24) & 4294967295
        if index % 8 in (0, 4):
            value = int.from_bytes(bytes((sbox[b] for b in value.to_bytes(4, 'big'))), 'big')
        if index % 8 == 0:
            value ^= rcon << 24
            rcon = xtime(rcon)
        forward.append(forward[index - 8] ^ value)
    for round_index in range(15):
        for column in range(4):
            expected = forward[(14 - round_index) * 4 + column]
            if 0 < round_index < 14:
                expected = mix_word(mix_word(mix_word(expected)))
            if words[round_index * 4 + column] != expected:
                raise ValueError('inconsistent AES-256 inverse round schedule')
    return master

SECTION_PRESETS = {47706: {'name': 'frozen-20260826', 'final_image_size': 198336512, 'size_of_code': 58258944, 'debug_dir': (194498560, 3835512), 'sections': [('.text', 9990960, 4096, 1610612768), ('il2cpp', 127000204, 9998336, 1610612768), ('.rdata', 36911468, 136998912, 1073741888), ('.data', 13381552, 173912064, 3221225536), ('.pdata', 7201032, 187293696, 1073741888), ('.reloc', 3835512, 194498560, 1107296320)]}}

def u16(buf, off: int) -> int:
    return buf[off] | buf[off + 1] << 8

def u32(buf, off: int) -> int:
    return buf[off] | buf[off + 1] << 8 | buf[off + 2] << 16 | buf[off + 3] << 24

def put16(buf: bytearray, off: int, value: int) -> None:
    buf[off] = value & 255
    buf[off + 1] = value >> 8 & 255

def put32(buf: bytearray, off: int, value: int) -> None:
    buf[off] = value & 255
    buf[off + 1] = value >> 8 & 255
    buf[off + 2] = value >> 16 & 255
    buf[off + 3] = value >> 24 & 255

def align(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & alignment - 1:
        raise ValueError(f'invalid PE alignment: 0x{alignment:X}')
    return value + alignment - 1 & ~(alignment - 1)

def align4(n: int) -> int:
    return n + 3 & ~3

def align16(n: int) -> int:
    return n + 15 & ~15

def log(msg: str) -> None:
    print(msg, flush=True)

def xor_chain(mid: bytearray, cipher: bytes, full: int) -> None:
    """mid[j] ^= cipher[j - 16] for j in 16 .. full-1 (single big-int XOR, C speed)."""
    if full <= 16:
        return
    span = full - 16
    left = int.from_bytes(mid[16:full], 'little') ^ int.from_bytes(cipher[:span], 'little')
    mid[16:full] = left.to_bytes(span, 'little')

IMAGE_DIRECTORY_ENTRY_IMPORT = 1

IMAGE_DIRECTORY_ENTRY_BASERELOC = 5

IMAGE_DIRECTORY_ENTRY_TLS = 9

IMAGE_DIRECTORY_ENTRY_IAT = 12

IMAGE_SCN_CNT_INITIALIZED_DATA = 64

IMAGE_SCN_MEM_EXECUTE = 536870912

IMAGE_SCN_MEM_READ = 1073741824

IMAGE_SCN_MEM_WRITE = 2147483648

@dataclass(frozen=True)
class Import:
    name: bytes | None
    ordinal: int | None

@dataclass(frozen=True)
class ImportGroup:
    dll: bytes
    first_thunk: int
    imports: tuple[Import, ...]

class Section:
    __slots__ = ('name', 'vsize', 'va', 'rsize', 'raw', 'chars', 'table_off')

    def __init__(self, buf: bytes, off: int) -> None:
        self.name = buf[off:off + 8].split(b'\x00')[0].decode('ascii', 'replace')
        self.vsize = u32(buf, off + 8)
        self.va = u32(buf, off + 12)
        self.rsize = u32(buf, off + 16)
        self.raw = u32(buf, off + 20)
        self.chars = u32(buf, off + 36)
        self.table_off = off

    @property
    def mapped_size(self) -> int:
        return max(self.vsize, self.rsize)

def rva_to_raw(rva: int, sections: list[Section]) -> int | None:
    for section in sections:
        if section.va <= rva < section.va + section.mapped_size:
            return section.raw + rva - section.va
    return None

class Pe:
    __slots__ = ('lfanew', 'opt', 'opt_size', 'entry', 'image_base', 'size_of_image', 'size_of_headers', 'num_rva', 'sections')

def parse_pe(buf: bytes) -> Pe | None:
    if len(buf) < 64 or buf[0] != 77 or buf[1] != 90:
        return None
    lfanew = u32(buf, 60)
    if lfanew + 24 >= len(buf) or u32(buf, lfanew) != 17744:
        return None
    sections = u16(buf, lfanew + 6)
    opt_size = u16(buf, lfanew + 20)
    opt = lfanew + 24
    if u16(buf, opt) != 523:
        return None
    pe = Pe()
    pe.lfanew = lfanew
    pe.opt = opt
    pe.opt_size = opt_size
    pe.entry = u32(buf, opt + 16)
    pe.image_base = struct.unpack_from('<Q', buf, opt + 24)[0]
    pe.size_of_image = u32(buf, opt + 56)
    pe.size_of_headers = u32(buf, opt + 60)
    pe.num_rva = u32(buf, opt + 108)
    sec_off = opt + opt_size
    pe.sections = [Section(buf, sec_off + i * 40) for i in range(sections)]
    return pe

def map_disk_sections(file: bytes, pe: Pe, image: bytearray) -> None:
    header = min(pe.size_of_headers, len(file), len(image))
    image[0:header] = file[0:header]
    for section in pe.sections:
        if section.rsize <= 0 or section.raw <= 0:
            continue
        count = min(section.rsize, section.vsize, len(file) - section.raw)
        if count <= 0 or section.va + count > len(image):
            continue
        image[section.va:section.va + count] = file[section.raw:section.raw + count]
        log(f'[map] {section.name:<8} file 0x{section.raw:X} -> VA 0x{section.va:X} {count:,}B')

def decode_header(file: bytes, off: int) -> list[int] | None:
    if len(file) < off + 32:
        log(f'[err] file too small for header at 0x{off:X}')
        return None
    src = [u32(file, off + i * 4) for i in range(8)]
    dst = [0] * 8
    dst[0] = src[0]
    acc = src[0]
    dst[1] = src[1] ^ acc
    acc = acc + src[1] & 4294967295
    dst[2] = src[2] ^ acc
    t = (src[2] + acc - 1 ^ 1) & 4294967295
    dst[3] = src[3] ^ t
    t = (src[3] + t - 2 ^ 4) & 4294967295
    dst[4] = src[4] ^ t
    t = (src[4] + t - 3 ^ 9) & 4294967295
    dst[5] = src[5] ^ t
    t = (src[5] + t - 4 ^ 16) & 4294967295
    dst[6] = src[6] ^ t
    t = (src[6] + t - 5 ^ 25) & 4294967295
    dst[7] = src[7] ^ t
    log('[hdr] raw  ' + ' '.join((f'{v:08X}' for v in src)))
    log('[hdr] dec  ' + ' '.join((f'{v & 4294967295:08X}' for v in dst)))
    if dst[1] != KONN:
        log(f'[err] magic mismatch: got 0x{dst[1]:08X} expected KONN (0x{KONN:08X})')
        return None
    log('[hdr] magic KONN ok')
    return dst

def decrypt_6e0(dest: bytearray, dest_off: int, src: bytes, src_off: int, size: int, key: int) -> None:
    count = size >> 2
    k = key + (~size & 4294967295) & 4294967295
    values = struct.unpack_from(f'<{count}I', src, src_off) if count else ()
    out = bytearray(count * 4)
    for i in range(count):
        c = values[i]
        p = c ^ k
        k = k + c + i & 4294967295
        k ^= i * i & 4294967295
        put32(out, i * 4, p)
    dest[dest_off:dest_off + count * 4] = out
    rem = size & 3
    if rem:
        dest[dest_off + count * 4:dest_off + count * 4 + rem] = src[src_off + count * 4:src_off + count * 4 + rem]
    log(f'[dec] 0x6E0 wrote {count:,} dwords ({count * 4:,} bytes)')

def stage1(packed: bytes) -> tuple[bytearray, dict, Pe]:
    pe = parse_pe(packed)
    if pe is None:
        raise SystemExit('[err] packed file is not a PE')
    log(f'[pe] ImageBase=0x{pe.image_base:X} SizeOfImage=0x{pe.size_of_image:X} entry=0x{pe.entry:X} secs={len(pe.sections)}')
    header = decode_header(packed, PACKED_PAYLOAD_OFF)
    if header is None:
        raise SystemExit(4)
    image = bytearray(pe.size_of_image)
    map_disk_sections(packed, pe, image)
    dest_rva = header[3]
    src_off = PACKED_PAYLOAD_OFF + header[4]
    chunk = header[6] - header[3] + 8192
    key = header[0]
    log(f'[hdr] [0] key/flags = 0x{header[0]:08X}')
    log(f'[hdr] [3] dest RVA  = 0x{header[3]:08X}')
    log(f'[hdr] [4] src add   = 0x{header[4]:08X}')
    log(f'[hdr] [5] total     = 0x{header[5]:08X} ({header[5]:,})')
    log(f'[hdr] [6] split     = 0x{header[6]:08X}')
    log(f'[dec] destRVA=0x{dest_rva:X} srcOff=0x{src_off:X} chunk=0x{chunk:X}({chunk:,}) key=0x{key:08X}')
    if src_off < 0 or dest_rva < 0 or chunk <= 0 or (src_off + chunk > len(packed)) or (dest_rva + chunk > len(image)):
        raise SystemExit('[err] header offsets out of range')
    decrypt_6e0(image, dest_rva, packed, src_off, chunk, key)
    tail = header[5] - chunk
    if tail > 0:
        tsrc = src_off + chunk
        tdst = dest_rva + chunk
        if tsrc + tail > len(packed) or tdst + tail > len(image):
            raise SystemExit(f'[err] tail copy out of range: 0x{tail:X} bytes')
        image[tdst:tdst + tail] = packed[tsrc:tsrc + tail]
        log(f'[dec] tail memcpy 0x{tail:X} bytes -> RVA 0x{tdst:X}')
    meta = {'header': header, 'dest_rva': dest_rva, 'chunk': chunk, 'tail': tail, 'written': [dest_rva, dest_rva + max(chunk, chunk + tail)]}
    return (image, meta, pe)

class AesHelper:
    """Use the verified AES-256 body primitive without executing helper bytes."""

    def __init__(self, schedule: bytes) -> None:
        if _CryptoAES is None:
            raise SystemExit('[err] profile decoding requires pycryptodome (Crypto.Cipher.AES)')
        try:
            master = aes_master_from_inverse_schedule(schedule)
        except (TypeError, ValueError, struct.error) as exc:
            raise SystemExit(f'[err] invalid AES inverse schedule: {exc}') from exc
        self._cipher = _CryptoAES.new(master, _CryptoAES.MODE_ECB)

    def decrypt_blocks(self, data: bytes) -> bytes:
        if len(data) & 15:
            raise ValueError('AES helper input must be 16-byte aligned')
        return self._cipher.decrypt(data)

def record_mid(helper: AesHelper, cipher: bytes, packed_size: int, span: int, sbox: bytes) -> bytearray:
    """Stage-2b mid buffer for one record.

    `cipher` is the `align4(packed_size)` slice; the helper runs over 16 B blocks up to
    `packed_size & ~15`, bytes in [full, span) keep their cipher value / zero padding,
    the XOR chain covers exactly [0, full) and the sbox covers the payload bytes.
    """
    full = packed_size & ~15
    mid = bytearray(span)
    mid[:len(cipher)] = cipher
    mid[:full] = helper.decrypt_blocks(cipher[:full])
    xor_chain(mid, cipher, full)
    mid[:packed_size] = mid[:packed_size].translate(sbox)
    return mid

def peek32(source: bytes, length: int, bit_offset: int) -> int:
    byte_offset = bit_offset >> 3
    length = min(length, len(source))
    value = 0
    for i in range(4):
        if byte_offset + i < length:
            value |= source[byte_offset + i] << 8 * i
    return value >> (bit_offset & 7) & 4294967295

def decode_stream(source: bytes, source_length: int, table: bytes, destination, start: int, length: int) -> int:
    """Port of the build's bit-unpack decoder; returns bits consumed, or -output on error."""
    bit_offset = 0
    output = start
    end = start + length
    hold = 0
    table_len = len(table)
    while output < end:
        bits = peek32(source, source_length, bit_offset)
        index = bits & 255
        entry = index * 3
        if entry + 3 > table_len:
            return -output
        node = u16(table, entry)
        bit_length = table[entry + 2]
        if node & 32768:
            symbol, length_bits = (node & 32767, bit_length)
        else:
            consumed = bit_length + 1
            mask = 1 << consumed - 1
            index = (node & 32767) + (1 if bits & mask else 0)
            for _ in range(32):
                entry = index * 3
                if entry + 3 > table_len:
                    return -output
                node = u16(table, entry)
                bit_length = table[entry + 2]
                if node & 32768:
                    break
                mask <<= 1
                consumed += 1
                index = (node & 32767) + (1 if bits & mask else 0)
            if not node & 32768:
                return -output
            symbol, length_bits = (node & 32767, bit_length)
        bit_offset += length_bits
        flags = symbol & 768
        payload = symbol & 255
        if flags == 0:
            destination[output] = payload
            output += 1
        elif flags == 256:
            hold = payload if hold == 0 else hold << 8 | payload
        elif flags == 768:
            distance = hold + payload
            if distance <= 0 or payload > end - output or output < distance:
                return -output
            for _ in range(payload):
                destination[output] = destination[output - distance]
                output += 1
            hold = 0
        elif flags == 512:
            repetitions = hold if hold else 1
            unit = payload
            count = repetitions * unit
            if count > end - output:
                return -output
            if unit in (1, 2, 4) and output >= unit:
                for i in range(count):
                    destination[output + i] = destination[output - unit + i % unit]
            output += count
            hold = 0
        else:
            destination[output] = payload
            output += 1
    return bit_offset

def decode_bodies(image: bytearray, packed: bytes, *, records, sbox: bytes, table: bytes, payload: int, helper: AesHelper) -> dict:
    cursor = payload
    valid = invalid = 0
    compared = matched = 0
    started = time.time()
    for index, (dest, packed_size, unpacked) in enumerate(records):
        if dest < 4096 or dest + unpacked > len(image) or packed_size == 0 or (packed_size > MAX_SPAN) or (unpacked == 0) or (unpacked > MAX_SPAN):
            raise SystemExit(f'[err] record {index} is invalid (dest=0x{dest:X} pk=0x{packed_size:X} un=0x{unpacked:X})')
        store = align4(packed_size)
        span = align16(store)
        if cursor + store > len(packed):
            raise SystemExit(f'[err] record {index} exceeds packed input at 0x{cursor:X}')
        cipher = packed[cursor:cursor + store]
        mid = record_mid(helper, cipher, packed_size, span, sbox)
        if packed_size == unpacked:
            image[dest:dest + unpacked] = mid[:unpacked]
            bits = packed_size * 8
        else:
            bits = decode_stream(bytes(mid), span, table, image, dest, unpacked)
        if bits >= 0 and (bits + 7) // 8 == packed_size:
            valid += 1
        else:
            invalid += 1
            if invalid <= 4:
                log(f'[warn] record {index}: dest=0x{dest:X} pk=0x{packed_size:X} un=0x{unpacked:X} bits={bits}')
        cursor += store
    elapsed = time.time() - started
    log(f'[body] records={len(records):,} streams={valid:,}/{invalid:,} payload=0x{payload:X} ({elapsed:.1f}s)')
    if invalid:
        raise SystemExit(f'[err] body stream invariant failed: valid={valid}, invalid={invalid}')
    return {'records': len(records), 'valid': valid, 'invalid': invalid, 'compared': compared, 'matched': matched, 'cursor_end': cursor}

def rebuild_original_pe(image: bytearray, preset: dict) -> int:
    sections = preset['sections']
    final_size = preset['final_image_size']
    if u16(image, 0) != 23117:
        raise SystemExit('[err] decoded image is not an MZ executable')
    pe = u32(image, 60)
    if pe + 264 > len(image) or u32(image, pe) != 17744:
        raise SystemExit('[err] decoded image has an invalid PE header')
    optional = pe + 24
    section_table = optional + u16(image, pe + 20)
    if section_table + len(sections) * 40 > len(image):
        raise SystemExit('[err] decoded section table is out of range')
    put16(image, pe + 6, len(sections))
    put32(image, optional + 8, preset['size_of_code'])
    put32(image, optional + 56, final_size)
    put32(image, optional + 112 + 8, 0)
    put32(image, optional + 112 + 12, 0)
    put32(image, optional + 112 + 40, preset['debug_dir'][0])
    put32(image, optional + 112 + 44, preset['debug_dir'][1])
    for i, (name, vsize, vaddr, chars) in enumerate(sections):
        section = section_table + i * 40
        image[section:section + 40] = b'\x00' * 40
        image[section:section + len(name)] = name.encode('ascii')
        nxt = sections[i + 1][2] if i + 1 < len(sections) else final_size
        put32(image, section + 8, vsize)
        put32(image, section + 12, vaddr)
        put32(image, section + 16, nxt - vaddr)
        put32(image, section + 20, vaddr)
        put32(image, section + 36, chars)
    debug_rva = u32(image, optional + 112 + 48)
    debug_size = u32(image, optional + 112 + 52)
    if debug_rva + debug_size <= len(image):
        for offset in range(0, max(0, debug_size - 27), 28):
            put32(image, debug_rva + offset + 24, u32(image, debug_rva + offset + 20))
    log(f"[pe] rebuilt original layout: {len(sections)} sections, size 0x{final_size:X} ({preset.get('name', 'custom')})")
    return final_size

def rebuild_rva_mapped_pe(image: bytearray, pe: Pe) -> int:
    """Repair a decoded image whose bytes are currently stored at RVA offsets.

    Stage 1 maps the packed input into a memory image, so its section table still
    contains the packed file offsets and compressed raw sizes.  A decoded output
    must expose the RVA-mapped bytes as ordinary section raw data; otherwise PE
    readers seek into the packed tail and see zeros or unrelated bytes.
    """
    file_alignment = u32(image, pe.opt + 36)
    size_of_image = pe.size_of_image
    if file_alignment <= 0 or size_of_image <= 0 or size_of_image > len(image):
        raise SystemExit('[err] decoded PE has invalid file/image alignment')
    for index, section in enumerate(pe.sections):
        if section.va < pe.size_of_headers or section.va >= size_of_image or section.va % file_alignment:
            raise SystemExit(f'[err] decoded section {section.name!r} has invalid RVA 0x{section.va:X}')
        next_va = pe.sections[index + 1].va if index + 1 < len(pe.sections) else size_of_image
        if next_va <= section.va:
            raise SystemExit(f'[err] decoded sections are not ordered at {section.name!r}')
        if index + 1 < len(pe.sections) and section.va + section.vsize > next_va:
            raise SystemExit(f'[err] decoded section {section.name!r} overlaps the next section')
        end = max(next_va, section.va + section.vsize)
        if end > size_of_image or end <= section.va:
            raise SystemExit(f'[err] decoded section {section.name!r} exceeds SizeOfImage')
        raw_size = end - section.va
        raw_size = (raw_size + file_alignment - 1) // file_alignment * file_alignment
        if section.va + raw_size > size_of_image or (index + 1 < len(pe.sections) and section.va + raw_size > next_va):
            raise SystemExit(f'[err] decoded section {section.name!r} is not file-alignable')
        put32(image, section.table_off + 16, raw_size)
        put32(image, section.table_off + 20, section.va)
    if pe.num_rva > 6:
        debug_dir = pe.opt + 112 + 6 * 8
        debug_rva = u32(image, debug_dir)
        debug_size = u32(image, debug_dir + 4)
        if debug_rva + debug_size <= size_of_image:
            for offset in range(0, debug_size - debug_size % 28, 28):
                entry = debug_rva + offset
                address = u32(image, entry + 20)
                if address:
                    put32(image, entry + 24, address)
    log(f'[pe] repaired RVA-mapped layout: {len(pe.sections)} sections, size 0x{size_of_image:X}')
    return size_of_image

def apply_stock_conform(image: bytearray) -> dict:
    """Add a real-value registration record that stock LibCpp2IL can discover.

    The game stores its registration in a compact native layout that the stock
    v31.1 reader does not recognize.  This leaves the runtime's module array
    untouched and writes a private copy with the mscorlib slot at the index
    expected by the stock backtracker, then points a 17-qword stock-layout
    record at the copied arrays.
    """
    pe = parse_pe(bytes(image))
    if pe is None:
        raise SystemExit('[err] --stock-conform requires a decoded PE image')
    image_size = max((section.va + section.vsize for section in pe.sections))
    image_base = pe.image_base

    def rva_to_offset(rva: int) -> int:
        for section in pe.sections:
            end = section.va + max(section.vsize, section.rsize)
            if section.va <= rva < end:
                offset = section.raw + (rva - section.va)
                if 0 <= offset < len(image):
                    return offset
        return -1

    def offset_to_rva(offset: int) -> int:
        for section in pe.sections:
            if section.raw <= offset < section.raw + section.rsize:
                return section.va + (offset - section.raw)
        return 0

    def normalize(value: int) -> int:
        if image_base <= value < image_base + image_size:
            return value - image_base
        return value

    def executable(rva: int) -> bool:
        return any((section.va <= rva < section.va + section.vsize and section.chars & 536870912 for section in pe.sections))

    def qword(offset: int) -> int:
        return struct.unpack_from('<Q', image, offset)[0]
    best_start = -1
    best_length = 0
    current_start = 0
    current_length = 0
    for offset in range(0, len(image) - 7, 8):
        value = normalize(qword(offset))
        if value and executable(value):
            if current_length == 0:
                current_start = offset
            current_length += 1
            if current_length > best_length:
                best_start = current_start
                best_length = current_length
        else:
            current_length = 0
    if best_length < 50000:
        raise SystemExit(f'[err] --stock-conform generic pointer run not found ({best_length:,} qwords)')
    gmp_offset = best_start
    gmp_count = best_length
    if best_start >= 8 and qword(best_start - 8) == 0:
        gmp_offset -= 8
        gmp_count += 1
    gmp_rva = offset_to_rva(gmp_offset)
    if not gmp_rva:
        raise SystemExit('[err] --stock-conform generic pointer run is not section-mapped')
    module_names = {}
    cursor = 0
    while True:
        suffix = image.find(b'.dll\x00', cursor)
        if suffix < 0:
            break
        start = suffix
        while start > max(0, suffix - 96) and (image[start - 1] in b'0123456789' or image[start - 1] in b'ABCDEFGHIJKLMNOPQRSTUVWXYZ' or image[start - 1] in b'abcdefghijklmnopqrstuvwxyz' or (image[start - 1] in b'_.+-')):
            start -= 1
        name = bytes(image[start:suffix + 4])
        if len(name) >= 5:
            rva = offset_to_rva(start)
            if rva:
                module_names.setdefault(rva, name)
        cursor = suffix + 5
    if len(module_names) < 32:
        raise SystemExit(f'[err] --stock-conform found only {len(module_names)} module names')
    module_structs = {}
    module_struct_names = {}
    for offset in range(0, len(image) - 23, 8):
        name_rva = normalize(qword(offset))
        if name_rva not in module_names:
            continue
        struct_rva = offset_to_rva(offset)
        if not struct_rva or struct_rva & 7:
            continue
        method_count = u32(image, offset + 8)
        method_pointers = qword(offset + 16)
        if method_count > 5000000:
            continue
        if method_count and (not method_pointers):
            continue
        if method_pointers and normalize(method_pointers) >= image_size:
            continue
        module_struct_names[struct_rva] = name_rva
    if len(module_struct_names) < 32:
        raise SystemExit(f'[err] --stock-conform found only {len(module_struct_names)} module structs')
    module_struct_set = set(module_struct_names)
    slot_indices = []
    for offset in range(0, len(image) - 7, 8):
        if normalize(qword(offset)) in module_struct_set:
            slot_indices.append(offset // 8)
    if len(slot_indices) < 32:
        raise SystemExit(f'[err] --stock-conform found only {len(slot_indices)} module pointer slots')
    best_first = best_last = slot_indices[0]
    run_first = run_last = slot_indices[0]
    best_filled = filled = 1
    for index in slot_indices[1:]:
        if index - run_last <= 3:
            run_last = index
            filled += 1
        else:
            if filled > best_filled:
                best_first, best_last, best_filled = (run_first, run_last, filled)
            run_first = run_last = index
            filled = 1
    if filled > best_filled:
        best_first, best_last, best_filled = (run_first, run_last, filled)
    cgm_count = best_last - best_first + 1
    if not 32 <= cgm_count <= 4096 or best_filled * 4 < cgm_count * 3:
        raise SystemExit(f'[err] --stock-conform module pointer span is implausible: {best_filled}/{cgm_count}')
    cgm_offset = best_first * 8
    cgm_rva = offset_to_rva(cgm_offset)
    if not cgm_rva:
        raise SystemExit('[err] --stock-conform module pointer array is not section-mapped')
    mscorlib_name_rvas = {rva for rva, name in module_names.items() if name == b'mscorlib.dll'}
    mscorlib_structs = {struct_rva for struct_rva, name_rva in module_struct_names.items() if name_rva in mscorlib_name_rvas}
    if len(mscorlib_structs) != 1:
        raise SystemExit(f'[err] --stock-conform expected one mscorlib module, got {len(mscorlib_structs)}')
    mscorlib_struct = next(iter(mscorlib_structs))
    array_offset = rva_to_offset(cgm_rva)
    target_index = cgm_count - 10
    mscorlib_index = None
    for index in range(cgm_count):
        if normalize(qword(array_offset + index * 8)) == mscorlib_struct:
            mscorlib_index = index
            break
    if mscorlib_index is None:
        raise SystemExit('[err] --stock-conform mscorlib is not in the module array')
    original_values = [qword(array_offset + index * 8) for index in range(cgm_count)]
    record_size = 17 * 8
    cgm_copy_size = cgm_count * 8
    reservation_size = record_size + cgm_copy_size
    record_offset = -1
    zero_block = b'\x00' * reservation_size
    for section in pe.sections:
        if section.chars & 536870912 or not section.chars & 2147483648:
            continue
        start = max(section.va, section.raw)
        end = min(len(image), section.va + max(section.vsize, section.rsize))
        candidate = end - reservation_size & ~7
        while candidate >= start:
            if image[candidate:candidate + reservation_size] == zero_block:
                record_offset = candidate
                break
            candidate -= 8
        if record_offset >= 0:
            break
    if record_offset < 0:
        raise SystemExit(f'[err] --stock-conform found no writable zero-filled PE padding for {reservation_size:,} bytes')
    record_rva = offset_to_rva(record_offset)
    cgm_copy_offset = record_offset + record_size
    cgm_copy_rva = offset_to_rva(cgm_copy_offset)
    if not record_rva or not cgm_copy_rva:
        raise SystemExit('[err] --stock-conform registration padding is not section-mapped')
    conformed_values = original_values[:]
    if mscorlib_index != target_index:
        conformed_values[mscorlib_index], conformed_values[target_index] = (conformed_values[target_index], conformed_values[mscorlib_index])
    struct.pack_into(f'<{cgm_count}Q', image, cgm_copy_offset, *conformed_values)
    registration = [0] * 17
    registration[2] = gmp_count
    registration[3] = image_base + gmp_rva
    registration[15] = cgm_count
    registration[16] = image_base + cgm_copy_rva
    struct.pack_into('<17Q', image, record_offset, *registration)
    log(f'[conform] stock LibCpp2IL record @0x{record_rva:X}; gmp=0x{gmp_rva:X}({gmp_count:,}) cgm-copy=0x{cgm_copy_rva:X}({cgm_count}) cgm-source=0x{cgm_rva:X} mscorlib-index={target_index}')
    return {'record_rva': record_rva, 'gmp_rva': gmp_rva, 'gmp_count': gmp_count, 'cgm_rva': cgm_copy_rva, 'cgm_source_rva': cgm_rva, 'cgm_count': cgm_count, 'patched_refs': 0}

def read_stable_imports(manifest_path: Path, sections: list[Section]) -> list[ImportGroup]:
    try:
        raw_groups = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f'[err] cannot read decoded import manifest {manifest_path}: {exc}')
    if not isinstance(raw_groups, list) or not raw_groups:
        raise SystemExit(f'[err] decoded import manifest {manifest_path} is not a non-empty list')
    rdata = next((section for section in sections if section.name == '.rdata'), None)
    if rdata is None:
        raise SystemExit('[err] decoded PE has no .rdata section for the stable IAT')
    old_iat_base = min((int(group['first_thunk']) for group in raw_groups))
    iat_delta = rdata.va - old_iat_base
    groups: list[ImportGroup] = []
    for index, raw_group in enumerate(raw_groups):
        if not isinstance(raw_group, dict):
            raise SystemExit(f'[err] decoded import manifest group {index} is not an object')
        try:
            dll = str(raw_group['dll']).encode('ascii')
            first_thunk = int(raw_group['first_thunk']) + iat_delta
            raw_imports = raw_group['imports']
        except (KeyError, TypeError, ValueError, UnicodeEncodeError) as exc:
            raise SystemExit(f'[err] invalid decoded import manifest group {index}: {exc}')
        imports: list[Import] = []
        for item_index, raw_import in enumerate(raw_imports):
            if 'ordinal' in raw_import:
                ordinal = int(raw_import['ordinal'])
                if not 0 < ordinal <= 65535:
                    raise SystemExit(f'[err] invalid ordinal at decoded import {index}:{item_index}')
                imports.append(Import(name=None, ordinal=ordinal))
            else:
                try:
                    name = str(raw_import['name']).encode('ascii')
                except (KeyError, TypeError, UnicodeEncodeError) as exc:
                    raise SystemExit(f'[err] invalid name at decoded import {index}:{item_index}: {exc}')
                imports.append(Import(name=name, ordinal=None))
        if not imports:
            raise SystemExit(f'[err] decoded import manifest group {index} has no functions')
        groups.append(ImportGroup(dll=dll, first_thunk=first_thunk, imports=tuple(imports)))
    return groups

def append_aligned(blob: bytearray, value: bytes, alignment: int) -> int:
    offset = align(len(blob), alignment)
    if len(blob) < offset:
        blob.extend(b'\x00' * (offset - len(blob)))
    blob.extend(value)
    return offset

def build_import_section(groups: list[ImportGroup], section_rva: int) -> tuple[bytes, int, int, int]:
    descriptor_size = (len(groups) + 1) * 20
    blob = bytearray(descriptor_size)
    descriptors: list[tuple[int, int, int]] = []
    first_thunk = min((group.first_thunk for group in groups))
    last_thunk = max((group.first_thunk + 8 * (len(group.imports) + 1) for group in groups))
    for group in groups:
        lookup_offset = append_aligned(blob, b'\x00' * (8 * (len(group.imports) + 1)), 8)
        for index, item in enumerate(group.imports):
            if item.ordinal is not None:
                value = 1 << 63 | item.ordinal
            else:
                name_offset = append_aligned(blob, b'\x00\x00' + item.name + b'\x00', 2)
                value = section_rva + name_offset
            struct.pack_into('<Q', blob, lookup_offset + index * 8, value)
        dll_offset = append_aligned(blob, group.dll + b'\x00', 1)
        descriptors.append((section_rva + lookup_offset, section_rva + dll_offset, group.first_thunk))
    for index, (lookup_rva, dll_rva, thunk_rva) in enumerate(descriptors):
        struct.pack_into('<IIIII', blob, index * 20, lookup_rva, 0, 0, dll_rva, thunk_rva)
    return (bytes(blob), descriptor_size, first_thunk, last_thunk)

def make_loadable(image: bytearray, manifest_path: Path) -> dict:
    """Transform a decoded flat PE into a Windows loadable DLL with stable imports and CRT entrypoint."""
    pe = parse_pe(bytes(image))
    if pe is None:
        raise SystemExit('[err] make_loadable requires a valid PE image')
    file_alignment = u32(image, pe.opt + 36)
    section_alignment = u32(image, pe.opt + 32)
    size_of_headers = pe.size_of_headers
    sections_offset = pe.opt + pe.opt_size
    section_count = len(pe.sections)
    if section_count + 1 > 65535 or sections_offset + (section_count + 1) * 40 > size_of_headers:
        raise SystemExit('[err] PE header has no room for the .idata section')
    for section in pe.sections:
        if section.raw != section.va or section.rsize < section.vsize:
            raise SystemExit(f'[err] decoded section {section.name!r} is not an RVA-mapped flat section (raw=0x{section.raw:X}, rva=0x{section.va:X}, raw-size=0x{section.rsize:X}, virtual-size=0x{section.vsize:X})')
        if section.va + section.rsize > len(image):
            raise SystemExit(f'[err] decoded section {section.name!r} exceeds the input file')
    groups = read_stable_imports(manifest_path, pe.sections)
    for group in groups:
        thunk_raw = rva_to_raw(group.first_thunk, pe.sections)
        thunk_end = rva_to_raw(group.first_thunk + 8 * len(group.imports), pe.sections)
        if thunk_raw is None or thunk_end is None:
            raise SystemExit(f"[err] decoded IAT for {group.dll.decode('ascii', 'replace')!r} is outside the flat PE sections (RVA 0x{group.first_thunk:X})")
    idata_rva = align(pe.size_of_image, section_alignment)
    raw_offset = align(len(image), file_alignment)
    section_data, import_directory_size, first_thunk, last_thunk = build_import_section(groups, idata_rva)
    raw_size = align(len(section_data), file_alignment)
    if len(image) < raw_offset:
        image.extend(b'\x00' * (raw_offset - len(image)))
    image.extend(section_data)
    image.extend(b'\x00' * (raw_offset + raw_size - len(image)))
    header = sections_offset + section_count * 40
    image[header:header + 40] = b'\x00' * 40
    image[header:header + 8] = b'.idata\x00\x00'
    struct.pack_into('<IIII', image, header + 8, len(section_data), idata_rva, raw_size, raw_offset)
    put32(image, header + 36, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
    put16(image, pe.lfanew + 6, section_count + 1)
    put32(image, pe.opt + 56, align(idata_rva + len(section_data), section_alignment))
    directories = pe.opt + 112
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, idata_rva)
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4, import_directory_size)
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_IAT * 8, first_thunk)
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_IAT * 8 + 4, last_thunk - first_thunk)
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8, 0)
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4, 0)
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_TLS * 8, 0)
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_TLS * 8 + 4, 0)
    put16(image, pe.opt + 70, u16(image, pe.opt + 70) & ~96)
    startup_pattern = re.compile(b'\\x48\\x89\\x5c\\x24\\x08\\x48\\x89\\x74\\x24\\x10\\x57\\x48\\x83\\xec\\x20\\x49\\x8b\\xf8\\x8b\\xda\\x48\\x8b\\xf1\\x83\\xfa\\x01\\x75\\x05\\xe8.{4}\\x4c\\x8b\\xc7\\x8b\\xd3\\x48\\x8b\\xce\\x48\\x8b\\x5c\\x24\\x30\\x48\\x8b\\x74\\x24\\x38\\x48\\x83\\xc4\\x20\\x5f\\xe9.{4}', re.DOTALL)
    entrypoints = []
    for section in pe.sections:
        if not section.chars & IMAGE_SCN_MEM_EXECUTE:
            continue
        for match in startup_pattern.finditer(image, section.raw, section.raw + section.rsize):
            entrypoints.append(section.va + match.start() - section.raw)
    if len(entrypoints) != 1:
        raise SystemExit(f'[err] expected one decoded CRT DLL entrypoint, found {len(entrypoints)}')
    entry_rva = entrypoints[0]
    put32(image, pe.opt + 16, entry_rva)
    log(f'[loadable] .idata @0x{idata_rva:X} ({len(section_data):,} B); entrypoint @0x{entry_rva:X}; {len(groups)} DLLs, {sum((len(g.imports) for g in groups))} imports')
    return {'dlls': len(groups), 'imports': sum((len(group.imports) for group in groups)), 'idata_rva': idata_rva, 'entrypoint_rva': entry_rva, 'size': len(image)}

def decode(packed: bytes, materials: dict[str, bytes], payload: int) -> tuple[bytearray, dict]:
    """Decode using already validated profile bytes, without writing any artifacts."""
    image, _, pe = stage1(packed)
    blob = materials["records"]
    records = [(u32(blob, at), u32(blob, at + 4), u32(blob, at + 12))
               for at in range(0, len(blob), 16)]
    helper = AesHelper(materials["key"])
    stats = decode_bodies(image, packed, records=records, sbox=materials["sbox"],
                          table=materials["pass3"], payload=payload, helper=helper)
    preset = SECTION_PRESETS.get(len(records))
    final_size = (rebuild_original_pe(image, preset) if preset is not None
                  else rebuild_rva_mapped_pe(image, pe))
    del image[final_size:]
    apply_stock_conform(image)
    make_loadable(image, Path(__file__).with_name("decoded-imports.json"))
    return image, stats
