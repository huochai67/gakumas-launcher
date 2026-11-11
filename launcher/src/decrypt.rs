use std::{ collections::{BTreeMap, BTreeSet}, fs, path::Path };
use serde::Deserialize;
use sha2::{Digest, Sha256};
use crate::client::DynError;

const KONN: u32 = 1313754955;
const PACKED_PAYLOAD_OFF: usize = 4096;
const KEY_LEN: usize = 240;
const MAX_SPAN: usize = 4096;

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const DECODED_IMPORTS_JSON: &str = include_str!("../../decryptor/decoded-imports.json");

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline]
fn u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

#[inline]
fn put16(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn put32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn put64(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn align(value: usize, alignment: usize) -> Result<usize, DynError> {
    if alignment == 0 || (alignment & (alignment - 1)) != 0 {
        return Err(format!("invalid PE alignment: 0x{alignment:X}").into());
    }
    Ok((value + alignment - 1) & !(alignment - 1))
}

#[inline]
fn xtime(value: u8) -> u8 {
    (value << 1) ^ if (value & 0x80) != 0 { 0x1b } else { 0 }
}

#[inline]
fn mix_word(word: u32) -> u32 {
    let [a, b, c, d] = word.to_be_bytes();
    let r0 = xtime(a) ^ xtime(b) ^ b ^ c ^ d;
    let r1 = a ^ xtime(b) ^ xtime(c) ^ c ^ d;
    let r2 = a ^ b ^ xtime(c) ^ xtime(d) ^ d;
    let r3 = xtime(a) ^ a ^ b ^ c ^ xtime(d);
    u32::from_be_bytes([r0, r1, r2, r3])
}

struct Aes256Inv {
    words: [u32; 60],
    inv_sbox: [u8; 256],
    inv_mix_table: [[u32; 256]; 4],
}

impl Aes256Inv {
    fn new(schedule: &[u8]) -> Result<Self, DynError> {
        if schedule.len() != KEY_LEN {
            return Err(format!("AES inverse schedule must be {KEY_LEN} bytes").into());
        }
        let mut words = [0u32; 60];
        for (i, chunk) in schedule.chunks_exact(4).enumerate() {
            words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let mut forward = [0u32; 60];
        forward[0..4].copy_from_slice(&words[56..60]);
        for i in 0..4 {
            forward[4 + i] = mix_word(words[52 + i]);
        }
        let mut rcon = 1u8;
        for index in 8..60 {
            let mut value = forward[index - 1];
            if index % 8 == 0 {
                value = value.rotate_left(8);
            }
            if index % 8 == 0 || index % 8 == 4 {
                let [b0, b1, b2, b3] = value.to_be_bytes();
                value = u32::from_be_bytes([
                    AES_SBOX[b0 as usize],
                    AES_SBOX[b1 as usize],
                    AES_SBOX[b2 as usize],
                    AES_SBOX[b3 as usize],
                ]);
            }
            if index % 8 == 0 {
                value ^= (rcon as u32) << 24;
                rcon = xtime(rcon);
            }
            forward[index] = forward[index - 8] ^ value;
        }

        for round_index in 0..15 {
            for column in 0..4 {
                let mut expected = forward[(14 - round_index) * 4 + column];
                if round_index > 0 && round_index < 14 {
                    expected = mix_word(mix_word(mix_word(expected)));
                }
                if words[round_index * 4 + column] != expected {
                    return Err("inconsistent AES-256 inverse round schedule".into());
                }
            }
        }

        let mut inv_sbox = [0u8; 256];
        for (i, &v) in AES_SBOX.iter().enumerate() {
            inv_sbox[v as usize] = i as u8;
        }

        let mut inv_mix_table = [[0u32; 256]; 4];
        for x in 0..256usize {
            let b = inv_sbox[x] as u32;
            inv_mix_table[0][x] = mix_word(mix_word(mix_word(b << 24)));
            inv_mix_table[1][x] = mix_word(mix_word(mix_word(b << 16)));
            inv_mix_table[2][x] = mix_word(mix_word(mix_word(b << 8)));
            inv_mix_table[3][x] = mix_word(mix_word(mix_word(b)));
        }

        Ok(Self {
            words,
            inv_sbox,
            inv_mix_table,
        })
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8]) {
        let mut s0 = u32::from_be_bytes(block[0..4].try_into().unwrap()) ^ self.words[0];
        let mut s1 = u32::from_be_bytes(block[4..8].try_into().unwrap()) ^ self.words[1];
        let mut s2 = u32::from_be_bytes(block[8..12].try_into().unwrap()) ^ self.words[2];
        let mut s3 = u32::from_be_bytes(block[12..16].try_into().unwrap()) ^ self.words[3];

        for round in 1..14 {
            let k = round * 4;
            let t0 = self.inv_mix_table[0][(s0 >> 24) as usize]
                ^ self.inv_mix_table[1][((s3 >> 16) & 0xff) as usize]
                ^ self.inv_mix_table[2][((s2 >> 8) & 0xff) as usize]
                ^ self.inv_mix_table[3][(s1 & 0xff) as usize]
                ^ self.words[k];
            let t1 = self.inv_mix_table[0][(s1 >> 24) as usize]
                ^ self.inv_mix_table[1][((s0 >> 16) & 0xff) as usize]
                ^ self.inv_mix_table[2][((s3 >> 8) & 0xff) as usize]
                ^ self.inv_mix_table[3][(s2 & 0xff) as usize]
                ^ self.words[k + 1];
            let t2 = self.inv_mix_table[0][(s2 >> 24) as usize]
                ^ self.inv_mix_table[1][((s1 >> 16) & 0xff) as usize]
                ^ self.inv_mix_table[2][((s0 >> 8) & 0xff) as usize]
                ^ self.inv_mix_table[3][(s3 & 0xff) as usize]
                ^ self.words[k + 2];
            let t3 = self.inv_mix_table[0][(s3 >> 24) as usize]
                ^ self.inv_mix_table[1][((s2 >> 16) & 0xff) as usize]
                ^ self.inv_mix_table[2][((s1 >> 8) & 0xff) as usize]
                ^ self.inv_mix_table[3][(s0 & 0xff) as usize]
                ^ self.words[k + 3];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }

        let f0 = u32::from_be_bytes([
            self.inv_sbox[(s0 >> 24) as usize],
            self.inv_sbox[((s3 >> 16) & 0xff) as usize],
            self.inv_sbox[((s2 >> 8) & 0xff) as usize],
            self.inv_sbox[(s1 & 0xff) as usize],
        ]) ^ self.words[56];
        let f1 = u32::from_be_bytes([
            self.inv_sbox[(s1 >> 24) as usize],
            self.inv_sbox[((s0 >> 16) & 0xff) as usize],
            self.inv_sbox[((s3 >> 8) & 0xff) as usize],
            self.inv_sbox[(s2 & 0xff) as usize],
        ]) ^ self.words[57];
        let f2 = u32::from_be_bytes([
            self.inv_sbox[(s2 >> 24) as usize],
            self.inv_sbox[((s1 >> 16) & 0xff) as usize],
            self.inv_sbox[((s0 >> 8) & 0xff) as usize],
            self.inv_sbox[(s3 & 0xff) as usize],
        ]) ^ self.words[58];
        let f3 = u32::from_be_bytes([
            self.inv_sbox[(s3 >> 24) as usize],
            self.inv_sbox[((s2 >> 16) & 0xff) as usize],
            self.inv_sbox[((s1 >> 8) & 0xff) as usize],
            self.inv_sbox[(s0 & 0xff) as usize],
        ]) ^ self.words[59];

        block[0..4].copy_from_slice(&f0.to_be_bytes());
        block[4..8].copy_from_slice(&f1.to_be_bytes());
        block[8..12].copy_from_slice(&f2.to_be_bytes());
        block[12..16].copy_from_slice(&f3.to_be_bytes());
    }
}

#[derive(Clone)]
struct Section {
    name: String,
    vsize: usize,
    va: usize,
    rsize: usize,
    raw: usize,
    chars: u32,
    table_off: usize,
}

impl Section {
    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let raw_name = &buf[off..off + 8];
        let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
        Self {
            name,
            vsize: u32_le(buf, off + 8) as usize,
            va: u32_le(buf, off + 12) as usize,
            rsize: u32_le(buf, off + 16) as usize,
            raw: u32_le(buf, off + 20) as usize,
            chars: u32_le(buf, off + 36),
            table_off: off,
        }
    }

    fn mapped_size(&self) -> usize {
        self.vsize.max(self.rsize)
    }
}

struct Pe {
    lfanew: usize,
    opt: usize,
    opt_size: usize,
    image_base: u64,
    size_of_image: usize,
    size_of_headers: usize,
    num_rva: usize,
    sections: Vec<Section>,
}

fn parse_pe(buf: &[u8]) -> Option<Pe> {
    if buf.len() < 64 || buf[0] != 77 || buf[1] != 90 {
        return None;
    }
    let lfanew = u32_le(buf, 60) as usize;
    if lfanew + 24 >= buf.len() || u32_le(buf, lfanew) != 17744 {
        return None;
    }
    let section_count = u16_le(buf, lfanew + 6) as usize;
    let opt_size = u16_le(buf, lfanew + 20) as usize;
    let opt = lfanew + 24;
    if opt + opt_size > buf.len() || u16_le(buf, opt) != 523 {
        return None;
    }
    let sec_off = opt + opt_size;
    if sec_off + section_count * 40 > buf.len() {
        return None;
    }
    let sections = (0..section_count)
        .map(|i| Section::from_bytes(buf, sec_off + i * 40))
        .collect();
    Some(Pe {
        lfanew,
        opt,
        opt_size,
        image_base: u64_le(buf, opt + 24),
        size_of_image: u32_le(buf, opt + 56) as usize,
        size_of_headers: u32_le(buf, opt + 60) as usize,
        num_rva: u32_le(buf, opt + 108) as usize,
        sections,
    })
}

fn rva_to_raw(rva: usize, sections: &[Section]) -> Option<usize> {
    for section in sections {
        if rva >= section.va && rva < section.va + section.mapped_size() {
            return Some(section.raw + rva - section.va);
        }
    }
    None
}

fn stage1(packed: &[u8]) -> Result<(Vec<u8>, Pe), DynError> {
    let pe = parse_pe(packed).ok_or("packed file is not a valid PE64 image")?;
    if packed.len() < PACKED_PAYLOAD_OFF + 32 {
        return Err("packed file too small for KONN header".into());
    }
    let mut src = [0u32; 8];
    for i in 0..8 {
        src[i] = u32_le(packed, PACKED_PAYLOAD_OFF + i * 4);
    }
    let mut dst = [0u32; 8];
    dst[0] = src[0];
    let mut acc = src[0];
    dst[1] = src[1] ^ acc;
    acc = acc.wrapping_add(src[1]);
    dst[2] = src[2] ^ acc;
    let mut t = src[2].wrapping_add(acc).wrapping_sub(1) ^ 1;
    dst[3] = src[3] ^ t;
    t = src[3].wrapping_add(t).wrapping_sub(2) ^ 4;
    dst[4] = src[4] ^ t;
    t = src[4].wrapping_add(t).wrapping_sub(3) ^ 9;
    dst[5] = src[5] ^ t;
    t = src[5].wrapping_add(t).wrapping_sub(4) ^ 16;
    dst[6] = src[6] ^ t;
    t = src[6].wrapping_add(t).wrapping_sub(5) ^ 25;
    dst[7] = src[7] ^ t;

    if dst[1] != KONN {
        return Err(format!("KONN magic mismatch: got 0x{:08X}", dst[1]).into());
    }

    let mut image = vec![0u8; pe.size_of_image];
    let header_len = pe.size_of_headers.min(packed.len()).min(image.len());
    image[..header_len].copy_from_slice(&packed[..header_len]);
    for section in &pe.sections {
        if section.rsize == 0 || section.raw == 0 || section.raw >= packed.len() {
            continue;
        }
        let count = section.rsize.min(section.vsize).min(packed.len() - section.raw);
        if count == 0 || section.va + count > image.len() {
            continue;
        }
        image[section.va..section.va + count]
            .copy_from_slice(&packed[section.raw..section.raw + count]);
    }

    let dest_rva = dst[3] as usize;
    let src_off = PACKED_PAYLOAD_OFF + dst[4] as usize;
    let chunk = (dst[6] as usize + 8192).checked_sub(dst[3] as usize).ok_or("invalid KONN chunk size")?;
    let key = dst[0];
    if chunk == 0 || src_off + chunk > packed.len() || dest_rva + chunk > image.len() {
        return Err("KONN header offsets out of range".into());
    }

    let count = chunk >> 2;
    let mut k = key.wrapping_add(!(chunk as u32));
    for i in 0..count {
        let c = u32_le(packed, src_off + i * 4);
        let p = c ^ k;
        let idx = i as u32;
        k = k.wrapping_add(c).wrapping_add(idx);
        k ^= idx.wrapping_mul(idx);
        put32(&mut image, dest_rva + i * 4, p);
    }
    let rem = chunk & 3;
    if rem != 0 {
        image[dest_rva + count * 4..dest_rva + count * 4 + rem]
            .copy_from_slice(&packed[src_off + count * 4..src_off + count * 4 + rem]);
    }

    let total = dst[5] as usize;
    if total > chunk {
        let tail = total - chunk;
        let tsrc = src_off + chunk;
        let tdst = dest_rva + chunk;
        if tsrc + tail > packed.len() || tdst + tail > image.len() {
            return Err("KONN tail copy out of range".into());
        }
        image[tdst..tdst + tail].copy_from_slice(&packed[tsrc..tsrc + tail]);
    }

    Ok((image, pe))
}

#[inline]
fn peek32(source: &[u8], length: usize, bit_offset: usize) -> u32 {
    let byte_offset = bit_offset >> 3;
    let length = length.min(source.len());
    let mut value = 0u64;
    for i in 0..4 {
        if byte_offset + i < length {
            value |= (source[byte_offset + i] as u64) << (8 * i);
        }
    }
    ((value >> (bit_offset & 7)) & 0xffff_ffff) as u32
}

fn decode_stream(
    source: &[u8],
    source_length: usize,
    table: &[u8],
    destination: &mut [u8],
    start: usize,
    length: usize,
) -> isize {
    let mut bit_offset = 0usize;
    let mut output = start;
    let end = start + length;
    let mut hold = 0usize;
    let table_len = table.len();

    while output < end {
        let bits = peek32(source, source_length, bit_offset);
        let mut index = (bits & 255) as usize;
        let mut entry = index * 3;
        if entry + 3 > table_len {
            return -(output as isize);
        }
        let mut node = u16_le(table, entry);
        let mut bit_length = table[entry + 2] as usize;
        let (symbol, length_bits) = if (node & 0x8000) != 0 {
            ((node & 0x7fff) as usize, bit_length)
        } else {
            let mut mask = 1u32 << bit_length;
            index = (node & 0x7fff) as usize + usize::from((bits & mask) != 0);
            for _ in 0..32 {
                entry = index * 3;
                if entry + 3 > table_len {
                    return -(output as isize);
                }
                node = u16_le(table, entry);
                bit_length = table[entry + 2] as usize;
                if (node & 0x8000) != 0 {
                    break;
                }
                mask = mask.wrapping_shl(1);
                index = (node & 0x7fff) as usize + usize::from((bits & mask) != 0);
            }
            if (node & 0x8000) == 0 {
                return -(output as isize);
            }
            ((node & 0x7fff) as usize, bit_length)
        };

        bit_offset += length_bits;
        let flags = symbol & 0x300;
        let payload = symbol & 0xff;
        if flags == 0 {
            destination[output] = payload as u8;
            output += 1;
        } else if flags == 0x100 {
            hold = if hold == 0 { payload } else { (hold << 8) | payload };
        } else if flags == 0x300 {
            let distance = hold + payload;
            if distance == 0 || payload > end - output || output < distance {
                return -(output as isize);
            }
            for _ in 0..payload {
                destination[output] = destination[output - distance];
                output += 1;
            }
            hold = 0;
        } else if flags == 0x200 {
            let repetitions = if hold != 0 { hold } else { 1 };
            let unit = payload;
            let count = repetitions * unit;
            if count > end - output {
                return -(output as isize);
            }
            if (unit == 1 || unit == 2 || unit == 4) && output >= unit {
                for i in 0..count {
                    destination[output + i] = destination[output - unit + (i % unit)];
                }
            }
            output += count;
            hold = 0;
        } else {
            destination[output] = payload as u8;
            output += 1;
        }
    }

    bit_offset as isize
}

fn decode_bodies(
    image: &mut [u8],
    packed: &[u8],
    records: &[(usize, usize, usize)],
    sbox: &[u8],
    table: &[u8],
    payload: usize,
    aes: &Aes256Inv,
) -> Result<(), DynError> {
    if sbox.len() < 256 {
        return Err("sbox.bin must be at least 256 bytes".into());
    }
    let mut cursor = payload;
    let mut mid = [0u8; MAX_SPAN];

    for (index, &(dest, packed_size, unpacked)) in records.iter().enumerate() {
        if dest < 4096
            || dest + unpacked > image.len()
            || packed_size == 0
            || packed_size > MAX_SPAN
            || unpacked == 0
            || unpacked > MAX_SPAN
        {
            return Err(format!(
                "record {index} is invalid (dest=0x{dest:X} pk=0x{packed_size:X} un=0x{unpacked:X})"
            )
            .into());
        }
        let store = (packed_size + 3) & !3;
        let span = (store + 15) & !15;
        if cursor + store > packed.len() {
            return Err(format!("record {index} exceeds packed input at 0x{cursor:X}").into());
        }
        let cipher = &packed[cursor..cursor + store];
        let full = packed_size & !15;

        mid[..store].copy_from_slice(cipher);
        mid[store..span].fill(0);
        for block in mid[..full].chunks_exact_mut(16) {
            aes.decrypt_block(block);
        }
        if full > 16 {
            for j in 16..full {
                mid[j] ^= cipher[j - 16];
            }
        }
        for b in &mut mid[..packed_size] {
            *b = sbox[*b as usize];
        }

        let bits = if packed_size == unpacked {
            image[dest..dest + unpacked].copy_from_slice(&mid[..unpacked]);
            (packed_size * 8) as isize
        } else {
            decode_stream(&mid[..span], span, table, image, dest, unpacked)
        };
        if bits < 0 || ((bits as usize + 7) / 8) != packed_size {
            return Err(format!("record {index} stream decode failed (bits={bits})").into());
        }
        cursor += store;
    }
    Ok(())
}

fn rebuild_frozen_preset(image: &mut [u8]) -> Result<usize, DynError> {
    let final_size = 198_336_512usize;
    let size_of_code = 58_258_944u32;
    let debug_dir = (194_498_560u32, 3_835_512u32);
    let sections: [(&str, u32, u32, u32); 6] = [
        (".text", 9_990_960, 4096, 1_610_612_768),
        ("il2cpp", 127_000_204, 9_998_336, 1_610_612_768),
        (".rdata", 36_911_468, 136_998_912, 1_073_741_888),
        (".data", 13_381_552, 173_912_064, 3_221_225_536),
        (".pdata", 7_201_032, 187_293_696, 1_073_741_888),
        (".reloc", 3_835_512, 194_498_560, 1_107_296_320),
    ];
    if u16_le(image, 0) != 23117 {
        return Err("decoded image is not an MZ executable".into());
    }
    let pe = u32_le(image, 60) as usize;
    if pe + 264 > image.len() || u32_le(image, pe) != 17744 {
        return Err("decoded image has an invalid PE header".into());
    }
    let optional = pe + 24;
    let section_table = optional + u16_le(image, pe + 20) as usize;
    if section_table + sections.len() * 40 > image.len() {
        return Err("decoded section table is out of range".into());
    }
    put16(image, pe + 6, sections.len() as u16);
    put32(image, optional + 8, size_of_code);
    put32(image, optional + 56, final_size as u32);
    put32(image, optional + 112 + 8, 0);
    put32(image, optional + 112 + 12, 0);
    put32(image, optional + 112 + 40, debug_dir.0);
    put32(image, optional + 112 + 44, debug_dir.1);
    for (i, &(name, vsize, vaddr, chars)) in sections.iter().enumerate() {
        let section = section_table + i * 40;
        image[section..section + 40].fill(0);
        image[section..section + name.len()].copy_from_slice(name.as_bytes());
        let nxt = if i + 1 < sections.len() {
            sections[i + 1].2
        } else {
            final_size as u32
        };
        put32(image, section + 8, vsize);
        put32(image, section + 12, vaddr);
        put32(image, section + 16, nxt - vaddr);
        put32(image, section + 20, vaddr);
        put32(image, section + 36, chars);
    }
    let debug_rva = u32_le(image, optional + 112 + 48) as usize;
    let debug_size = u32_le(image, optional + 112 + 52) as usize;
    if debug_rva + debug_size <= image.len() && debug_size >= 28 {
        let mut offset = 0;
        while offset + 28 <= debug_size {
            let addr = u32_le(image, debug_rva + offset + 20);
            put32(image, debug_rva + offset + 24, addr);
            offset += 28;
        }
    }
    Ok(final_size)
}

fn rebuild_rva_mapped_pe(image: &mut [u8], pe: &Pe) -> Result<usize, DynError> {
    let file_alignment = u32_le(image, pe.opt + 36) as usize;
    let size_of_image = pe.size_of_image;
    if file_alignment == 0 || size_of_image == 0 || size_of_image > image.len() {
        return Err("decoded PE has invalid file/image alignment".into());
    }
    for (index, section) in pe.sections.iter().enumerate() {
        if section.va < pe.size_of_headers
            || section.va >= size_of_image
            || section.va % file_alignment != 0
        {
            return Err(format!("decoded section {} has invalid RVA", section.name).into());
        }
        let next_va = if index + 1 < pe.sections.len() {
            pe.sections[index + 1].va
        } else {
            size_of_image
        };
        if next_va <= section.va
            || (index + 1 < pe.sections.len() && section.va + section.vsize > next_va)
        {
            return Err(format!("decoded section {} overlaps next section", section.name).into());
        }
        let end = next_va.max(section.va + section.vsize);
        if end > size_of_image || end <= section.va {
            return Err(format!("decoded section {} exceeds SizeOfImage", section.name).into());
        }
        let raw_size = ((end - section.va + file_alignment - 1) / file_alignment) * file_alignment;
        if section.va + raw_size > size_of_image
            || (index + 1 < pe.sections.len() && section.va + raw_size > next_va)
        {
            return Err(format!("decoded section {} is not file-alignable", section.name).into());
        }
        put32(image, section.table_off + 16, raw_size as u32);
        put32(image, section.table_off + 20, section.va as u32);
    }
    if pe.num_rva > 6 {
        let debug_dir = pe.opt + 112 + 6 * 8;
        let debug_rva = u32_le(image, debug_dir) as usize;
        let debug_size = u32_le(image, debug_dir + 4) as usize;
        if debug_rva + debug_size <= size_of_image {
            let mut offset = 0;
            while offset + 28 <= debug_size {
                let entry = debug_rva + offset;
                let address = u32_le(image, entry + 20);
                if address != 0 {
                    put32(image, entry + 24, address);
                }
                offset += 28;
            }
        }
    }
    Ok(size_of_image)
}

fn apply_stock_conform(image: &mut [u8]) -> Result<(), DynError> {
    let pe = parse_pe(image).ok_or("stock-conform requires a decoded PE image")?;
    let image_size = pe
        .sections
        .iter()
        .map(|s| (s.va + s.vsize) as u64)
        .max()
        .unwrap_or(0);
    let image_base = pe.image_base;

    let rva_to_offset = |rva: u64| -> Option<usize> {
        let rva = rva as usize;
        for section in &pe.sections {
            let end = section.va + section.vsize.max(section.rsize);
            if rva >= section.va && rva < end {
                let offset = section.raw + (rva - section.va);
                if offset < image.len() {
                    return Some(offset);
                }
            }
        }
        None
    };

    let offset_to_rva = |offset: usize| -> u64 {
        for section in &pe.sections {
            if offset >= section.raw && offset < section.raw + section.rsize {
                return (section.va + (offset - section.raw)) as u64;
            }
        }
        0
    };

    let normalize = |value: u64| -> u64 {
        if value >= image_base && value < image_base + image_size {
            value - image_base
        } else {
            value
        }
    };

    let executable = |rva: u64| -> bool {
        let rva = rva as usize;
        pe.sections.iter().any(|s| {
            rva >= s.va && rva < s.va + s.vsize && (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0
        })
    };

    let mut best_start = 0usize;
    let mut best_length = 0usize;
    let mut current_start = 0usize;
    let mut current_length = 0usize;

    let mut offset = 0usize;
    while offset + 8 <= image.len() {
        let value = normalize(u64_le(image, offset));
        if value != 0 && executable(value) {
            if current_length == 0 {
                current_start = offset;
            }
            current_length += 1;
            if current_length > best_length {
                best_start = current_start;
                best_length = current_length;
            }
        } else {
            current_length = 0;
        }
        offset += 8;
    }

    if best_length < 50_000 {
        return Err(format!("generic pointer run not found ({best_length} qwords)").into());
    }
    let mut gmp_offset = best_start;
    let mut gmp_count = best_length;
    if best_start >= 8 && u64_le(image, best_start - 8) == 0 {
        gmp_offset -= 8;
        gmp_count += 1;
    }
    let gmp_rva = offset_to_rva(gmp_offset);
    if gmp_rva == 0 {
        return Err("generic pointer run is not section-mapped".into());
    }

    let mut module_names = BTreeMap::<u64, Vec<u8>>::new();
    let needle = b".dll\0";
    let mut cursor = 0usize;
    while cursor + needle.len() <= image.len() {
        let Some(pos) = image[cursor..].windows(needle.len()).position(|w| w == needle) else {
            break;
        };
        let suffix = cursor + pos;
        let min_start = suffix.saturating_sub(96);
        let mut start = suffix;
        while start > min_start {
            let b = image[start - 1];
            if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-') {
                start -= 1;
            } else {
                break;
            }
        }
        let name = &image[start..suffix + 4];
        if name.len() >= 5 {
            let rva = offset_to_rva(start);
            if rva != 0 {
                module_names.entry(rva).or_insert_with(|| name.to_vec());
            }
        }
        cursor = suffix + 5;
    }
    if module_names.len() < 32 {
        return Err(format!("found only {} module names", module_names.len()).into());
    }

    let mut module_struct_names = BTreeMap::<u64, u64>::new();
    let mut off = 0usize;
    while off + 24 <= image.len() {
        let name_rva = normalize(u64_le(image, off));
        if module_names.contains_key(&name_rva) {
            let struct_rva = offset_to_rva(off);
            if struct_rva != 0 && (struct_rva & 7) == 0 {
                let method_count = u32_le(image, off + 8);
                let method_pointers = u64_le(image, off + 16);
                if method_count <= 5_000_000
                    && (method_count == 0 || method_pointers != 0)
                    && (method_pointers == 0 || normalize(method_pointers) < image_size)
                {
                    module_struct_names.insert(struct_rva, name_rva);
                }
            }
        }
        off += 8;
    }
    if module_struct_names.len() < 32 {
        return Err(format!("found only {} module structs", module_struct_names.len()).into());
    }

    let mut slot_indices = Vec::new();
    let mut off = 0usize;
    while off + 8 <= image.len() {
        if module_struct_names.contains_key(&normalize(u64_le(image, off))) {
            slot_indices.push(off / 8);
        }
        off += 8;
    }
    if slot_indices.len() < 32 {
        return Err("insufficient module pointer slots".into());
    }

    let mut best_first = slot_indices[0];
    let mut best_last = slot_indices[0];
    let mut run_first = slot_indices[0];
    let mut run_last = slot_indices[0];
    let mut best_filled = 1usize;
    let mut filled = 1usize;
    for &index in &slot_indices[1..] {
        if index - run_last <= 3 {
            run_last = index;
            filled += 1;
        } else {
            if filled > best_filled {
                best_first = run_first;
                best_last = run_last;
                best_filled = filled;
            }
            run_first = index;
            run_last = index;
            filled = 1;
        }
    }
    if filled > best_filled {
        best_first = run_first;
        best_last = run_last;
        best_filled = filled;
    }
    let cgm_count = best_last - best_first + 1;
    if !(32..=4096).contains(&cgm_count) || best_filled * 4 < cgm_count * 3 {
        return Err("module pointer span is implausible".into());
    }
    let cgm_offset = best_first * 8;
    let cgm_rva = offset_to_rva(cgm_offset);
    if cgm_rva == 0 {
        return Err("module pointer array is not section-mapped".into());
    }

    let mscorlib_name_rvas: BTreeSet<u64> = module_names
        .iter()
        .filter(|(_, name)| name.as_slice() == b"mscorlib.dll")
        .map(|(&rva, _)| rva)
        .collect();
    let mscorlib_structs: Vec<u64> = module_struct_names
        .iter()
        .filter(|(_, name_rva)| mscorlib_name_rvas.contains(name_rva))
        .map(|(&struct_rva, _)| struct_rva)
        .collect();
    if mscorlib_structs.len() != 1 {
        return Err(format!("expected one mscorlib module, got {}", mscorlib_structs.len()).into());
    }
    let mscorlib_struct = mscorlib_structs[0];
    let array_offset = rva_to_offset(cgm_rva).ok_or("invalid cgm_rva offset")?;
    let target_index = cgm_count - 10;
    let mscorlib_index = (0..cgm_count)
        .find(|&idx| normalize(u64_le(image, array_offset + idx * 8)) == mscorlib_struct)
        .ok_or("mscorlib is not in the module array")?;

    let mut conformed_values: Vec<u64> = (0..cgm_count)
        .map(|idx| u64_le(image, array_offset + idx * 8))
        .collect();
    if mscorlib_index != target_index {
        conformed_values.swap(mscorlib_index, target_index);
    }

    let record_size = 17 * 8;
    let cgm_copy_size = cgm_count * 8;
    let reservation_size = record_size + cgm_copy_size;
    let mut record_offset = None;

    for section in &pe.sections {
        if (section.chars & IMAGE_SCN_MEM_EXECUTE) != 0
            || (section.chars & IMAGE_SCN_MEM_WRITE) == 0
        {
            continue;
        }
        let start = section.va.max(section.raw);
        let end = image.len().min(section.va + section.vsize.max(section.rsize));
        if end < start + reservation_size {
            continue;
        }
        let mut candidate = (end - reservation_size) & !7;
        while candidate >= start {
            if image[candidate..candidate + reservation_size]
                .iter()
                .all(|&b| b == 0)
            {
                record_offset = Some(candidate);
                break;
            }
            if candidate < 8 {
                break;
            }
            candidate -= 8;
        }
        if record_offset.is_some() {
            break;
        }
    }

    let record_offset = record_offset.ok_or("found no writable zero-filled PE padding")?;
    let record_rva = offset_to_rva(record_offset);
    let cgm_copy_offset = record_offset + record_size;
    let cgm_copy_rva = offset_to_rva(cgm_copy_offset);
    if record_rva == 0 || cgm_copy_rva == 0 {
        return Err("registration padding is not section-mapped".into());
    }

    for (i, &val) in conformed_values.iter().enumerate() {
        put64(image, cgm_copy_offset + i * 8, val);
    }
    let mut registration = [0u64; 17];
    registration[2] = gmp_count as u64;
    registration[3] = image_base + gmp_rva;
    registration[15] = cgm_count as u64;
    registration[16] = image_base + cgm_copy_rva;
    for (i, &val) in registration.iter().enumerate() {
        put64(image, record_offset + i * 8, val);
    }

    Ok(())
}

#[derive(Deserialize)]
struct RawImport {
    name: Option<String>,
    ordinal: Option<u16>,
}

#[derive(Deserialize)]
struct RawImportGroup {
    dll: String,
    first_thunk: usize,
    imports: Vec<RawImport>,
}

fn append_aligned(blob: &mut Vec<u8>, value: &[u8], alignment: usize) -> Result<usize, DynError> {
    let offset = align(blob.len(), alignment)?;
    if blob.len() < offset {
        blob.resize(offset, 0);
    }
    blob.extend_from_slice(value);
    Ok(offset)
}

fn make_loadable(image: &mut Vec<u8>) -> Result<(), DynError> {
    let pe = parse_pe(image).ok_or("make_loadable requires a valid PE image")?;
    let file_alignment = u32_le(image, pe.opt + 36) as usize;
    let section_alignment = u32_le(image, pe.opt + 32) as usize;
    let sections_offset = pe.opt + pe.opt_size;
    let section_count = pe.sections.len();
    if section_count + 1 > 65535 || sections_offset + (section_count + 1) * 40 > pe.size_of_headers
    {
        return Err("PE header has no room for .idata section".into());
    }
    for section in &pe.sections {
        if section.raw != section.va
            || section.rsize < section.vsize
            || section.va + section.rsize > image.len()
        {
            return Err(format!("decoded section {} is not flat RVA-mapped", section.name).into());
        }
    }

    let raw_groups: Vec<RawImportGroup> = serde_json::from_str(DECODED_IMPORTS_JSON)?;
    let rdata = pe
        .sections
        .iter()
        .find(|s| s.name == ".rdata")
        .ok_or("decoded PE has no .rdata section")?;
    let old_iat_base = raw_groups
        .iter()
        .map(|g| g.first_thunk)
        .min()
        .ok_or("empty import manifest")?;

    let idata_rva = align(pe.size_of_image, section_alignment)?;
    let raw_offset = align(image.len(), file_alignment)?;

    let descriptor_size = (raw_groups.len() + 1) * 20;
    let mut blob = vec![0u8; descriptor_size];
    let mut descriptors = Vec::with_capacity(raw_groups.len());
    let mut first_thunk = usize::MAX;
    let mut last_thunk = 0usize;

    for group in &raw_groups {
        let group_thunk = (group.first_thunk + rdata.va)
            .checked_sub(old_iat_base)
            .ok_or("IAT thunk underflow")?;
        if rva_to_raw(group_thunk, &pe.sections).is_none()
            || rva_to_raw(group_thunk + 8 * group.imports.len(), &pe.sections).is_none()
        {
            return Err(format!("decoded IAT for {} is outside sections", group.dll).into());
        }
        first_thunk = first_thunk.min(group_thunk);
        last_thunk = last_thunk.max(group_thunk + 8 * (group.imports.len() + 1));

        let lookup_zeros = vec![0u8; 8 * (group.imports.len() + 1)];
        let lookup_offset = append_aligned(&mut blob, &lookup_zeros, 8)?;
        for (index, item) in group.imports.iter().enumerate() {
            let value = if let Some(ordinal) = item.ordinal {
                (1u64 << 63) | (ordinal as u64)
            } else if let Some(name) = &item.name {
                let mut entry = Vec::with_capacity(name.len() + 3);
                entry.extend_from_slice(&[0, 0]);
                entry.extend_from_slice(name.as_bytes());
                entry.push(0);
                let name_offset = append_aligned(&mut blob, &entry, 2)?;
                (idata_rva + name_offset) as u64
            } else {
                return Err("import item missing both name and ordinal".into());
            };
            put64(&mut blob, lookup_offset + index * 8, value);
        }
        let mut dll_bytes = group.dll.as_bytes().to_vec();
        dll_bytes.push(0);
        let dll_offset = append_aligned(&mut blob, &dll_bytes, 1)?;
        descriptors.push((
            (idata_rva + lookup_offset) as u32,
            (idata_rva + dll_offset) as u32,
            group_thunk as u32,
        ));
    }

    for (index, &(lookup_rva, dll_rva, thunk_rva)) in descriptors.iter().enumerate() {
        let off = index * 20;
        put32(&mut blob, off, lookup_rva);
        put32(&mut blob, off + 4, 0);
        put32(&mut blob, off + 8, 0);
        put32(&mut blob, off + 12, dll_rva);
        put32(&mut blob, off + 16, thunk_rva);
    }

    let section_data_len = blob.len();
    let raw_size = align(section_data_len, file_alignment)?;
    if image.len() < raw_offset {
        image.resize(raw_offset, 0);
    }
    image.extend_from_slice(&blob);
    image.resize(raw_offset + raw_size, 0);

    let header = sections_offset + section_count * 40;
    image[header..header + 40].fill(0);
    image[header..header + 8].copy_from_slice(b".idata\0\0");
    put32(image, header + 8, section_data_len as u32);
    put32(image, header + 12, idata_rva as u32);
    put32(image, header + 16, raw_size as u32);
    put32(image, header + 20, raw_offset as u32);
    put32(
        image,
        header + 36,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    );
    put16(image, pe.lfanew + 6, (section_count + 1) as u16);
    put32(
        image,
        pe.opt + 56,
        align(idata_rva + section_data_len, section_alignment)? as u32,
    );

    let directories = pe.opt + 112;
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, idata_rva as u32);
    put32(
        image,
        directories + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4,
        descriptor_size as u32,
    );
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_IAT * 8, first_thunk as u32);
    put32(
        image,
        directories + IMAGE_DIRECTORY_ENTRY_IAT * 8 + 4,
        (last_thunk - first_thunk) as u32,
    );
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8, 0);
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4, 0);
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_TLS * 8, 0);
    put32(image, directories + IMAGE_DIRECTORY_ENTRY_TLS * 8 + 4, 0);
    let dll_chars = u16_le(image, pe.opt + 70) & !0x0060;
    put16(image, pe.opt + 70, dll_chars);

    const PREFIX: &[u8] = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xec\x20\x49\x8b\xf8\x8b\xda\x48\x8b\xf1\x83\xfa\x01\x75\x05\xe8";
    const SUFFIX: &[u8] = b"\x4c\x8b\xc7\x8b\xd3\x48\x8b\xce\x48\x8b\x5c\x24\x30\x48\x8b\x74\x24\x38\x48\x83\xc4\x20\x5f\xe9";
    const TOTAL_LEN: usize = PREFIX.len() + 4 + SUFFIX.len() + 4;

    let mut entrypoints = Vec::new();
    for section in &pe.sections {
        if (section.chars & IMAGE_SCN_MEM_EXECUTE) == 0 {
            continue;
        }
        let slice = &image[section.raw..section.raw + section.rsize];
        if slice.len() < TOTAL_LEN {
            continue;
        }
        for i in 0..=slice.len() - TOTAL_LEN {
            if &slice[i..i + PREFIX.len()] == PREFIX
                && &slice[i + PREFIX.len() + 4..i + PREFIX.len() + 4 + SUFFIX.len()] == SUFFIX
            {
                entrypoints.push((section.va + i) as u32);
            }
        }
    }
    if entrypoints.len() != 1 {
        return Err(format!(
            "expected one decoded CRT DLL entrypoint, found {}",
            entrypoints.len()
        )
        .into());
    }
    put32(image, pe.opt + 16, entrypoints[0]);
    Ok(())
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(data);
    hex::encode(hash.finalize())
}

pub fn decrypt_with_profile(
    packed_path: &Path,
    output_path: &Path,
    profile_dir: &Path,
) -> Result<String, DynError> {
    let packed = fs::read(packed_path)?;
    let packed_hash = sha256_bytes(&packed);

    let manifest_bytes = fs::read(profile_dir.join("manifest.json"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    if let Some(expected) = manifest.get("packed_sha256").and_then(|v| v.as_str()) {
        if !expected.eq_ignore_ascii_case(&packed_hash) {
            return Err("packed GameAssembly.dll SHA-256 does not match profile manifest".into());
        }
    }
    let payload = manifest
        .get("payload")
        .and_then(|v| v.as_u64())
        .ok_or("invalid payload offset in profile manifest")? as usize;

    let mut materials = BTreeMap::<&str, Vec<u8>>::new();
    for name in ["key", "sbox", "pass3", "records"] {
        let data = fs::read(profile_dir.join(format!("{name}.bin")))?;
        if let Some(expected_sha) = manifest
            .get(name)
            .and_then(|m| m.get("sha256"))
            .and_then(|v| v.as_str())
        {
            if !sha256_bytes(&data).eq_ignore_ascii_case(expected_sha) {
                return Err(format!("{name}.bin SHA-256 mismatch").into());
            }
        }
        materials.insert(name, data);
    }

    let (mut image, pe) = stage1(&packed)?;
    let records_blob = &materials["records"];
    if records_blob.len() % 16 != 0 {
        return Err("records.bin size must be a multiple of 16".into());
    }
    let records: Vec<(usize, usize, usize)> = (0..records_blob.len())
        .step_by(16)
        .map(|at| {
            (
                u32_le(records_blob, at) as usize,
                u32_le(records_blob, at + 4) as usize,
                u32_le(records_blob, at + 12) as usize,
            )
        })
        .collect();

    let aes = Aes256Inv::new(&materials["key"])?;
    decode_bodies(
        &mut image,
        &packed,
        &records,
        &materials["sbox"],
        &materials["pass3"],
        payload,
        &aes,
    )?;

    let final_size = if records.len() == 47706 {
        rebuild_frozen_preset(&mut image)?
    } else {
        rebuild_rva_mapped_pe(&mut image, &pe)?
    };
    image.truncate(final_size);
    apply_stock_conform(&mut image)?;
    make_loadable(&mut image)?;

    let output_hash = sha256_bytes(&image);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut temp, &image)?;
        temp.persist(output_path)?;
    } else {
        fs::write(output_path, &image)?;
    }
    Ok(output_hash)
}
