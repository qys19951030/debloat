"""Build minimal PE32/PE32+ files from raw bytes for tests.

No binary samples are stored in the repository; every test file is
generated here. The DOS header, PE signature, COFF header, optional
header and a single .text section are all written by hand.
"""
import struct

import pefile

E_LFANEW = 0x80
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
SECTION_RAW_PTR = 0x200
SECTION_RAW_SIZE = 0x200
SIZE_OF_HEADERS = 0x200
ENTRY_POINT_RVA = 0x1000


def optional_header_offset(data: bytes) -> int:
    '''File offset of the optional header.'''
    return struct.unpack_from("<I", data, 0x3C)[0] + 4 + 20


def checksum_offset(data: bytes) -> int:
    '''File offset of the CheckSum field (same for PE32 and PE32+).'''
    return optional_header_offset(data) + 64


def section_header_offset(data: bytes) -> int:
    '''File offset of the first section header.'''
    opt_offset = optional_header_offset(data)
    opt_size = struct.unpack_from("<H", data, opt_offset - 4)[0]
    return opt_offset + opt_size


def security_directory_offset(data: bytes) -> int:
    '''File offset of the security data directory entry.'''
    opt_offset = optional_header_offset(data)
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    directories = opt_offset + (112 if magic == 0x20B else 96)
    return directories + 4 * 8  # IMAGE_DIRECTORY_ENTRY_SECURITY


def build_pe(pe_plus: bool = False,
             overlay: bytes = b"",
             certificate: bytes = None,
             checksum: int = 0) -> bytes:
    '''Return the bytes of a minimal but valid PE file.

    Keyword Arguments:
    pe_plus -- build a PE32+ (64-bit) file instead of PE32
    overlay -- bytes appended after the section data
    certificate -- certificate blob wrapped in a WIN_CERTIFICATE
        structure and pointed to by the security directory
    checksum -- initial value of the header CheckSum field
    '''
    opt_size = 0xF0 if pe_plus else 0xE0
    machine = 0x8664 if pe_plus else 0x14C
    characteristics = 0x0022 if pe_plus else 0x0102

    dos = bytearray(E_LFANEW)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, E_LFANEW)

    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size,
                       characteristics)

    if pe_plus:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 0, 0, SECTION_RAW_SIZE, 0, 0, ENTRY_POINT_RVA, 0x1000,
            0x140000000, SECTION_ALIGNMENT, FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0, 0, 0x2000, SIZE_OF_HEADERS,
            checksum, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000,
            0, 16)
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 0, 0, SECTION_RAW_SIZE, 0, 0, ENTRY_POINT_RVA, 0x1000,
            0x2000, 0x400000, SECTION_ALIGNMENT, FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0, 0, 0x2000, SIZE_OF_HEADERS,
            checksum, 3, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000,
            0, 16)
    opt = bytearray(opt)
    opt[len(opt):] = bytearray(16 * 8)  # data directories
    assert len(opt) == opt_size

    section = struct.pack(
        "<8sIIIIIIHHI", b".text\x00\x00\x00", 0x100, ENTRY_POINT_RVA,
        SECTION_RAW_SIZE, SECTION_RAW_PTR, 0, 0, 0, 0, 0x60000020)

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + section
    data = headers.ljust(SIZE_OF_HEADERS, b"\x00") + bytes(SECTION_RAW_SIZE)
    data += overlay

    if certificate is not None:
        cert_offset = len(data)
        dw_length = 8 + len(certificate)
        data += struct.pack("<IHH", dw_length, 0x0200, 0x0002) + certificate
        data = bytearray(data)
        struct.pack_into("<II", data, security_directory_offset(bytes(data)),
                         cert_offset, dw_length)
        data = bytes(data)
    return data


def fix_checksum(data: bytes) -> bytes:
    '''Return the PE bytes with a freshly computed header CheckSum.'''
    pe = pefile.PE(data=data)
    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    return bytes(pe.write())
