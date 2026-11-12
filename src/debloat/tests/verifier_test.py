"""Tests for the output verification module."""
import struct

import pytest

from debloat import verifier
from debloat.tests.pe_factory import (
    build_pe,
    checksum_offset,
    fix_checksum,
    section_header_offset,
    security_directory_offset,
)


def error_codes(issues):
    return [issue.code for issue in issues
            if issue.severity == verifier.SEVERITY_ERROR]


@pytest.mark.parametrize("pe_plus", [False, True])
def test_clean_output_has_no_errors(pe_plus):
    original = build_pe(pe_plus=pe_plus)
    output = fix_checksum(original)
    issues = verifier.verify_output(original, output)
    assert error_codes(issues) == []
    assert not verifier.has_errors(issues)


def test_clean_output_checksum_matches_recomputed():
    original = build_pe()
    output = fix_checksum(original)
    issues = verifier.verify_output(original, output)
    assert "CHECKSUM_MISMATCH" not in error_codes(issues)


def test_section_pointer_moved_is_an_error():
    original = build_pe()
    output = bytearray(fix_checksum(original))
    # Move PointerToRawData of .text beyond the end of the file.
    struct.pack_into("<I", output, section_header_offset(bytes(output)) + 20,
                     0x600)
    output = fix_checksum(bytes(output))
    issues = verifier.verify_output(original, output)
    assert "SECTION_RAW_OUT_OF_BOUNDS" in error_codes(issues)


def test_cert_length_smaller_than_directory_size_is_an_error():
    original = build_pe(certificate=b"ABCD")
    output = bytearray(fix_checksum(original))
    # Shrink dwLength of the WIN_CERTIFICATE from 12 to 8.
    struct.pack_into("<I", output, 0x400, 8)
    output = fix_checksum(bytes(output))
    issues = verifier.verify_output(original, output)
    assert "CERT_SIZE_MISMATCH" in error_codes(issues)


def test_checksum_mismatch_is_an_error():
    original = build_pe()
    output = bytearray(fix_checksum(original))
    struct.pack_into("<I", output, checksum_offset(bytes(output)), 0xDEADBEEF)
    issues = verifier.verify_output(original, bytes(output))
    assert "CHECKSUM_MISMATCH" in error_codes(issues)


def test_trailing_bytes_after_certificate_are_an_error():
    original = build_pe(certificate=b"ABCD")
    # Glue 4 extra bytes after the certificate and grow the directory
    # Size so they are covered by it.
    output = bytearray(original + b"GLUE")
    sec_dir = security_directory_offset(bytes(output))
    address, size = struct.unpack_from("<II", output, sec_dir)
    struct.pack_into("<II", output, sec_dir, address, size + 4)
    output = fix_checksum(bytes(output))
    issues = verifier.verify_output(original, output)
    assert "CERT_SIZE_MISMATCH" in error_codes(issues)


def test_security_directory_half_zero_is_an_error():
    original = build_pe(certificate=b"ABCD")
    output = bytearray(fix_checksum(original))
    sec_dir = security_directory_offset(bytes(output))
    address, size = struct.unpack_from("<II", output, sec_dir)
    struct.pack_into("<II", output, sec_dir, address, 0)
    output = fix_checksum(bytes(output))
    issues = verifier.verify_output(original, output)
    assert "SECURITY_DIR_INCONSISTENT" in error_codes(issues)


def test_unparseable_output_is_an_error():
    original = build_pe()
    issues = verifier.verify_output(original, b"this is not a PE")
    assert "OUTPUT_UNPARSEABLE" in error_codes(issues)

