"""
Verification of debloated PE output.

The functions in this module compare the original PE bytes with the
bytes produced by the processor and report structural problems as a
list of VerificationIssue objects. Each issue carries a stable short
code, a severity ("error" or "warning") and a human readable message.
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple
import struct

import pefile

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"


@dataclass
class VerificationIssue:
    """A single problem found while verifying a debloated PE."""
    code: str
    severity: str
    message: str
    offset: Optional[int] = None


def has_errors(issues: List[VerificationIssue]) -> bool:
    """Return True if any issue has error severity."""
    return any(issue.severity == SEVERITY_ERROR for issue in issues)


def _parse_pe(data: bytes) -> Tuple[Optional[pefile.PE], Optional[Exception]]:
    """Fully parse PE bytes, returning (pe, None) or (None, exception)."""
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:
        return None, exc
    return pe, None


def _check_structure_preserved(original_pe: pefile.PE,
                               output_pe: pefile.PE,
                               issues: List[VerificationIssue]) -> None:
    """Section count and entry point must survive debloating."""
    original_count = len(original_pe.sections)
    output_count = len(output_pe.sections)
    if original_count != output_count:
        issues.append(VerificationIssue(
            code="SECTION_COUNT_MISMATCH",
            severity=SEVERITY_ERROR,
            message="Section count changed from %d to %d."
                    % (original_count, output_count)))
    original_entry = original_pe.OPTIONAL_HEADER.AddressOfEntryPoint
    output_entry = output_pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if original_entry != output_entry:
        issues.append(VerificationIssue(
            code="ENTRY_POINT_MISMATCH",
            severity=SEVERITY_ERROR,
            message="Entry point RVA changed from 0x%X to 0x%X."
                    % (original_entry, output_entry)))


def _check_section_bounds(output_pe: pefile.PE,
                          output_size: int,
                          issues: List[VerificationIssue]) -> None:
    """Every section's raw data must lie inside the output file."""
    for section in output_pe.sections:
        raw_start = section.PointerToRawData
        raw_end = raw_start + section.SizeOfRawData
        if raw_end > output_size:
            name = section.Name.rstrip(b"\x00").decode("utf8", errors="backslashreplace")
            issues.append(VerificationIssue(
                code="SECTION_RAW_OUT_OF_BOUNDS",
                severity=SEVERITY_ERROR,
                message="Section %s raw data ends at 0x%X, beyond the "
                        "output file size 0x%X." % (name, raw_end, output_size),
                offset=raw_start))


def _check_security_directory(output_data: bytes,
                              output_pe: pefile.PE,
                              issues: List[VerificationIssue]) -> None:
    """Validate the certificate table of the output file.

    The security directory's VirtualAddress and Size must either both
    be zero or both be set. When set, the WIN_CERTIFICATE entries are
    walked by their dwLength field: the accumulated lengths must add
    up to the directory Size exactly, with no trailing bytes, and the
    whole table must lie inside the file.
    """
    directory = output_pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    address = directory.VirtualAddress
    size = directory.Size
    if address == 0 and size == 0:
        return
    if address == 0 or size == 0:
        issues.append(VerificationIssue(
            code="SECURITY_DIR_INCONSISTENT",
            severity=SEVERITY_ERROR,
            message="Security directory VirtualAddress (0x%X) and Size "
                    "(0x%X) must both be zero or both be non-zero."
                    % (address, size)))
        return
    output_size = len(output_data)
    if address + size > output_size:
        issues.append(VerificationIssue(
            code="SECURITY_DIR_OUT_OF_BOUNDS",
            severity=SEVERITY_ERROR,
            message="Security directory ends at 0x%X, beyond the output "
                    "file size 0x%X." % (address + size, output_size),
            offset=address))
        return
    offset = address
    end = address + size
    while offset < end:
        if offset + 8 > end:
            issues.append(VerificationIssue(
                code="CERT_SIZE_MISMATCH",
                severity=SEVERITY_ERROR,
                message="%d trailing byte(s) after the last WIN_CERTIFICATE "
                        "do not add up to the security directory Size."
                        % (end - offset),
                offset=offset))
            return
        dw_length = struct.unpack_from("<I", output_data, offset)[0]
        if dw_length < 8:
            issues.append(VerificationIssue(
                code="CERT_ENTRY_INVALID",
                severity=SEVERITY_ERROR,
                message="WIN_CERTIFICATE at 0x%X has invalid dwLength %d."
                        % (offset, dw_length),
                offset=offset))
            return
        offset += dw_length
    if offset != end:
        issues.append(VerificationIssue(
            code="CERT_SIZE_MISMATCH",
            severity=SEVERITY_ERROR,
            message="WIN_CERTIFICATE dwLength values sum to 0x%X, past the "
                    "security directory Size 0x%X."
                    % (offset - address, size),
            offset=address))


def _check_checksum(output_pe: pefile.PE,
                    issues: List[VerificationIssue]) -> None:
    """The output CheckSum must match the recomputed PE checksum."""
    expected = output_pe.generate_checksum()
    actual = output_pe.OPTIONAL_HEADER.CheckSum
    if actual != expected:
        issues.append(VerificationIssue(
            code="CHECKSUM_MISMATCH",
            severity=SEVERITY_ERROR,
            message="Header CheckSum 0x%08X does not match the recomputed "
                    "value 0x%08X." % (actual, expected)))


def verify_output(original_data: bytes,
                  output_data: bytes) -> List[VerificationIssue]:
    """Compare original PE bytes with debloated output bytes.

    Returns a list of VerificationIssue objects; an empty list means
    the output passed every check.
    """
    issues = []  # type: List[VerificationIssue]
    output_pe, output_error = _parse_pe(output_data)
    if output_error is not None:
        issues.append(VerificationIssue(
            code="OUTPUT_UNPARSEABLE",
            severity=SEVERITY_ERROR,
            message="Output file cannot be parsed as a PE: %s" % output_error))
        return issues
    original_pe, original_error = _parse_pe(original_data)
    if original_error is None:
        _check_structure_preserved(original_pe, output_pe, issues)
    _check_section_bounds(output_pe, len(output_data), issues)
    _check_security_directory(output_data, output_pe, issues)
    _check_checksum(output_pe, issues)
    return issues
