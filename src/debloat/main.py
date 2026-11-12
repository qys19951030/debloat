"""This file handles passing the CLI arguments into the processor"""
import logging
import json
import os
import sys
from pathlib import Path
import argparse
import pefile
import debloat.processor
from debloat.processor import DEBLOAT_VERSION
from debloat.processor import RESULT_CODES


def _empty_json_result() -> dict:
    '''JSON result for inputs that could not be processed at all.'''
    return {
        "ok": False,
        "tactic": None,
        "result_code": None,
        "original_size": None,
        "output_size": None,
        "removed_bytes": None,
        "written": False,
        "output_path": None,
        "verification": [],
    }


def _result_to_json(result: debloat.processor.ProcessResult,
                    output_path) -> dict:
    '''Convert a ProcessResult into the stable JSON output shape.'''
    return {
        "ok": result.ok,
        "tactic": result.tactic,
        "result_code": result.result_code,
        "original_size": result.original_size,
        "output_size": result.output_size,
        "removed_bytes": result.removed_bytes,
        "written": result.written,
        "output_path": output_path,
        "verification": [
            {
                "code": issue.code,
                "severity": issue.severity,
                "message": issue.message,
            }
            for issue in result.verification
        ],
    }


def main() -> int:
    logging.basicConfig(level=logging.WARN)
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", 
                        help="Path to the executable to be debloated",
                        type=Path)
    parser.add_argument("--output", 
                        help="Output location", 
                        type=Path,
                        required=False)
    parser.add_argument("-yolo", "--last-ditch", dest="last_ditch_processing",
                        help="""
    Run last-ditch processing. In this mode Debloat may remove the
    whole PE Overlay as a last resort if no smarter method works.
                            """,
                        action='store_true', default=False)
    parser.add_argument("-c", "--cert", dest="cert_preservation",
                        help="""
    Preserve the certificate on the end of the file if there is a certificate.
    The certificate will no longer be valid.""",
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument("--no-extract", dest="no_extract",
                        help="""
    Do not extract embedded installer files (NSIS).
    If the file is an installer, the overlay will be trimmed instead.
                        """,
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument("--json", dest="json_output",
                        help="""
    Print a single machine readable JSON object to stdout.
    All log and warning output is redirected to stderr.
                        """,
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument("--analyze", dest="analyze",
                        help="""
    Only analyze the file: report the identified tactic and the
    estimated size reduction without writing any output file.
                        """,
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument("-v", "--version", action='version', version='debloat version ' + DEBLOAT_VERSION, help="Prints program version")
    args = parser.parse_args()

    if args.json_output:
        def log_message(message: str, end: str = "\n",
                        flush: bool = False) -> None:
            print(message, end=end, flush=flush, file=sys.stderr)
    else:
        log_message = print

    file_path = args.executable
    out_path = args.output

    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as bloated_file:
            pe_data = bloated_file.read()
        pe = pefile.PE(data=pe_data, fast_load=True)
    except Exception:
        message = '''
Provided file is not an executable! Please try again with an executable. 
Maybe it needs unzipped?'''
        if args.json_output:
            print(json.dumps(_empty_json_result()))
            print(message, file=sys.stderr)
        else:
            print(message)
        return 2

    if not out_path:
        out_path = file_path.parent \
            / f"{file_path.stem}_patched{file_path.suffix}"

    result = debloat.processor.process_pe(pe,
                        out_path=str(out_path),
                        last_ditch_processing=args.last_ditch_processing,
                        cert_preservation=args.cert_preservation,
                        log_message=log_message,
                        beginning_file_size=file_size,
                        extract=not args.no_extract,
                        write_output=not args.analyze
                        )

    if args.analyze:
        output_path = None
        exit_code = 0 if result.result_code != 0 else 1
    elif result.ok:
        output_path = str(out_path)
        exit_code = 0
    elif result.result_code == 0:
        output_path = None
        exit_code = 1
    else:
        # The output failed verification and was discarded.
        output_path = None
        exit_code = 3

    if args.json_output:
        print(json.dumps(_result_to_json(result, output_path)))
    else:
        print("Tactic identified:", RESULT_CODES.get(result.result_code))
    return exit_code

if __name__ == "__main__":
    sys.exit(main())
