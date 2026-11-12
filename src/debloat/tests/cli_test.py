"""Tests for the debloat command line interface."""
import json
import os
import subprocess
import sys

import debloat.main
import debloat.processor
from debloat.tests.pe_factory import build_pe
from debloat.verifier import VerificationIssue

EXPECTED_JSON_FIELDS = {
    "ok", "tactic", "result_code", "original_size", "output_size",
    "removed_bytes", "written", "output_path", "verification",
}


def run_cli(args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "debloat.main"] + args,
        capture_output=True, cwd=str(cwd))


def make_bloated_sample(path):
    # A certificate followed by junk: "Junk after signature." tactic.
    data = build_pe(certificate=b"ABCD") + b"J" * 512
    path.write_bytes(data)
    return data


def test_json_success_exit_0(tmp_path):
    sample = tmp_path / "bloated.exe"
    make_bloated_sample(sample)
    out = tmp_path / "out.exe"
    proc = run_cli([str(sample), "--json", "--output", str(out)], tmp_path)
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert set(payload.keys()) == EXPECTED_JSON_FIELDS
    assert payload["ok"] is True
    assert payload["written"] is True
    assert payload["result_code"] == 1
    assert payload["tactic"] == "Junk after signature."
    assert payload["output_path"] == str(out)
    assert payload["removed_bytes"] > 0
    assert out.exists()
    # Logs must not pollute stdout: it is exactly one JSON object.
    assert proc.stdout.decode().strip().startswith("{")
    assert proc.stdout.decode().strip().endswith("}")


def test_json_not_a_pe_exit_2(tmp_path):
    sample = tmp_path / "notpe.txt"
    sample.write_text("this is not a PE")
    proc = run_cli([str(sample), "--json"], tmp_path)
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert set(payload.keys()) == EXPECTED_JSON_FIELDS
    assert payload["ok"] is False
    assert payload["written"] is False


def test_json_no_solution_exit_1(tmp_path):
    sample = tmp_path / "clean.exe"
    sample.write_bytes(build_pe())
    proc = run_cli([str(sample), "--json"], tmp_path)
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["result_code"] == 0
    assert payload["written"] is False
    assert not (tmp_path / "clean_patched.exe").exists()


def test_verification_failure_exit_3(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "bloated.exe"
    make_bloated_sample(sample)
    out = tmp_path / "out.exe"

    def fake_verify_output(original_data, output_data):
        return [VerificationIssue(code="CHECKSUM_MISMATCH",
                                  severity="error",
                                  message="forced failure")]

    monkeypatch.setattr(debloat.processor, "verify_output",
                        fake_verify_output)
    monkeypatch.setattr(sys, "argv",
                        ["debloat", str(sample), "--json", "--output",
                         str(out)])
    exit_code = debloat.main.main()
    assert exit_code == 3
    # The broken output must have been deleted again.
    assert not out.exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["written"] is False
    assert payload["output_path"] is None
    assert payload["verification"][0]["code"] == "CHECKSUM_MISMATCH"
    assert payload["verification"][0]["severity"] == "error"
    assert "message" in payload["verification"][0]


def test_analyze_json_is_deterministic_and_writes_nothing(tmp_path):
    sample = tmp_path / "bloated.exe"
    data = make_bloated_sample(sample)
    before = set(os.listdir(tmp_path))
    first = run_cli([str(sample), "--analyze", "--json"], tmp_path)
    second = run_cli([str(sample), "--analyze", "--json"], tmp_path)
    assert first.returncode == 0
    assert second.returncode == 0
    # Byte-identical stdout across runs.
    assert first.stdout == second.stdout
    # No new files and the input is untouched.
    assert set(os.listdir(tmp_path)) == before
    assert sample.read_bytes() == data
    payload = json.loads(first.stdout)
    assert set(payload.keys()) == EXPECTED_JSON_FIELDS
    assert payload["written"] is False
    assert payload["output_path"] is None
    assert payload["tactic"] == "Junk after signature."
    assert payload["removed_bytes"] > 0

