"""Tests for storage.py (scan persistence, baseline compare, decisions)."""
import pytest

from app import storage


def test_save_and_load_scan_roundtrip(isolate_storage, make_scan):
    scan = make_scan(scan_id="abc123")
    storage.save_scan(scan)
    loaded = storage.load_scan("abc123")
    assert loaded.scan_id == "abc123"
    assert len(loaded.findings) == len(scan.findings)
    assert loaded.findings[0].fingerprint == scan.findings[0].fingerprint


def test_load_missing_scan_raises(isolate_storage):
    with pytest.raises(FileNotFoundError):
        storage.load_scan("nope")


def test_list_scans(isolate_storage, make_scan):
    storage.save_scan(make_scan(scan_id="s1"))
    storage.save_scan(make_scan(scan_id="s2"))
    ids = {s.scan_id for s in storage.list_scans()}
    assert ids == {"s1", "s2"}


def test_baseline_save_and_load(isolate_storage, make_scan, make_finding):
    scan = make_scan(findings=[make_finding(fingerprint="fp1"), make_finding(id="f2", fingerprint="fp2")])
    storage.save_baseline(scan)
    baseline = storage.load_baseline()
    assert baseline["scan_id"] == scan.scan_id
    assert baseline["fingerprints"] == ["fp1", "fp2"]


def test_compare_to_baseline_without_baseline_marks_all_new(isolate_storage, make_scan, make_finding):
    scan = make_scan(findings=[make_finding(fingerprint="fp1"), make_finding(id="f2", fingerprint="fp2")])
    result = storage.compare_to_baseline(scan)
    assert result.new_findings == ["fp1", "fp2"]
    assert result.resolved_findings == []
    assert result.unchanged_findings == []


def test_compare_to_baseline_diff(isolate_storage, make_scan, make_finding):
    old = make_scan(findings=[make_finding(fingerprint="fp1"), make_finding(id="f2", fingerprint="fp2")])
    storage.save_baseline(old)
    new = make_scan(findings=[make_finding(id="f2", fingerprint="fp2"), make_finding(id="f3", fingerprint="fp3")])
    result = storage.compare_to_baseline(new)
    assert result.new_findings == ["fp3"]
    assert result.resolved_findings == ["fp1"]
    assert result.unchanged_findings == ["fp2"]


def test_decisions_save_load_and_apply(isolate_storage, make_scan, make_finding):
    storage.save_decision("f1", "false_positive", "known noise")
    assert storage.load_decisions()["f1"] == {"state": "false_positive", "reason": "known noise"}

    scan = make_scan(findings=[make_finding(id="f1"), make_finding(id="f2", fingerprint="fp2")])
    applied = storage.apply_decisions(scan)
    decided = {f.id: f for f in applied.findings}
    assert decided["f1"].decision == "false_positive"
    assert decided["f1"].decision_reason == "known noise"
    assert decided["f2"].decision == "open"  # untouched
