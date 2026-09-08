#!/usr/bin/env python3
"""Offline verification of published evidence, not a Core/consensus test."""
import csv
import hashlib
import json
import math
import re
import statistics
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def close(actual, expected, label):
    require(abs(actual - expected) < 0.000001, f"{label}: {actual} != {expected}")


def rows(path):
    with (ROOT / path).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def metric(group, column, median, p95):
    values = sorted(float(row[column]) for row in group)
    close(statistics.median(values), median, column + " median")
    close(values[math.ceil(len(values) * .95) - 1], p95, column + " p95")


def main():
    manifest = json.loads((ROOT / "evidence/manifest.json").read_text(encoding="utf-8-sig"))
    entries = manifest["artifacts"]
    require(len(entries) == manifest["artifactCount"], "artifact count")
    seen = set()
    for entry in entries:
        name = entry["path"]
        require(name not in seen, "duplicate evidence path")
        seen.add(name)
        path = (ROOT / name).resolve()
        require(path.is_relative_to(ROOT), "escaping evidence path")
        data = path.read_bytes()
        require(len(data) == entry["bytes"], name + " byte count")
        require(hashlib.sha256(data).hexdigest() == entry["sha256"], name + " SHA-256")
    binding = "".join(f'{entry["sha256"]}  {entry["path"]}\n' for entry in entries)
    require(hashlib.sha256(binding.encode()).hexdigest() == manifest["collectionSha256"], "collection digest")

    daemon = rows("evidence/daemon/warm-ab-21pairs.csv")
    require(len(daemon) == 46, "daemon rows including warmups")
    recorded = [r for r in daemon if r["phase"] == "recorded"]
    require(len(recorded) == 42, "daemon recorded count")
    for variant, wm, wp, cm, cp, trials in [
        ("baseline64", 3059.517, 3459.741, 2218.750, 2343.750, "178416"),
        ("candidate1", 1926.155, 2234.055, 1125.000, 1281.250, "0"),
    ]:
        group = [r for r in recorded if r["variant"] == variant]
        require(len(group) == 21, "daemon per-mode count")
        metric(group, "wall_ms", wm, wp)
        metric(group, "wallet_cpu_ms", cm, cp)
        require({r["legacy_window_trials"] for r in group} == {trials}, "legacy trial counter")
        for row in group:
            require(row["pq_outputs"] == row["v2_attempts"] == row["legacy_t0_attempts"] == "2832", "attempt counters")
            require(row["current_height"] == row["total_height"] == "14804" and row["node_height"] == "14803", "height")
            for field in ("actual_balance", "pending_balance", "transaction_count", "transfer_count", "recognized_outputs"):
                require(row[field] == "0", "empty benchmark wallet " + field)
            close(float(row["combined_cpu_ms"]), float(row["wallet_cpu_ms"]) + float(row["daemon_cpu_ms"]), "combined CPU")
    require(len({r["tip_hash"] for r in recorded}) == 1, "daemon tip equality")
    require(len({r["state_hash"] for r in recorded}) == 1, "daemon checked-state equality")
    for pair in range(1, 22):
        group = sorted([r for r in recorded if int(r["pair"]) == pair], key=lambda r: int(r["sequence"]))
        require(len(group) == 2, "paired daemon count")
        expected = ["baseline64", "candidate1"] if pair % 2 else ["candidate1", "baseline64"]
        require([r["variant"] for r in group] == expected, "AB/BA ordering")
        by_mode = {r["variant"]: r for r in group}
        require(float(by_mode["baseline64"]["wall_ms"]) > float(by_mode["candidate1"]["wall_ms"]), "21/21 wall direction")

    synthetic = rows("evidence/synthetic/ab-genesis-sync-4096-v2-outputs-release-final.csv")
    require(len(synthetic) == 42, "synthetic recorded count")
    for bound, wm, wp, cm, cp in [("64", 2040.906, 2156.786, 2031.25, 2140.625), ("1", 307.382, 328.331, 296.875, 312.5)]:
        group = [r for r in synthetic if r["maxT"] == bound]
        require(len(group) == 21, "synthetic per-mode count")
        metric(group, "wall_ms", wm, wp)
        metric(group, "cpu_ms", cm, cp)
        require({(r["balance"], r["transactions"], r["synced_height"]) for r in group} == {("800000", "1", "66")}, "synthetic checked-state fields")

    counts = [("existing_scan", 13), ("existing_builder", 7), ("existing_derive", 16), ("v2_only_prototype", 10)]
    count = 0
    for name, expected in counts:
        xml = ET.parse(ROOT / f"evidence/tests/{name}.xml").getroot()
        require(int(xml.attrib["tests"]) == expected, "XML case count")
        require(all(int(xml.attrib[k]) == 0 for k in ("failures", "errors", "disabled")), "nonpassing XML")
        count += expected
    xml = ET.parse(ROOT / "evidence/synthetic/wallet-sync-regression.xml").getroot()
    require(int(xml.attrib["tests"]) == 42, "wallet-regression count")
    require(all(int(xml.attrib[k]) == 0 for k in ("failures", "errors", "disabled")), "wallet-regression status")

    for doc in ROOT.rglob("*.md"):
        text = doc.read_text(encoding="utf-8-sig")
        require(not re.search(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/]", text), "local absolute path in " + doc.name)
        for match in re.finditer(r"\]\(([^)]+)\)", text):
            target = match.group(1)
            if target.startswith(("https://", "http://", "#")):
                continue
            path = (doc.parent / target.split("#", 1)[0]).resolve()
            require(path.is_relative_to(ROOT) and path.exists(), "broken or external local link: " + target)
    print(json.dumps({"status": "pass", "evidenceArtifacts": len(entries), "recordedRows": 84,
                      "recordedTestCases": count + 42, "scope": "integrity, statistics and document links; not Core replay"}, indent=2))


if __name__ == "__main__":
    main()
