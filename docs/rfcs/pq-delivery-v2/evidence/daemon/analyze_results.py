#!/usr/bin/env python3
import csv
import json
import math
import statistics
import sys
from collections import defaultdict


def nearest_rank(values, fraction):
    ordered = sorted(values)
    return ordered[max(1, math.ceil(len(ordered) * fraction)) - 1]


def summary(values):
    return {
        "count": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "p95_nearest_rank": nearest_rank(values, 0.95),
        "max": max(values),
        "mean": statistics.mean(values),
        "stdev_population": statistics.pstdev(values),
    }


def two_sided_sign_test(positive, negative):
    n = positive + negative
    if n == 0:
        return 1.0
    tail = min(positive, negative)
    probability = sum(math.comb(n, k) for k in range(tail + 1)) / (2 ** n)
    return min(1.0, 2.0 * probability)


def main(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        rows = [row for row in csv.DictReader(handle) if row["phase"] == "recorded"]
    if not rows:
        raise SystemExit("no recorded rows")

    grouped = defaultdict(list)
    for row in rows:
        grouped[row["variant"]].append(row)
    expected = {"baseline64", "candidate1"}
    if set(grouped) != expected:
        raise SystemExit(f"expected variants {sorted(expected)}, got {sorted(grouped)}")

    numeric_metrics = ["wall_ms", "wallet_cpu_ms", "daemon_cpu_ms", "combined_cpu_ms"]
    result = {"variants": {}, "paired": {}}
    for variant, variant_rows in grouped.items():
        result["variants"][variant] = {
            metric: summary([float(row[metric]) for row in variant_rows])
            for metric in numeric_metrics
        }
        invariant_fields = [
            "current_height", "total_height", "node_height", "tip_hash",
            "actual_balance", "pending_balance", "transaction_count",
            "transfer_count", "state_hash", "pq_outputs", "v2_attempts",
            "legacy_t0_attempts", "legacy_window_trials", "recognized_outputs",
        ]
        result["variants"][variant]["invariants"] = {
            field: sorted({row[field] for row in variant_rows})
            for field in invariant_fields
        }

    for metric in numeric_metrics:
        b = result["variants"]["baseline64"][metric]
        c = result["variants"]["candidate1"][metric]
        result["paired"][metric] = {
            "median_absolute_saved": b["median"] - c["median"],
            "median_speedup": b["median"] / c["median"],
            "p95_absolute_saved": b["p95_nearest_rank"] - c["p95_nearest_rank"],
            "p95_ratio": b["p95_nearest_rank"] / c["p95_nearest_rank"],
        }

    by_pair = defaultdict(dict)
    for row in rows:
        by_pair[int(row["pair"])][row["variant"]] = row
    for metric in numeric_metrics:
        ratios = []
        deltas = []
        for pair, variants in sorted(by_pair.items()):
            if set(variants) != expected:
                raise SystemExit(f"pair {pair} is incomplete")
            baseline = float(variants["baseline64"][metric])
            candidate = float(variants["candidate1"][metric])
            ratios.append(baseline / candidate)
            deltas.append(baseline - candidate)
        result["paired"][metric].update({
            "paired_speedup_median": statistics.median(ratios),
            "paired_speedup_p95": nearest_rank(ratios, 0.95),
            "paired_delta_median": statistics.median(deltas),
            "paired_delta_p95": nearest_rank(deltas, 0.95),
            "paired_delta_min": min(deltas),
            "paired_delta_max": max(deltas),
            "baseline_faster_pairs": sum(delta < 0 for delta in deltas),
            "candidate_faster_pairs": sum(delta > 0 for delta in deltas),
            "tied_pairs": sum(delta == 0 for delta in deltas),
            "two_sided_exact_sign_test_p": two_sided_sign_test(
                sum(delta > 0 for delta in deltas),
                sum(delta < 0 for delta in deltas),
            ),
        })


    wall_ratios_by_order = {"baseline_first": [], "candidate_first": []}
    for pair, variants in sorted(by_pair.items()):
        label = "baseline_first" if pair % 2 == 1 else "candidate_first"
        wall_ratios_by_order[label].append(
            float(variants["baseline64"]["wall_ms"])
            / float(variants["candidate1"]["wall_ms"])
        )
    result["order_check"] = {
        label: {
            "count": len(ratios),
            "wall_speedup_median": statistics.median(ratios),
        }
        for label, ratios in wall_ratios_by_order.items()
    }

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: analyze_results.py <results.csv>")
    main(sys.argv[1])
