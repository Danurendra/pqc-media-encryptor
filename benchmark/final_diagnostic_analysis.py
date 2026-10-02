import csv
import os
import statistics
from collections import defaultdict


DISK_PATH = "results/diagnostic_disk.csv"
TMPFS_PATH = "results/diagnostic_tmpfs.csv"

OUTPUT_SUMMARY = "results/diagnostic_summary.csv"
OUTPUT_COMPARISON = "results/diagnostic_comparison.csv"


def load_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def analyze(rows):
    groups = defaultdict(list)

    for r in rows:
        key = (
            r["system"],
            r["operation"],
            int(r["chunk_size_bytes"]),
        )

        groups[key].append({
            "throughput": float(r["throughput_mib_per_second"]),
            "elapsed": float(r["elapsed_seconds"]),
            "peak_rss": float(r["peak_rss_mib"]),
            "peak_delta": float(r["peak_delta_rss_mib"]),
        })

    results = []

    for (system, operation, chunk), values in sorted(groups.items()):

        throughput = [x["throughput"] for x in values]
        elapsed = [x["elapsed"] for x in values]
        peak_rss = [x["peak_rss"] for x in values]
        peak_delta = [x["peak_delta"] for x in values]

        mean_tp = statistics.mean(throughput)
        stdev_tp = statistics.stdev(throughput) if len(throughput) > 1 else 0

        cv = (
            (stdev_tp / mean_tp) * 100
            if mean_tp != 0
            else 0
        )

        results.append({
            "system": system,
            "operation": operation,
            "chunk_size_bytes": chunk,
            "runs": len(values),

            "throughput_mean": mean_tp,
            "throughput_median": statistics.median(throughput),
            "throughput_stdev": stdev_tp,
            "throughput_min": min(throughput),
            "throughput_max": max(throughput),
            "throughput_cv_percent": cv,

            "elapsed_mean": statistics.mean(elapsed),
            "elapsed_median": statistics.median(elapsed),

            "peak_rss_mean": statistics.mean(peak_rss),
            "peak_rss_max": max(peak_rss),

            "peak_delta_rss_mean": statistics.mean(peak_delta),
            "peak_delta_rss_max": max(peak_delta),
        })

    return results


def write_csv(path, rows):
    if not rows:
        return

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(rows[0].keys()),
        )

        writer.writeheader()
        writer.writerows(rows)


def chunk_name(value):
    value = int(value)

    if value == 4 * 1024:
        return "4 KiB"
    if value == 64 * 1024:
        return "64 KiB"
    if value == 256 * 1024:
        return "256 KiB"
    if value == 1024 * 1024:
        return "1 MiB"
    if value == 4096 * 1024:
        return "4 MiB"

    return f"{value} bytes"


def main():

    print("=" * 100)
    print("FINAL DIAGNOSTIC EXTRACTION")
    print("=" * 100)

    disk_rows = load_csv(DISK_PATH)
    tmpfs_rows = load_csv(TMPFS_PATH)

    print(f"Disk rows  : {len(disk_rows)}")
    print(f"TMPFS rows : {len(tmpfs_rows)}")

    assert len(disk_rows) == 200, \
        f"Expected 200 disk rows, got {len(disk_rows)}"

    assert len(tmpfs_rows) == 200, \
        f"Expected 200 TMPFS rows, got {len(tmpfs_rows)}"

    disk = analyze(disk_rows)
    tmpfs = analyze(tmpfs_rows)

    write_csv(OUTPUT_SUMMARY, tmpfs)

    disk_map = {
        (
            r["system"],
            r["operation"],
            r["chunk_size_bytes"],
        ): r
        for r in disk
    }

    tmpfs_map = {
        (
            r["system"],
            r["operation"],
            r["chunk_size_bytes"],
        ): r
        for r in tmpfs
    }

    comparison = []

    for key in sorted(tmpfs_map):

        d = disk_map[key]
        t = tmpfs_map[key]

        disk_tp = d["throughput_mean"]
        tmpfs_tp = t["throughput_mean"]

        disk_cv = d["throughput_cv_percent"]
        tmpfs_cv = t["throughput_cv_percent"]

        throughput_change = (
            ((tmpfs_tp - disk_tp) / disk_tp) * 100
            if disk_tp != 0
            else 0
        )

        cv_reduction = (
            ((disk_cv - tmpfs_cv) / disk_cv) * 100
            if disk_cv != 0
            else 0
        )

        memory_change = (
            t["peak_rss_mean"] - d["peak_rss_mean"]
        )

        comparison.append({
            "system": key[0],
            "operation": key[1],
            "chunk_size_bytes": key[2],

            "chunk_size": chunk_name(key[2]),

            "disk_throughput_mean":
                disk_tp,

            "tmpfs_throughput_mean":
                tmpfs_tp,

            "throughput_change_percent":
                throughput_change,

            "disk_cv_percent":
                disk_cv,

            "tmpfs_cv_percent":
                tmpfs_cv,

            "cv_reduction_percent":
                cv_reduction,

            "disk_peak_rss_mean":
                d["peak_rss_mean"],

            "tmpfs_peak_rss_mean":
                t["peak_rss_mean"],

            "peak_rss_change_mib":
                memory_change,
        })

    write_csv(
        OUTPUT_COMPARISON,
        comparison,
    )

    print()
    print("=" * 100)
    print("DISK vs TMPFS")
    print("=" * 100)

    print(
        f"{'System':<8}"
        f"{'Op':<9}"
        f"{'Chunk':<9}"
        f"{'Disk TP':>12}"
        f"{'TMPFS TP':>12}"
        f"{'TP Change':>12}"
        f"{'Disk CV':>10}"
        f"{'TMPFS CV':>10}"
        f"{'CV Reduction':>14}"
    )

    print("-" * 100)

    for r in comparison:

        print(
            f"{r['system']:<8}"
            f"{r['operation']:<9}"
            f"{r['chunk_size']:<9}"
            f"{r['disk_throughput_mean']:>12.2f}"
            f"{r['tmpfs_throughput_mean']:>12.2f}"
            f"{r['throughput_change_percent']:>11.2f}%"
            f"{r['disk_cv_percent']:>9.2f}%"
            f"{r['tmpfs_cv_percent']:>9.2f}%"
            f"{r['cv_reduction_percent']:>13.2f}%"
        )

    print()
    print("=" * 100)
    print("OUTPUT")
    print("=" * 100)

    print(f"TMPFS summary : {OUTPUT_SUMMARY}")
    print(f"Comparison    : {OUTPUT_COMPARISON}")

    print()
    print("PASS: final diagnostic extraction completed")


if __name__ == "__main__":
    main()
