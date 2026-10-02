import csv
import json
import os
import shutil
import subprocess
import sys
import time


FILE_SIZE = 100 * 1024 * 1024

CHUNK_SIZES = [
    4 * 1024,
    64 * 1024,
    256 * 1024,
    1024 * 1024,
]

SYSTEMS = [
    "aes",
    "hybrid",
]

OPERATIONS = [
    "encrypt",
    "decrypt",
]

REPETITIONS = 5

TMPFS_DIR = "/dev/shm/pqc_benchmark"

INPUT_PATH = os.path.join(
    TMPFS_DIR,
    "benchmark_100mb.bin",
)

RESULT_PATH = (
    "results/diagnostic_tmpfs.csv"
)


def create_test_file(path, size):
    pattern = bytes(range(256))

    with open(path, "wb") as f:
        remaining = size

        while remaining > 0:
            block_size = min(
                len(pattern),
                remaining,
            )

            f.write(
                pattern[:block_size]
            )

            remaining -= block_size


def run_worker(
    system,
    operation,
    chunk_size,
    input_path,
    output_path,
):
    command = [
        sys.executable,
        "-m",
        "benchmark.worker_v3",

        "--system",
        system,

        "--operation",
        operation,

        "--input",
        input_path,

        "--output",
        output_path,

        "--chunk-size",
        str(chunk_size),
    ]

    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )

    lines = result.stdout.strip().splitlines()

    if not lines:
        raise RuntimeError(
            "Worker produced no stdout"
        )

    return json.loads(lines[-1])


def prepare_ciphertexts():
    prepared = {}

    print("\nPreparing ciphertext files...")

    for system in SYSTEMS:
        for chunk_size in CHUNK_SIZES:

            path = os.path.join(
                TMPFS_DIR,
                f"prepared_"
                f"{system}_"
                f"{chunk_size}.pqcm",
            )

            print(
                f"Preparing "
                f"{system} "
                f"{chunk_size // 1024} KiB"
            )

            run_worker(
                system=system,
                operation="encrypt",
                chunk_size=chunk_size,
                input_path=INPUT_PATH,
                output_path=path,
            )

            prepared[
                (system, chunk_size)
            ] = path

    return prepared


def main():
    os.makedirs(
        TMPFS_DIR,
        exist_ok=True,
    )

    os.makedirs(
        "results",
        exist_ok=True,
    )

    print("=" * 60)
    print("TMPFS DIAGNOSTIC")
    print("=" * 60)

    print(
        f"Dataset: "
        f"{FILE_SIZE / (1024 * 1024):.2f} MiB"
    )

    print(
        f"TMPFS directory: "
        f"{TMPFS_DIR}"
    )

    print(
        f"Repetitions: "
        f"{REPETITIONS}"
    )

    print(
        f"Chunk sizes: "
        f"{[size // 1024 for size in CHUNK_SIZES]} KiB"
    )

    print(
        "\nCreating benchmark input..."
    )

    if os.path.exists(INPUT_PATH):
        actual_size = os.path.getsize(
            INPUT_PATH
        )

        if actual_size != FILE_SIZE:
            os.remove(INPUT_PATH)
            create_test_file(
                INPUT_PATH,
                FILE_SIZE,
            )
    else:
        create_test_file(
            INPUT_PATH,
            FILE_SIZE,
        )

    actual_size = os.path.getsize(
        INPUT_PATH
    )

    if actual_size != FILE_SIZE:
        raise RuntimeError(
            f"Unexpected input size: "
            f"{actual_size}"
        )

    print(
        f"Input size: "
        f"{actual_size / (1024 * 1024):.2f} MiB"
    )

    prepared = prepare_ciphertexts()

    configurations = []

    for chunk_size in CHUNK_SIZES:
        for system in SYSTEMS:
            for operation in OPERATIONS:
                for run in range(
                    1,
                    REPETITIONS + 1,
                ):
                    configurations.append({
                        "chunk_size": chunk_size,
                        "system": system,
                        "operation": operation,
                        "run": run,
                    })

    fieldnames = [
        "storage",
        "file_size_bytes",
        "chunk_size_bytes",
        "system",
        "operation",
        "run",
        "elapsed_seconds",
        "throughput_mib_per_second",
        "baseline_rss_mib",
        "peak_rss_mib",
        "peak_delta_rss_mib",
        "input_size_bytes",
        "output_size_bytes",
    ]

    with open(
        RESULT_PATH,
        "w",
        newline="",
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        total = len(configurations)

        for index, config in enumerate(
            configurations,
            start=1,
        ):
            chunk_size = config[
                "chunk_size"
            ]

            system = config[
                "system"
            ]

            operation = config[
                "operation"
            ]

            run = config[
                "run"
            ]

            if operation == "encrypt":

                input_path = INPUT_PATH

                output_path = os.path.join(
                    TMPFS_DIR,
                    f"diag_"
                    f"{system}_"
                    f"{chunk_size}_"
                    f"{run}.pqcm",
                )

            else:

                input_path = prepared[
                    (system, chunk_size)
                ]

                output_path = os.path.join(
                    TMPFS_DIR,
                    f"diag_"
                    f"{system}_"
                    f"{chunk_size}_"
                    f"{run}_"
                    f"recovered.bin",
                )

            print(
                f"[{index}/{total}] "
                f"{system} "
                f"{operation} "
                f"{chunk_size // 1024} KiB "
                f"run {run}"
            )

            data = run_worker(
                system=system,
                operation=operation,
                chunk_size=chunk_size,
                input_path=input_path,
                output_path=output_path,
            )

            input_size = os.path.getsize(
                input_path
            )

            output_size = os.path.getsize(
                output_path
            )

            print(
                f"  Time: "
                f"{data['elapsed_seconds']:.4f} s"
            )

            print(
                f"  Throughput: "
                f"{data['throughput_mib_per_second']:.2f} MiB/s"
            )

            print(
                f"  Peak RSS: "
                f"{data['peak_rss_mib']:.2f} MiB"
            )

            writer.writerow({
                "storage": "tmpfs",

                "file_size_bytes": (
                    FILE_SIZE
                ),

                "chunk_size_bytes": (
                    chunk_size
                ),

                "system": system,

                "operation": operation,

                "run": run,

                "elapsed_seconds": (
                    data["elapsed_seconds"]
                ),

                "throughput_mib_per_second": (
                    data[
                        "throughput_mib_per_second"
                    ]
                ),

                "baseline_rss_mib": (
                    data[
                        "baseline_rss_mib"
                    ]
                ),

                "peak_rss_mib": (
                    data[
                        "peak_rss_mib"
                    ]
                ),

                "peak_delta_rss_mib": (
                    data[
                        "peak_delta_rss_mib"
                    ]
                ),

                "input_size_bytes": (
                    input_size
                ),

                "output_size_bytes": (
                    output_size
                ),
            })

            if os.path.exists(
                output_path
            ):
                os.remove(
                    output_path
                )

    print("\n" + "=" * 60)
    print("TMPFS DIAGNOSTIC COMPLETED")
    print("=" * 60)

    print(
        f"Results: {RESULT_PATH}"
    )

    print(
        f"Measurements: {len(configurations)}"
    )

    print(
        "\nNote:"
    )

    print(
        "For decrypt, chunk_size identifies "
        "the chunk size used to create the "
        "prepared ciphertext. The current "
        "worker does not pass chunk_size "
        "into the decrypt implementation."
    )

    print(
        "\nCleaning temporary TMPFS files..."
    )

    if os.path.exists(TMPFS_DIR):
        shutil.rmtree(TMPFS_DIR)

    print("Cleanup completed.")


if __name__ == "__main__":
    main()
