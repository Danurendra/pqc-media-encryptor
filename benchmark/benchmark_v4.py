import csv
import json
import os
import random
import subprocess
import sys


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

INPUT_PATH = (
    "data/benchmark/benchmark_100mb.bin"
)

RESULT_PATH = (
    "results/benchmark_v4.csv"
)


def create_test_file(
    path,
    size,
):
    pattern = bytes(
        range(256)
    )

    with open(
        path,
        "wb",
    ) as f:

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


def prepare_ciphertext(
    system,
    chunk_size,
):

    encrypted_path = (
        "data/benchmark/"
        f"prepared_v4_"
        f"{system}_"
        f"{chunk_size}.pqcm"
    )

    command = [
        sys.executable,
        "-m",
        "benchmark.worker_v3",

        "--system",
        system,

        "--operation",
        "encrypt",

        "--input",
        INPUT_PATH,

        "--output",
        encrypted_path,

        "--chunk-size",
        str(chunk_size),
    ]

    subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )

    return encrypted_path


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

    return json.loads(
        result.stdout.strip().splitlines()[-1]
    )


def main():

    os.makedirs(
        "data/benchmark",
        exist_ok=True,
    )

    os.makedirs(
        "results",
        exist_ok=True,
    )

    if not os.path.exists(
        INPUT_PATH
    ):

        print(
            "Creating 100 MiB benchmark file..."
        )

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

    print(
        "\nPreparing ciphertext files..."
    )

    prepared = {}

    for system in SYSTEMS:

        for chunk_size in CHUNK_SIZES:

            print(
                f"Preparing "
                f"{system} "
                f"{chunk_size // 1024} KiB"
            )

            prepared[
                (system, chunk_size)
            ] = prepare_ciphertext(
                system,
                chunk_size,
            )

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

    random.shuffle(
        configurations
    )

    fieldnames = [
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

        total = len(
            configurations
        )

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

                output_path = (
                    "data/benchmark/"
                    f"v4_{system}_"
                    f"{chunk_size}_"
                    f"{run}.pqcm"
                )

            else:

                input_path = prepared[
                    (system, chunk_size)
                ]

                output_path = (
                    "data/benchmark/"
                    f"v4_{system}_"
                    f"{chunk_size}_"
                    f"{run}_"
                    f"recovered.bin"
                )

            print(
                f"[{index}/{total}] "
                f"{system} "
                f"{operation} "
                f"{chunk_size // 1024} KiB "
                f"run {run}"
            )

            data = run_worker(
                system,
                operation,
                chunk_size,
                input_path,
                output_path,
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
                "file_size_bytes": FILE_SIZE,

                "chunk_size_bytes": (
                    chunk_size
                ),

                "system": system,

                "operation": operation,

                "run": run,

                "elapsed_seconds": (
                    data[
                        "elapsed_seconds"
                    ]
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

                "output_size_bytes": (
                    data[
                        "output_size_bytes"
                    ]
                ),
            })

            csv_file.flush()

    print(
        "\n========================================"
    )

    print(
        "Benchmark v4 completed."
    )

    print(
        f"Results: {RESULT_PATH}"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()
