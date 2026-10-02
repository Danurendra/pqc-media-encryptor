import csv
import os
import random
import threading
import time

import psutil

from app.crypto.aes_baseline import (
    encrypt_file_aes,
    decrypt_file_aes,
)

from app.crypto.stream_cipher import (
    encrypt_file_streaming,
    decrypt_file_streaming,
)


PROCESS = psutil.Process()

SAMPLE_INTERVAL = 0.001

SEED = bytes(range(64))

AES_KEY = bytes(range(32))


class MemoryMonitor:

    def __init__(self):

        self.peak_rss = 0

        self.stop_event = (
            threading.Event()
        )

        self.thread = None

    def sample(self):

        while not self.stop_event.is_set():

            rss = (
                PROCESS
                .memory_info()
                .rss
            )

            if rss > self.peak_rss:
                self.peak_rss = rss

            time.sleep(
                SAMPLE_INTERVAL
            )

    def start(self):

        self.peak_rss = (
            PROCESS
            .memory_info()
            .rss
        )

        self.stop_event.clear()

        self.thread = threading.Thread(
            target=self.sample,
            daemon=True,
        )

        self.thread.start()

    def stop(self):

        self.stop_event.set()

        if self.thread:
            self.thread.join()

        rss = (
            PROCESS
            .memory_info()
            .rss
        )

        self.peak_rss = max(
            self.peak_rss,
            rss,
        )


def run_operation(
    operation,
    input_path,
    output_path,
    file_size,
    *args,
):

    baseline_rss = (
        PROCESS
        .memory_info()
        .rss
    )

    monitor = MemoryMonitor()

    start = time.perf_counter()

    monitor.start()

    operation(
        input_path,
        output_path,
        *args,
    )

    monitor.stop()

    elapsed = (
        time.perf_counter()
        - start
    )

    throughput = (
        file_size
        / elapsed
        / (1024 * 1024)
    )

    peak_delta = (
        monitor.peak_rss
        - baseline_rss
    )

    return {
        "elapsed_seconds": elapsed,
        "throughput_mib_per_second": throughput,
        "baseline_rss_mib": (
            baseline_rss
            / (1024 * 1024)
        ),
        "peak_rss_mib": (
            monitor.peak_rss
            / (1024 * 1024)
        ),
        "peak_delta_rss_mib": (
            peak_delta
            / (1024 * 1024)
        ),
    }


def create_test_file(
    path,
    size,
):

    pattern = bytes(range(256))

    with open(path, "wb") as f:

        remaining = size

        while remaining > 0:

            block = min(
                len(pattern),
                remaining,
            )

            f.write(
                pattern[:block]
            )

            remaining -= block


def main():

    os.makedirs(
        "data/benchmark",
        exist_ok=True,
    )

    os.makedirs(
        "results",
        exist_ok=True,
    )

    file_size = (
        10 * 1024 * 1024
    )

    chunk_sizes = [
        4 * 1024,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
    ]

    repetitions = 5

    input_path = (
        "data/benchmark/"
        "benchmark_10mb.bin"
    )

    if not os.path.exists(input_path):

        create_test_file(
            input_path,
            file_size,
        )

    configurations = []

    for chunk_size in chunk_sizes:

        for system in [
            "aes",
            "hybrid",
        ]:

            for operation in [
                "encrypt",
                "decrypt",
            ]:

                for run in range(
                    1,
                    repetitions + 1,
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

    results_path = (
        "results/benchmark_v2.csv"
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

    # ------------------------------------
    # Warm-up
    # ------------------------------------

    print("Running warm-up...")

    warmup_encrypted = (
        "data/benchmark/warmup.pqcm"
    )

    warmup_recovered = (
        "data/benchmark/"
        "warmup_recovered.bin"
    )

    encrypt_file_streaming(
        input_path,
        warmup_encrypted,
        SEED,
        64 * 1024,
    )

    decrypt_file_streaming(
        warmup_encrypted,
        warmup_recovered,
        SEED,
    )

    warmup_aes = (
        "data/benchmark/"
        "warmup_aes.pqcm"
    )

    warmup_aes_recovered = (
        "data/benchmark/"
        "warmup_aes_recovered.bin"
    )

    encrypt_file_aes(
        input_path,
        warmup_aes,
        AES_KEY,
        64 * 1024,
    )

    decrypt_file_aes(
        warmup_aes,
        warmup_aes_recovered,
        AES_KEY,
    )

    print(
        "Warm-up complete."
    )

    # ------------------------------------
    # Benchmark
    # ------------------------------------

    with open(
        results_path,
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

            print(
                f"[{index}/{total}] "
                f"{system} "
                f"{operation} "
                f"{chunk_size // 1024} KiB "
                f"run {run}"
            )

            encrypted_path = (
                "data/benchmark/"
                f"tmp_{system}_"
                f"{chunk_size}.pqcm"
            )

            recovered_path = (
                "data/benchmark/"
                f"tmp_{system}_"
                f"{chunk_size}_"
                f"recovered.bin"
            )

            if system == "hybrid":

                if operation == "encrypt":

                    result = run_operation(
                        encrypt_file_streaming,
                        input_path,
                        encrypted_path,
                        file_size,
                        SEED,
                        chunk_size,
                    )

                    output_size = os.path.getsize(
                        encrypted_path
                    )

                else:

                    # Encryption is regenerated
                    # before decryption.
                    encrypt_file_streaming(
                        input_path,
                        encrypted_path,
                        SEED,
                        chunk_size,
                    )

                    result = run_operation(
                        decrypt_file_streaming,
                        encrypted_path,
                        recovered_path,
                        file_size,
                        SEED,
                    )

                    output_size = os.path.getsize(
                        recovered_path
                    )

            else:

                if operation == "encrypt":

                    result = run_operation(
                        encrypt_file_aes,
                        input_path,
                        encrypted_path,
                        file_size,
                        AES_KEY,
                        chunk_size,
                    )

                    output_size = os.path.getsize(
                        encrypted_path
                    )

                else:

                    encrypt_file_aes(
                        input_path,
                        encrypted_path,
                        AES_KEY,
                        chunk_size,
                    )

                    result = run_operation(
                        decrypt_file_aes,
                        encrypted_path,
                        recovered_path,
                        file_size,
                        AES_KEY,
                    )

                    output_size = os.path.getsize(
                        recovered_path
                    )

            writer.writerow({
                "file_size_bytes": file_size,
                "chunk_size_bytes": chunk_size,
                "system": system,
                "operation": operation,
                "run": run,
                **result,
                "output_size_bytes": output_size,
            })

            csv_file.flush()

    print(
        "\n========================================"
    )

    print(
        "Benchmark v2 completed."
    )

    print(
        f"Results: {results_path}"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()
