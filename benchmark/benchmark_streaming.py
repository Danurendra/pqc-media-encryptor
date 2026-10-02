import csv
import os
import threading
import time

import psutil

from app.crypto.stream_cipher import (
    encrypt_file_streaming,
    decrypt_file_streaming,
)


SEED = bytes(range(64))

PROCESS = psutil.Process()

SAMPLE_INTERVAL = 0.001


class MemoryMonitor:
    """
    Sample process RSS while an operation is running.
    """

    def __init__(self):
        self.peak_rss = 0
        self._stop_event = threading.Event()
        self._thread = None

    def _sample(self):
        while not self._stop_event.is_set():

            rss = PROCESS.memory_info().rss

            if rss > self.peak_rss:
                self.peak_rss = rss

            time.sleep(
                SAMPLE_INTERVAL
            )

    def start(self):

        # Capture RSS immediately before
        # the operation starts.
        self.peak_rss = (
            PROCESS.memory_info().rss
        )

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._sample,
            daemon=True,
        )

        self._thread.start()

    def stop(self):

        self._stop_event.set()

        if self._thread is not None:
            self._thread.join()

        # Final RSS sample.
        rss = PROCESS.memory_info().rss

        if rss > self.peak_rss:
            self.peak_rss = rss


def benchmark_operation(
    operation,
    input_path,
    output_path,
    file_size,
    chunk_size,
):

    monitor = MemoryMonitor()

    start = time.perf_counter()

    monitor.start()

    operation(
        input_path,
        output_path,
        SEED,
        chunk_size,
    )

    monitor.stop()

    elapsed = (
        time.perf_counter()
        - start
    )

    throughput = (
        file_size / elapsed
    )

    return {
        "elapsed_seconds": elapsed,
        "throughput_bytes_per_second": throughput,
        "throughput_mib_per_second": (
            throughput / (1024 * 1024)
        ),
        "peak_rss_bytes": monitor.peak_rss,
        "peak_rss_mib": (
            monitor.peak_rss
            / (1024 * 1024)
        ),
    }


def benchmark_decryption(
    input_path,
    output_path,
    file_size,
):

    monitor = MemoryMonitor()

    start = time.perf_counter()

    monitor.start()

    decrypt_file_streaming(
        input_path=input_path,
        output_path=output_path,
        seed=SEED,
    )

    monitor.stop()

    elapsed = (
        time.perf_counter()
        - start
    )

    throughput = (
        file_size / elapsed
    )

    return {
        "elapsed_seconds": elapsed,
        "throughput_bytes_per_second": throughput,
        "throughput_mib_per_second": (
            throughput / (1024 * 1024)
        ),
        "peak_rss_bytes": monitor.peak_rss,
        "peak_rss_mib": (
            monitor.peak_rss
            / (1024 * 1024)
        ),
    }


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

    input_path = (
        "data/benchmark/test_10mb.bin"
    )

    if not os.path.exists(input_path):

        print(
            "Creating 10 MiB benchmark file..."
        )

        create_test_file(
            input_path,
            file_size,
        )

    results_path = (
        "results/benchmark_v1.csv"
    )

    fieldnames = [
        "file_size_bytes",
        "chunk_size_bytes",
        "operation",
        "elapsed_seconds",
        "throughput_mib_per_second",
        "peak_rss_bytes",
        "peak_rss_mib",
        "output_size_bytes",
    ]

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

        for chunk_size in chunk_sizes:

            print(
                "\n================================"
            )

            print(
                f"Chunk size: "
                f"{chunk_size / 1024:.0f} KiB"
            )

            print(
                "================================"
            )

            encrypted_path = (
                "data/benchmark/"
                f"test_10mb_"
                f"{chunk_size}.pqcm"
            )

            recovered_path = (
                "data/benchmark/"
                f"test_10mb_"
                f"{chunk_size}_recovered.bin"
            )

            # -----------------------------
            # Encryption
            # -----------------------------

            encryption = benchmark_operation(
                encrypt_file_streaming,
                input_path,
                encrypted_path,
                file_size,
                chunk_size,
            )

            encrypted_size = os.path.getsize(
                encrypted_path
            )

            print(
                f"Encryption time : "
                f"{encryption['elapsed_seconds']:.6f} s"
            )

            print(
                f"Encryption speed: "
                f"{encryption['throughput_mib_per_second']:.2f} MiB/s"
            )

            print(
                f"Peak RSS        : "
                f"{encryption['peak_rss_mib']:.2f} MiB"
            )

            writer.writerow({
                "file_size_bytes": file_size,
                "chunk_size_bytes": chunk_size,
                "operation": "encrypt",
                "elapsed_seconds": (
                    encryption["elapsed_seconds"]
                ),
                "throughput_mib_per_second": (
                    encryption[
                        "throughput_mib_per_second"
                    ]
                ),
                "peak_rss_bytes": (
                    encryption[
                        "peak_rss_bytes"
                    ]
                ),
                "peak_rss_mib": (
                    encryption[
                        "peak_rss_mib"
                    ]
                ),
                "output_size_bytes": encrypted_size,
            })

            # -----------------------------
            # Decryption
            # -----------------------------

            decryption = benchmark_decryption(
                encrypted_path,
                recovered_path,
                file_size,
            )

            recovered_size = os.path.getsize(
                recovered_path
            )

            print(
                f"Decryption time : "
                f"{decryption['elapsed_seconds']:.6f} s"
            )

            print(
                f"Decryption speed: "
                f"{decryption['throughput_mib_per_second']:.2f} MiB/s"
            )

            print(
                f"Peak RSS        : "
                f"{decryption['peak_rss_mib']:.2f} MiB"
            )

            writer.writerow({
                "file_size_bytes": file_size,
                "chunk_size_bytes": chunk_size,
                "operation": "decrypt",
                "elapsed_seconds": (
                    decryption["elapsed_seconds"]
                ),
                "throughput_mib_per_second": (
                    decryption[
                        "throughput_mib_per_second"
                    ]
                ),
                "peak_rss_bytes": (
                    decryption[
                        "peak_rss_bytes"
                    ]
                ),
                "peak_rss_mib": (
                    decryption[
                        "peak_rss_mib"
                    ]
                ),
                "output_size_bytes": recovered_size,
            })

    print(
        "\n========================================"
    )

    print(
        "Benchmark completed."
    )

    print(
        f"Raw results: {results_path}"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()
