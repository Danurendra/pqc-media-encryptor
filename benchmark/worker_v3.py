import argparse
import json
import os
import time
import threading

import psutil

from app.crypto.file_format import HEADER_STRUCT

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
        self.stop_event = threading.Event()
        self.thread = None

    def _sample(self):
        while not self.stop_event.is_set():
            rss = PROCESS.memory_info().rss

            if rss > self.peak_rss:
                self.peak_rss = rss

            time.sleep(SAMPLE_INTERVAL)

    def start(self):
        self.peak_rss = PROCESS.memory_info().rss
        self.stop_event.clear()

        self.thread = threading.Thread(
            target=self._sample,
            daemon=True,
        )

        self.thread.start()

    def stop(self):
        self.stop_event.set()

        if self.thread is not None:
            self.thread.join()

        rss = PROCESS.memory_info().rss
        self.peak_rss = max(
            self.peak_rss,
            rss,
        )


def run_encrypt(
    system,
    input_path,
    output_path,
    chunk_size,
):
    if system == "hybrid":
        operation = lambda: encrypt_file_streaming(
            input_path,
            output_path,
            SEED,
            chunk_size,
        )

    elif system == "aes":
        operation = lambda: encrypt_file_aes(
            input_path,
            output_path,
            AES_KEY,
            chunk_size,
        )

    else:
        raise ValueError(
            f"Unknown system: {system}"
        )

    return operation


def run_decrypt(
    system,
    input_path,
    output_path,
):
    if system == "hybrid":
        operation = lambda: decrypt_file_streaming(
            input_path,
            output_path,
            SEED,
        )

    elif system == "aes":
        operation = lambda: decrypt_file_aes(
            input_path,
            output_path,
            AES_KEY,
        )

    else:
        raise ValueError(
            f"Unknown system: {system}"
        )

    return operation

def get_original_size_from_encrypted_file(
    path,
    system,
):
    with open(path, "rb") as f:

        if system == "hybrid":
            fixed_header = f.read(
                HEADER_STRUCT.size
            )

            if len(fixed_header) != HEADER_STRUCT.size:
                raise ValueError(
                    "Encrypted file header is truncated"
                )

            (
                magic,
                version,
                algorithm_id,
                chunk_size,
                original_size,
                chunk_count,
                kem_ciphertext_length,
                nonce_prefix,
            ) = HEADER_STRUCT.unpack(
                fixed_header
            )

            return original_size

        elif system == "aes":
            # AES baseline header:
            # >4sBIQ8s
            import struct

            AES_HEADER_STRUCT = struct.Struct(
                ">4sBIQ8s"
            )

            header = f.read(
                AES_HEADER_STRUCT.size
            )

            if len(header) != AES_HEADER_STRUCT.size:
                raise ValueError(
                    "AES encrypted file header is truncated"
                )

            (
                magic,
                version,
                chunk_size,
                original_size,
                nonce_prefix,
            ) = AES_HEADER_STRUCT.unpack(
                header
            )

            return original_size

        else:
            raise ValueError(
                f"Unknown system: {system}"
            )

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--system",
        required=True,
        choices=["aes", "hybrid"],
    )

    parser.add_argument(
        "--operation",
        required=True,
        choices=["encrypt", "decrypt"],
    )

    parser.add_argument(
        "--input",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    parser.add_argument(
        "--chunk-size",
        type=int,
        required=True,
    )

    args = parser.parse_args()

    file_size = os.path.getsize(
        args.input
    )

    baseline_rss = PROCESS.memory_info().rss

    if args.operation == "encrypt":

        operation = run_encrypt(
            args.system,
            args.input,
            args.output,
            args.chunk_size,
        )

    else:

        operation = run_decrypt(
            args.system,
            args.input,
            args.output,
        )

    monitor = MemoryMonitor()

    start = time.perf_counter()

    monitor.start()

    operation()

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

    result = {
        "file_size_bytes": file_size,
        "elapsed_seconds": elapsed,
        "throughput_mib_per_second": throughput,
        "baseline_rss_bytes": baseline_rss,
        "baseline_rss_mib": (
            baseline_rss
            / (1024 * 1024)
        ),
        "peak_rss_bytes": monitor.peak_rss,
        "peak_rss_mib": (
            monitor.peak_rss
            / (1024 * 1024)
        ),
        "peak_delta_rss_mib": (
            (
                monitor.peak_rss
                - baseline_rss
            )
            / (1024 * 1024)
        ),
        "output_size_bytes": os.path.getsize(
            args.output
        ),
    }

    print(
        json.dumps(result)
    )



if __name__ == "__main__":
    main()
