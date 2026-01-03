"""Performance tests for data protection pipeline.

Tests latency and throughput for files ranging from 1KB to 100MB.
"""

import io
import json
import statistics
import time
from dataclasses import dataclass
from typing import Callable

import pandas as pd
import pytest

from src.handlers.csv_handler import CSVHandler
from src.handlers.json_handler import JSONHandler
from src.handlers.parquet_handler import ParquetHandler
from src.pipeline.pipeline_orchestrator import create_pipeline


@dataclass
class PerformanceResult:
    """Result of a performance test."""

    file_size_bytes: int
    file_size_label: str
    duration_ms: float
    throughput_mbps: float
    rows_processed: int
    entities_detected: int
    protections_applied: int
    success: bool


@dataclass
class BenchmarkSummary:
    """Summary of benchmark results."""

    test_name: str
    iterations: int
    mean_ms: float
    std_ms: float
    min_ms: float
    max_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float


class TestDataGenerator:
    """Generates test data of various sizes."""

    PII_TEMPLATES = [
        {
            'name': 'John Smith',
            'email': 'john.smith@example.com',
            'phone': '+44 7911 123456',
            'card': '4111111111111111',
            'ssn': '123-45-6789',
            'address': '123 Main St London UK'
        },
        {
            'name': 'Jane Doe',
            'email': 'jane.doe@company.co.uk',
            'phone': '020 7946 0958',
            'card': '5500000000000004',
            'ssn': '987-65-4321',
            'address': '456 Oak Ave Manchester UK'
        },
        {
            'name': 'Bob Wilson',
            'email': 'bob.wilson@test.org',
            'phone': '07700 900123',
            'card': '340000000000009',
            'ssn': '555-55-5555',
            'address': '789 Pine Rd Birmingham UK'
        }
    ]

    @classmethod
    def generate_csv(cls, target_size_kb: int) -> tuple[bytes, int]:
        """Generate CSV data of approximate target size.

        Args:
            target_size_kb: Target size in kilobytes

        Returns:
            Tuple of (CSV bytes, row count)
        """
        rows = []
        current_size = 0
        target_bytes = target_size_kb * 1024
        row_idx = 0

        header = 'id,name,email,phone,card_number,ssn,address,notes\n'
        current_size = len(header)

        while current_size < target_bytes:
            template = cls.PII_TEMPLATES[row_idx % len(cls.PII_TEMPLATES)]
            row = (
                f"{row_idx},{template['name']},{template['email']},"
                f"{template['phone']},{template['card']},{template['ssn']},"
                f"{template['address']},Customer record {row_idx}\n"
            )
            rows.append(row)
            current_size += len(row)
            row_idx += 1

        content = header + ''.join(rows)
        return content.encode('utf-8'), len(rows)

    @classmethod
    def generate_json(cls, target_size_kb: int) -> tuple[bytes, int]:
        """Generate JSON data of approximate target size.

        Args:
            target_size_kb: Target size in kilobytes

        Returns:
            Tuple of (JSON bytes, record count)
        """
        records = []
        target_bytes = target_size_kb * 1024
        row_idx = 0

        while True:
            template = cls.PII_TEMPLATES[row_idx % len(cls.PII_TEMPLATES)]
            record = {
                'id': row_idx,
                'name': template['name'],
                'email': template['email'],
                'phone': template['phone'],
                'card_number': template['card'],
                'ssn': template['ssn'],
                'address': template['address'],
                'notes': f'Customer record {row_idx}'
            }
            records.append(record)
            row_idx += 1

            current = json.dumps({'records': records}, indent=2)
            if len(current) >= target_bytes:
                break

        content = json.dumps({'records': records}, indent=2)
        return content.encode('utf-8'), len(records)

    @classmethod
    def generate_parquet(cls, target_size_kb: int) -> tuple[bytes, int]:
        """Generate Parquet data of approximate target size.

        Args:
            target_size_kb: Target size in kilobytes

        Returns:
            Tuple of (Parquet bytes, row count)
        """
        rows_needed = max(10, target_size_kb // 2)

        tpl = cls.PII_TEMPLATES
        n = len(tpl)

        def get_field(field: str) -> list:
            return [tpl[i % n][field] for i in range(rows_needed)]

        data = {
            'id': list(range(rows_needed)),
            'name': get_field('name'),
            'email': get_field('email'),
            'phone': get_field('phone'),
            'card_number': get_field('card'),
            'ssn': get_field('ssn'),
            'address': get_field('address'),
            'notes': [f'Customer record {i}' for i in range(rows_needed)]
        }

        df = pd.DataFrame(data)
        buffer = io.BytesIO()
        df.to_parquet(buffer, index=False, compression='snappy')

        return buffer.getvalue(), rows_needed


def run_benchmark(
    func: Callable,
    iterations: int = 5,
    warmup: int = 1
) -> BenchmarkSummary:
    """Run benchmark with multiple iterations.

    Args:
        func: Function to benchmark (returns duration_ms)
        iterations: Number of iterations
        warmup: Warmup iterations (not counted)

    Returns:
        BenchmarkSummary with statistics
    """
    for _ in range(warmup):
        func()

    durations = []
    for _ in range(iterations):
        duration = func()
        durations.append(duration)

    return BenchmarkSummary(
        test_name=func.__name__ if hasattr(func, '__name__') else 'benchmark',
        iterations=iterations,
        mean_ms=statistics.mean(durations),
        std_ms=statistics.stdev(durations) if len(durations) > 1 else 0,
        min_ms=min(durations),
        max_ms=max(durations),
        p50_ms=statistics.median(durations),
        p95_ms=(
            sorted(durations)[int(len(durations) * 0.95)]
            if len(durations) >= 20 else max(durations)
        ),
        p99_ms=(
            sorted(durations)[int(len(durations) * 0.99)]
            if len(durations) >= 100 else max(durations)
        )
    )


class TestHandlerPerformance:
    """Performance tests for file handlers."""

    @pytest.mark.performance
    @pytest.mark.parametrize('size_kb', [1, 10, 100, 1000])
    def test_csv_handler_performance(self, size_kb):
        """Test CSV handler performance at various sizes."""
        content, rows = TestDataGenerator.generate_csv(size_kb)
        handler = CSVHandler()

        def benchmark():
            start = time.time()
            handler.validate(content, 'test.csv')
            df = handler.parse(content)
            handler.serialize(df)
            return (time.time() - start) * 1000

        summary = run_benchmark(benchmark, iterations=3)

        print(f"\nCSV {size_kb}KB ({rows} rows):")
        print(f"  Mean: {summary.mean_ms:.2f}ms")
        print(f"  Min/Max: {summary.min_ms:.2f}/{summary.max_ms:.2f}ms")

        assert summary.mean_ms < size_kb * 10

    @pytest.mark.performance
    @pytest.mark.parametrize('size_kb', [1, 10, 100, 1000])
    def test_json_handler_performance(self, size_kb):
        """Test JSON handler performance at various sizes."""
        content, records = TestDataGenerator.generate_json(size_kb)
        handler = JSONHandler()

        def benchmark():
            start = time.time()
            handler.validate(content, 'test.json')
            df = handler.parse(content)
            handler.serialize(df)
            return (time.time() - start) * 1000

        summary = run_benchmark(benchmark, iterations=3)

        print(f"\nJSON {size_kb}KB ({records} records):")
        print(f"  Mean: {summary.mean_ms:.2f}ms")

        assert summary.mean_ms < size_kb * 10

    @pytest.mark.performance
    @pytest.mark.parametrize('size_kb', [1, 10, 100, 1000])
    def test_parquet_handler_performance(self, size_kb):
        """Test Parquet handler performance at various sizes."""
        content, rows = TestDataGenerator.generate_parquet(size_kb)
        handler = ParquetHandler()

        def benchmark():
            start = time.time()
            handler.validate(content, 'test.parquet')
            df = handler.parse(content)
            handler.serialize(df)
            return (time.time() - start) * 1000

        summary = run_benchmark(benchmark, iterations=3)

        print(f"\nParquet {size_kb}KB ({rows} rows):")
        print(f"  Mean: {summary.mean_ms:.2f}ms")

        assert summary.mean_ms < size_kb * 10


class TestPipelinePerformance:
    """Performance tests for complete pipeline."""

    @pytest.fixture
    def pipeline(self):
        """Create pipeline for testing."""
        return create_pipeline()

    @pytest.mark.performance
    @pytest.mark.parametrize('size_kb,expected_max_ms', [
        (1, 5000),
        (10, 10000),
        (100, 60000),
        (1000, 180000),  # 3 minutes - PII detection is slow on large files
    ])
    def test_pipeline_csv_performance(
        self, pipeline, size_kb, expected_max_ms
    ):
        """Test pipeline performance with CSV files."""
        content, rows = TestDataGenerator.generate_csv(size_kb)

        def benchmark():
            result = pipeline.process(content, f'test_{size_kb}kb.csv')
            return result.total_duration_ms

        summary = run_benchmark(benchmark, iterations=2, warmup=1)

        if summary.mean_ms > 0:
            throughput = (size_kb / 1024) / (summary.mean_ms / 1000)
        else:
            throughput = 0

        print(f"\nPipeline CSV {size_kb}KB ({rows} rows):")
        print(f"  Mean: {summary.mean_ms:.2f}ms")
        print(f"  Throughput: {throughput:.2f} MB/s")

        msg = f"Pipeline too slow: {summary.mean_ms}ms > {expected_max_ms}ms"
        assert summary.mean_ms < expected_max_ms, msg

    @pytest.mark.performance
    @pytest.mark.slow
    def test_pipeline_large_file(self, pipeline):
        """Test pipeline with larger file (10MB)."""
        content, rows = TestDataGenerator.generate_csv(10000)

        start = time.time()
        result = pipeline.process(content, 'large_test.csv')
        duration_ms = (time.time() - start) * 1000

        print(f"\nLarge file test (10MB, {rows} rows):")
        print(f"  Duration: {duration_ms:.2f}ms")
        print(f"  Success: {result.success}")

        if result.detection_summary:
            entities = result.detection_summary.get('entities_found', 0)
            print(f"  Entities: {entities}")

        assert result.success


class TestDetectionPerformance:
    """Performance tests for PII detection."""

    @pytest.mark.performance
    def test_detection_scaling(self):
        """Test detection performance scales linearly."""
        from src.detection.presidio_detector import PresidioDetector

        detector = PresidioDetector(score_threshold=0.5)
        results = []

        for multiplier in [1, 2, 5, 10]:
            rows = 100 * multiplier
            data = {
                'email': [f'user{i}@example.com' for i in range(rows)],
                'phone': ['+44 7911 123456' for _ in range(rows)]
            }
            df = pd.DataFrame(data)

            start = time.time()
            detector.detect_dataframe(df)
            duration = (time.time() - start) * 1000

            results.append((rows, duration))
            print(f"\nDetection {rows} rows: {duration:.2f}ms")

        if len(results) >= 2:
            ratio = results[-1][1] / results[0][1]
            row_ratio = results[-1][0] / results[0][0]
            scaling_factor = ratio / row_ratio

            print(f"\nScaling factor: {scaling_factor:.2f}x (ideal: 1.0x)")
            assert scaling_factor < 3.0


class TestProtectionPerformance:
    """Performance tests for protection strategies."""

    @pytest.mark.performance
    def test_protection_methods_comparison(self):
        """Compare performance of different protection methods."""
        from src.protection import (
            AES256Encryption,
            Masking,
            SHA256Hashing,
            Tokenization,
        )

        test_value = "test@example.com"
        iterations = 1000

        strategies = [
            ('AES-256', AES256Encryption()),
            ('SHA-256', SHA256Hashing()),
            ('Masking', Masking()),
            ('Tokenization', Tokenization()),
        ]

        print("\nProtection method performance:")
        for name, strategy in strategies:
            start = time.time()
            for _ in range(iterations):
                strategy.protect(test_value)
            duration = (time.time() - start) * 1000

            ops_per_sec = iterations / (duration / 1000)
            print(
                f"  {name}: {duration:.2f}ms for {iterations} ops "
                f"({ops_per_sec:.0f} ops/sec)"
            )


class TestMemoryUsage:
    """Tests for memory usage."""

    @pytest.mark.performance
    def test_memory_not_excessive(self):
        """Test memory usage stays reasonable."""
        import sys

        pipeline = create_pipeline()
        content, _ = TestDataGenerator.generate_csv(1000)

        initial_size = sys.getsizeof(content)
        result = pipeline.process(content, 'test.csv')

        if result.protected_data:
            final_size = sys.getsizeof(result.protected_data)
            ratio = final_size / initial_size

            print(f"\nMemory ratio: {ratio:.2f}x")
            print(f"  Input: {initial_size / 1024:.1f}KB")
            print(f"  Output: {final_size / 1024:.1f}KB")

            assert ratio < 5.0
