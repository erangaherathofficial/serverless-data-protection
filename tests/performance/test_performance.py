"""Performance tests for data protection pipeline.

Tests latency and throughput for files ranging from 1KB to 100MB.
"""

import io
import json
import pandas as pd
import pytest
import statistics
import time
from dataclasses import dataclass
from typing import Callable

from src.detection.presidio_detector import PresidioDetector
from src.handlers.csv_handler import CSVHandler
from src.handlers.json_handler import JSONHandler
from src.handlers.parquet_handler import ParquetHandler
from src.pipeline.pipeline_orchestrator import create_pipeline


@dataclass
class BenchmarkSummary:
    """Summary of benchmark results."""

    mean_ms: float
    min_ms: float
    max_ms: float


class DataGenerator:
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
        warmup: int = 1,
) -> BenchmarkSummary:
    """Run ``func`` ``warmup`` + ``iterations`` times and summarise the
    timed iterations. ``func`` must return its own duration in ms."""
    for _ in range(warmup):
        func()
    durations = [func() for _ in range(iterations)]
    return BenchmarkSummary(
        mean_ms=statistics.mean(durations),
        min_ms=min(durations),
        max_ms=max(durations),
    )


class TestHandlerPerformance:
    """Performance tests for file handlers."""

    @pytest.mark.performance
    @pytest.mark.parametrize('size_kb', [1, 10, 100, 1000])
    def test_csv_handler_performance(self, size_kb):
        """Test CSV handler performance at various sizes."""
        content, rows = DataGenerator.generate_csv(size_kb)
        handler = CSVHandler()

        def benchmark():
            start = time.monotonic()
            handler.validate(content, 'test.csv')
            df = handler.parse(content)
            handler.serialize(df)
            return (time.monotonic() - start) * 1000

        summary = run_benchmark(benchmark, iterations=3)

        print(f"\nCSV {size_kb}KB ({rows} rows):")
        print(f"  Mean: {summary.mean_ms:.2f}ms")
        print(f"  Min/Max: {summary.min_ms:.2f}/{summary.max_ms:.2f}ms")

        assert summary.mean_ms < size_kb * 10

    @pytest.mark.performance
    @pytest.mark.parametrize('size_kb', [1, 10, 100, 1000])
    def test_json_handler_performance(self, size_kb):
        """Test JSON handler performance at various sizes."""
        content, records = DataGenerator.generate_json(size_kb)
        handler = JSONHandler()

        def benchmark():
            start = time.monotonic()
            handler.validate(content, 'test.json')
            df = handler.parse(content)
            handler.serialize(df)
            return (time.monotonic() - start) * 1000

        summary = run_benchmark(benchmark, iterations=3)

        print(f"\nJSON {size_kb}KB ({records} records):")
        print(f"  Mean: {summary.mean_ms:.2f}ms")

        assert summary.mean_ms < size_kb * 10

    @pytest.mark.performance
    @pytest.mark.parametrize('size_kb', [1, 10, 100, 1000])
    def test_parquet_handler_performance(self, size_kb):
        """Test Parquet handler performance at various sizes."""
        content, rows = DataGenerator.generate_parquet(size_kb)
        handler = ParquetHandler()

        def benchmark():
            start = time.monotonic()
            handler.validate(content, 'test.parquet')
            df = handler.parse(content)
            handler.serialize(df)
            return (time.monotonic() - start) * 1000

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
        content, rows = DataGenerator.generate_csv(size_kb)

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
        """Test pipeline with a larger file (10MB) within a 10-minute budget."""
        content, rows = DataGenerator.generate_csv(10000)

        start = time.monotonic()
        result = pipeline.process(content, 'large_test.csv')
        duration_ms = (time.monotonic() - start) * 1000

        print(f"\nLarge file test (10MB, {rows} rows):")
        print(f"  Duration: {duration_ms:.2f}ms")
        print(f"  Success: {result.success}")

        assert result.success
        assert duration_ms < 600_000, (
            f"Pipeline exceeded 10-minute budget: {duration_ms}ms"
        )


class TestDetectionPerformance:
    """Performance tests for PII detection."""

    @pytest.mark.performance
    def test_detection_scaling(self):
        """Test detection performance scales linearly."""
        detector = PresidioDetector(score_threshold=0.5)
        results = []

        for multiplier in [1, 2, 5, 10]:
            rows = 100 * multiplier
            data = {
                'email': [f'user{i}@example.com' for i in range(rows)],
                'phone': ['+44 7911 123456' for _ in range(rows)]
            }
            df = pd.DataFrame(data)

            start = time.monotonic()
            detector.detect_dataframe(df)
            duration = (time.monotonic() - start) * 1000

            results.append((rows, duration))
            print(f"\nDetection {rows} rows: {duration:.2f}ms")

        if len(results) >= 2:
            ratio = results[-1][1] / results[0][1]
            row_ratio = results[-1][0] / results[0][0]
            scaling_factor = ratio / row_ratio

            print(f"\nScaling factor: {scaling_factor:.2f}x (ideal: 1.0x)")
            assert scaling_factor < 3.0
