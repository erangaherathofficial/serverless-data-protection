"""Generate synthetic test data for performance and integration testing.

Creates test files with varying sizes and PII patterns across CSV, JSON,
and Parquet formats.
"""

import io
import random
from pathlib import Path
from typing import Any

import pandas as pd

import json


class SyntheticDataGenerator:
    """Generates synthetic test data with realistic PII patterns."""

    # UK-specific PII templates
    UK_NAMES = [
        'James Smith', 'Emma Johnson', 'Oliver Williams', 'Sophia Brown',
        'Harry Jones', 'Emily Taylor', 'Charlie Wilson', 'Olivia Davies',
        'Jack Thomas', 'Amelia Roberts', 'George Evans', 'Mia Walker',
        'William Wright', 'Isabella Robinson', 'Henry Hall', 'Lily Green',
        'Oscar King', 'Ava Wood', 'Thomas Harris', 'Grace Lewis'
    ]

    UK_POSTCODES = [
        'SW1A 1AA', 'EC1A 1BB', 'W1A 0AX', 'M1 1AE', 'B1 1AA',
        'G1 1AA', 'EH1 1AA', 'CF10 1AA', 'BT1 1AA', 'LS1 1AA',
        'NE1 1AA', 'S1 1AA', 'NG1 1AA', 'L1 1AA', 'BS1 1AA'
    ]

    UK_PHONE_FORMATS = [
        '+44 7{:03d} {:06d}',
        '07{:03d} {:06d}',
        '+44 20 {:04d} {:04d}',
        '020 {:04d} {:04d}',
        '0{:04d} {:06d}'
    ]

    DOMAINS = [
        'gmail.com', 'outlook.co.uk', 'yahoo.co.uk', 'company.co.uk',
        'university.ac.uk', 'business.com', 'organisation.org.uk'
    ]

    UK_CITIES = [
        'London', 'Manchester', 'Birmingham', 'Leeds', 'Glasgow',
        'Liverpool', 'Bristol', 'Sheffield', 'Edinburgh', 'Cardiff'
    ]

    def __init__(self, seed: int = 42):
        """Initialize generator with seed for reproducibility."""
        random.seed(seed)
        self.output_dir = Path(__file__).parent

    def _generate_email(self, name: str) -> str:
        """Generate email from name."""
        parts = name.lower().split()
        patterns = [
            f"{parts[0]}.{parts[1]}",
            f"{parts[0][0]}{parts[1]}",
            f"{parts[0]}{parts[1][0]}",
            f"{parts[0]}_{parts[1]}",
        ]
        return f"{random.choice(patterns)}@{random.choice(self.DOMAINS)}"

    def _generate_phone(self) -> str:
        """Generate UK phone number."""
        fmt = random.choice(self.UK_PHONE_FORMATS)
        return fmt.format(
            random.randint(100, 999),
            random.randint(100000, 999999)
        )

    def _generate_nino(self) -> str:
        """Generate UK National Insurance Number."""
        prefixes = ['AB', 'CD', 'EF', 'GH', 'JK', 'LM', 'NP', 'RS']
        prefix = random.choice(prefixes)
        numbers = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        suffix = random.choice(['A', 'B', 'C', 'D'])
        return f"{prefix}{numbers}{suffix}"

    def _generate_nhs_number(self) -> str:
        """Generate NHS number (10 digits)."""
        return ''.join([str(random.randint(0, 9)) for _ in range(10)])

    def _generate_credit_card(self) -> str:
        """Generate test credit card number (Luhn-invalid for safety)."""
        prefixes = ['4111', '5500', '3782', '6011']
        prefix = random.choice(prefixes)
        remaining = ''.join([str(random.randint(0, 9)) for _ in range(12)])
        return f"{prefix}{remaining}"

    def _generate_address(self) -> str:
        """Generate UK address."""
        number = random.randint(1, 200)
        street_types = ['Street', 'Road', 'Avenue', 'Lane', 'Close', 'Way']
        street_names = ['High', 'Church', 'Victoria', 'Station', 'Park']
        city = random.choice(self.UK_CITIES)
        postcode = random.choice(self.UK_POSTCODES)
        street = random.choice(street_names)
        st_type = random.choice(street_types)
        # Avoid commas to prevent CSV parsing issues
        return f"{number} {street} {st_type} {city} {postcode}"

    def _generate_dob(self) -> str:
        """Generate date of birth."""
        year = random.randint(1950, 2005)
        month = random.randint(1, 12)
        day = random.randint(1, 28)
        return f"{year:04d}-{month:02d}-{day:02d}"

    def generate_record(
            self, include_sensitive: bool = True
    ) -> dict[str, Any]:
        """Generate single record with PII data."""
        name = random.choice(self.UK_NAMES)

        record = {
            'id': random.randint(10000, 99999),
            'name': name,
            'email': self._generate_email(name),
            'phone': self._generate_phone(),
            'address': self._generate_address(),
            'postcode': random.choice(self.UK_POSTCODES),
            'date_of_birth': self._generate_dob(),
            'notes': f"Customer since {random.randint(2010, 2024)}"
        }

        if include_sensitive:
            record.update({
                'national_insurance': self._generate_nino(),
                'nhs_number': self._generate_nhs_number(),
                'credit_card': self._generate_credit_card(),
            })

        return record

    def generate_csv_data(
            self, rows: int, include_sensitive: bool = True
    ) -> bytes:
        """Generate CSV data with specified number of rows."""
        records = [
            self.generate_record(include_sensitive) for _ in range(rows)
        ]
        df = pd.DataFrame(records)
        return df.to_csv(index=False).encode('utf-8')

    def generate_json_data(
            self, records_count: int, nested: bool = False
    ) -> bytes:
        """Generate JSON data with specified number of records."""
        records = [self.generate_record() for _ in range(records_count)]

        if nested:
            data = {
                'metadata': {
                    'version': '1.0',
                    'record_count': records_count,
                    'generated_by': 'SyntheticDataGenerator'
                },
                'customers': records
            }
        else:
            data = {'records': records}

        return json.dumps(data, indent=2).encode('utf-8')

    def generate_ndjson_data(self, records_count: int) -> bytes:
        """Generate newline-delimited JSON data."""
        records = [self.generate_record() for _ in range(records_count)]
        lines = [json.dumps(r) for r in records]
        return '\n'.join(lines).encode('utf-8')

    def generate_parquet_data(self, rows: int) -> bytes | None:
        """Generate Parquet data with specified number of rows."""
        try:
            records = [self.generate_record() for _ in range(rows)]
            df = pd.DataFrame(records)
            buffer = io.BytesIO()
            df.to_parquet(buffer, index=False, compression='snappy')
            return buffer.getvalue()
        except ImportError:
            return None

    def create_test_files(self):
        """Create all test data files."""
        csv_dir = self.output_dir / 'csv'
        json_dir = self.output_dir / 'json'
        parquet_dir = self.output_dir / 'parquet'

        # Ensure directories exist
        csv_dir.mkdir(exist_ok=True)
        json_dir.mkdir(exist_ok=True)
        parquet_dir.mkdir(exist_ok=True)

        # CSV files of various sizes
        csv_sizes = [
            ('small', 100),
            ('medium', 1000),
            ('large', 10000),
        ]

        for name, rows in csv_sizes:
            data = self.generate_csv_data(rows)
            (csv_dir / f'{name}_{rows}_rows.csv').write_bytes(data)
            print(f"Created CSV: {name}_{rows}_rows.csv ({len(data)} bytes)")

        # CSV without sensitive data
        data = self.generate_csv_data(500, include_sensitive=False)
        (csv_dir / 'no_sensitive_500_rows.csv').write_bytes(data)
        print(f"Created CSV: no_sensitive_500_rows.csv ({len(data)} bytes)")

        # JSON files
        json_sizes = [
            ('small', 100),
            ('medium', 1000),
        ]

        for name, records in json_sizes:
            # Standard JSON
            data = self.generate_json_data(records)
            fname = f'{name}_{records}_records.json'
            (json_dir / fname).write_bytes(data)
            print(f"Created JSON: {fname} ({len(data)} bytes)")

            # Nested JSON
            data = self.generate_json_data(records, nested=True)
            fname = f'{name}_{records}_nested.json'
            (json_dir / fname).write_bytes(data)
            print(f"Created JSON: {fname} ({len(data)} bytes)")

        # NDJSON
        data = self.generate_ndjson_data(500)
        (json_dir / 'ndjson_500_records.ndjson').write_bytes(data)
        print(f"Created NDJSON: ndjson_500_records.ndjson ({len(data)} bytes)")

        # Parquet files
        parquet_sizes = [
            ('small', 100),
            ('medium', 1000),
            ('large', 10000),
        ]

        for name, rows in parquet_sizes:
            data = self.generate_parquet_data(rows)
            fname = f'{name}_{rows}_rows.parquet'
            if data:
                (parquet_dir / fname).write_bytes(data)
                print(f"Created Parquet: {fname} ({len(data)} bytes)")
            else:
                print(f"Skipped Parquet: {fname} (pyarrow unavailable)")

        print("\nTest data generation complete!")


def main():
    """Generate all test data files."""
    generator = SyntheticDataGenerator()
    generator.create_test_files()


if __name__ == '__main__':
    main()
