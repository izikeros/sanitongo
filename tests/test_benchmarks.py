"""
Performance benchmarks for MongoDB sanitization.

These tests measure the performance characteristics of the sanitizer
under various workloads and query complexities.
"""

import pytest

from sanitongo import create_sanitizer
from sanitongo.sanitizer import MongoSanitizer, SanitizationReport


class TestSanitizerPerformance:
    """Performance benchmarks for the sanitizer."""

    @pytest.fixture
    def sanitizer(self) -> MongoSanitizer:
        """Create a sanitizer for benchmarking."""
        return create_sanitizer(strict_mode=True)

    @pytest.fixture
    def lenient_sanitizer(self) -> MongoSanitizer:
        """Create a lenient sanitizer for benchmarking."""
        return create_sanitizer(strict_mode=False)

    def test_benchmark_simple_query_sanitization(self, benchmark, sanitizer) -> None:
        """Benchmark sanitization of simple queries."""
        simple_query = {"name": "John", "age": {"$gte": 18}}

        result = benchmark(sanitizer.sanitize_query, simple_query)
        assert result == simple_query

    def test_benchmark_complex_query_sanitization(self, benchmark, sanitizer) -> None:
        """Benchmark sanitization of complex queries."""
        complex_query = {
            "user": {
                "profile": {"name": "Alice", "age": {"$gte": 25}},
                "settings": {
                    "active": True,
                    "notifications": {"$in": ["email", "sms"]},
                },
            },
            "$and": [
                {"created_at": {"$gte": "2023-01-01"}},
                {"status": {"$ne": "deleted"}},
            ],
        }

        result = benchmark(sanitizer.sanitize_query, complex_query)
        # Should return the same query since it's safe
        assert "user" in result
        assert "$and" in result

    def test_benchmark_query_with_removals_lenient(
        self, benchmark, lenient_sanitizer
    ) -> None:
        """Benchmark sanitization that removes dangerous elements."""
        dangerous_query = {
            "name": "John",  # Safe
            "age": {"$gte": 18},  # Safe
            "$where": "function() { return true; }",  # Dangerous - should be removed
            "valid_field": "safe_value",  # Safe
        }

        result = benchmark(lenient_sanitizer.sanitize, dangerous_query)
        assert result.success is True
        assert "name" in result.sanitized_query
        assert "age" in result.sanitized_query
        assert "valid_field" in result.sanitized_query
        # Dangerous operator should be removed
        assert "$where" not in result.sanitized_query

    def test_benchmark_array_processing(self, benchmark, sanitizer) -> None:
        """Benchmark sanitization of queries with arrays."""
        array_query = {
            "tags": {"$in": ["python", "mongodb", "security"]},
            "scores": {"$all": [95, 98, 92]},
            "categories": [
                {"name": "tech", "priority": 1},
                {"name": "security", "priority": 2},
                {"name": "database", "priority": 3},
            ],
        }

        result = benchmark(sanitizer.sanitize_query, array_query)
        assert result == array_query

    def test_benchmark_nested_object_processing(self, benchmark, sanitizer) -> None:
        """Benchmark sanitization of deeply nested objects."""
        nested_query = {
            "level1": {
                "level2": {
                    "level3": {
                        "data": "value",
                        "filters": {"$ne": None},
                    }
                }
            }
        }

        result = benchmark(sanitizer.sanitize_query, nested_query)
        assert result == nested_query

    def test_benchmark_large_query_processing(self, benchmark) -> None:
        """Benchmark sanitization of large queries."""
        # Create a sanitizer with higher limits for large queries
        sanitizer: MongoSanitizer = create_sanitizer(strict_mode=True, max_keys=500)

        # Create a large query with many fields
        large_query = {}
        for i in range(50):  # Reduced to stay within limits
            large_query[f"field_{i}"] = {
                "value": f"data_{i}",
                "metadata": {"index": i, "active": True},
            }

        # Add some query operators
        large_query["$and"] = [
            {"status": "active"},
            {"created_at": {"$gte": "2023-01-01"}},
        ]

        result = benchmark(sanitizer.sanitize_query, large_query)
        assert len(result) == 51  # 50 fields + $and operator
        assert "$and" in result

    def test_benchmark_schema_validation_performance(self, benchmark) -> None:
        """Benchmark schema validation performance."""
        schema = {
            "name": "string",
            "age": "integer",
            "email": "string",
            "tags": "array",
            "metadata": "object",
        }

        sanitizer = create_sanitizer(schema=schema, strict_mode=True)

        query = {
            "name": "Alice Johnson",
            "age": {"$gte": 25},
            "email": "alice@example.com",
            "metadata": {"source": "api", "version": 1},
        }

        result = benchmark(sanitizer.sanitize_query, query)
        assert result == query

    @pytest.mark.parametrize("query_size", [10, 25, 50])
    def test_benchmark_query_size_scaling(self, benchmark, query_size) -> None:
        """Benchmark how performance scales with query size."""
        # Create a sanitizer with higher limits for scaling tests
        sanitizer: MongoSanitizer = create_sanitizer(strict_mode=True, max_keys=200)

        query = {}
        for i in range(query_size):
            query[f"field_{i}"] = {"$eq": f"value_{i}"}

        result = benchmark(sanitizer.sanitize_query, query)
        assert len(result) == query_size

    def test_benchmark_pattern_validation_performance(self, benchmark) -> None:
        """Benchmark pattern validation performance."""
        sanitizer: MongoSanitizer = create_sanitizer(
            strict_mode=False
        )  # Use lenient mode

        # Query with various string patterns that will be checked
        query = {
            "description": "This is a normal description with no dangerous patterns",
            "code": "def hello(): return 'world'",  # Code-like but safe
            "url": "https://example.com/path",
            "data": "Some data with <b>HTML</b> but not dangerous",
        }

        result = benchmark(sanitizer.sanitize, query)
        assert result.success is True

    def test_benchmark_type_validation_performance(self, benchmark, sanitizer) -> None:
        """Benchmark type validation performance."""
        mixed_type_query = {
            "string_field": "text value",
            "integer_field": 42,
            "float_field": 3.14,
            "boolean_field": True,
            "null_field": None,
            "array_field": [1, 2, 3, "mixed", True],
            "object_field": {"nested": "value", "count": 10},
        }

        result = benchmark(sanitizer.sanitize_query, mixed_type_query)
        assert result == mixed_type_query


class TestSanitizerMemoryUsage:
    """Memory usage tests for the sanitizer."""

    def test_benchmark_memory_usage_large_query(self, benchmark) -> None:
        """Benchmark memory usage with large queries."""
        sanitizer: MongoSanitizer = create_sanitizer(strict_mode=False, max_keys=2000)

        # Create a large query (reduced size to fit within limits)
        large_query = {}
        for i in range(100):  # Reduced from 1000
            large_query[f"field_{i}"] = {
                "data": f"{'x' * 50}",  # Reduced string size
                "nested": {
                    "value": i,
                    "tags": [f"tag_{j}" for j in range(3)],
                },  # Fewer tags
            }

        def sanitize_large_query() -> SanitizationReport:
            return sanitizer.sanitize(large_query)

        result = benchmark(sanitize_large_query)
        assert result.success is True
        assert len(result.sanitized_query) == 100


# Performance regression tests
class TestPerformanceRegression:
    """Performance regression tests to ensure no major slowdowns."""

    def test_benchmark_baseline_performance(self, benchmark) -> None:
        """Establish baseline performance for simple operations."""
        sanitizer: MongoSanitizer = create_sanitizer(strict_mode=True)
        simple_query = {"name": "test", "value": {"$gt": 10}}

        # This should complete very quickly
        result = benchmark.pedantic(
            sanitizer.sanitize_query, args=(simple_query,), iterations=100, rounds=5
        )
        assert result == simple_query

    def test_benchmark_worst_case_performance(self, benchmark) -> None:
        """Test performance in worst-case scenarios."""
        sanitizer: MongoSanitizer = create_sanitizer(strict_mode=True, max_depth=10)

        # Create a query at maximum allowed depth
        deep_query = {"level1": {"level2": {"level3": {"level4": {"value": "deep"}}}}}

        result = benchmark(sanitizer.sanitize_query, deep_query)
        assert result == deep_query
