"""Tests for the main MongoSanitizer class."""

from typing import Any

import pytest

from sanitongo import MongoSanitizer, SanitizerConfig
from sanitongo.exceptions import (
    SchemaViolationError,
    ValidationError,
)


class TestMongoSanitizer:
    """Test cases for the main MongoSanitizer class."""

    def test_sanitize_valid_query(
        self, strict_sanitizer: MongoSanitizer, valid_query: dict[str, Any]
    ) -> None:
        """Test sanitization of a valid query."""
        report = strict_sanitizer.sanitize(valid_query)

        assert report.success is True
        assert report.error is None
        assert report.sanitized_query is not None
        assert "Type Validation" in report.layers_processed
        assert "Schema Enforcement" in report.layers_processed

    def test_sanitize_dangerous_query_strict_mode(
        self, strict_sanitizer: MongoSanitizer, dangerous_query: dict[str, Any]
    ) -> None:
        """Test sanitization of dangerous query in strict mode."""
        # In strict mode with schema validation, unknown fields cause ValidationError
        with pytest.raises(ValidationError):
            strict_sanitizer.sanitize(dangerous_query)

    def test_sanitize_dangerous_query_lenient_mode(
        self, lenient_sanitizer: MongoSanitizer, dangerous_query: dict[str, Any]
    ) -> None:
        """Test sanitization of dangerous query in lenient mode."""
        report = lenient_sanitizer.sanitize(dangerous_query)

        assert report.success is True
        assert len(report.removed_items) > 0
        assert len(report.warnings) > 0
        assert "$where" not in report.sanitized_query

    def test_sanitize_invalid_schema_query(
        self, strict_sanitizer: MongoSanitizer, invalid_schema_query: dict[str, Any]
    ) -> None:
        """Test sanitization of query that violates schema."""
        with pytest.raises((ValidationError, SchemaViolationError)):
            strict_sanitizer.sanitize(invalid_schema_query)

    def test_sanitize_complex_query(
        self, strict_sanitizer: MongoSanitizer, complex_query: dict[str, Any]
    ) -> None:
        """Test sanitization of overly complex query."""
        # Complex query has unknown fields, so schema validation fails first
        with pytest.raises(ValidationError):
            strict_sanitizer.sanitize(complex_query)

    def test_sanitize_invalid_type(self, strict_sanitizer: MongoSanitizer) -> None:
        """Test sanitization of invalid input type."""
        with pytest.raises(ValidationError):
            strict_sanitizer.sanitize("not_a_dict")

    def test_sanitize_query_convenience_method(
        self, strict_sanitizer: MongoSanitizer, valid_query: dict[str, Any]
    ) -> None:
        """Test the convenience sanitize_query method."""
        sanitized = strict_sanitizer.sanitize_query(valid_query)
        assert isinstance(sanitized, dict)
        assert sanitized is not None

    def test_is_query_safe(
        self, strict_sanitizer: MongoSanitizer, valid_query: dict[str, Any]
    ) -> None:
        """Test the is_query_safe method."""
        assert strict_sanitizer.is_query_safe(valid_query) is True
        assert strict_sanitizer.is_query_safe({"$where": "evil"}) is False

    def test_update_config(self, strict_sanitizer: MongoSanitizer) -> None:
        """Test updating sanitizer configuration."""
        original_depth = strict_sanitizer.config.max_depth
        strict_sanitizer.update_config(max_depth=20)
        assert strict_sanitizer.config.max_depth == 20
        assert strict_sanitizer.config.max_depth != original_depth

    def test_get_config(self, strict_sanitizer: MongoSanitizer) -> None:
        """Test getting sanitizer configuration."""
        config = strict_sanitizer.get_config()
        assert isinstance(config, SanitizerConfig)
        assert config.strict_types is True

    def test_sanitization_report_methods(
        self, lenient_sanitizer: MongoSanitizer, dangerous_query: dict[str, Any]
    ) -> None:
        """Test sanitization report helper methods."""
        report = lenient_sanitizer.sanitize(dangerous_query)

        assert report.has_warnings() is True
        assert report.has_modifications() is True
        assert isinstance(report.get_summary(), str)

    def test_empty_query(self, strict_sanitizer: MongoSanitizer) -> None:
        """Test sanitization of empty query."""
        # Empty query fails schema validation because 'name' is required
        with pytest.raises(ValidationError):
            strict_sanitizer.sanitize({})

    def test_nested_dangerous_operators(
        self, lenient_sanitizer: MongoSanitizer
    ) -> None:
        """Test removal of nested dangerous operators."""
        query = {"user": {"profile": {"$where": "function() { return true; }"}}}

        report = lenient_sanitizer.sanitize(query)
        assert report.success is True
        assert "$where" not in str(report.sanitized_query)

    def test_performance_metrics(
        self, strict_sanitizer: MongoSanitizer, valid_query: dict[str, Any]
    ) -> None:
        """Test that performance metrics are collected."""
        report = strict_sanitizer.sanitize(valid_query)

        assert "processing_time_ms" in report.performance_metrics
        assert "layers_processed" in report.performance_metrics
        assert report.performance_metrics["processing_time_ms"] >= 0

    def test_logging_disabled_in_tests(self, strict_sanitizer: MongoSanitizer) -> None:
        """Test that logging is disabled in test configuration."""
        assert strict_sanitizer.config.enable_logging is False


class TestSanitizerConfig:
    """Test cases for SanitizerConfig class."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = SanitizerConfig()

        assert config.strict_types is True
        assert config.max_depth == 10
        assert config.max_keys == 100
        assert config.enable_logging is True

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = SanitizerConfig(
            strict_types=False,
            max_depth=20,
            enable_logging=False,
        )

        assert config.strict_types is False
        assert config.max_depth == 20
        assert config.enable_logging is False

    def test_config_validation(self) -> None:
        """Test configuration validation."""
        # This should work fine
        config = SanitizerConfig(max_depth=5, max_keys=50)
        assert config.max_depth == 5
        assert config.max_keys == 50
