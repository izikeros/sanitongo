"""Test configuration and fixtures for the Sanitongo test suite."""

from typing import Any

import pytest

from sanitongo import MongoSanitizer, SanitizerConfig
from sanitongo.schema import FieldRule, FieldType, SchemaValidator


@pytest.fixture
def basic_schema() -> dict[str, FieldRule]:
    """Create a basic schema for testing."""
    return {
        "_id": FieldRule(FieldType.OBJECT_ID, description="Document ID"),
        "name": FieldRule(
            FieldType.STRING,
            required=True,
            min_length=1,
            max_length=100,
            description="User name",
        ),
        "email": FieldRule(
            FieldType.STRING,
            pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            description="Email address",
        ),
        "age": FieldRule(FieldType.INTEGER, description="Age in years"),
        "active": FieldRule(FieldType.BOOLEAN, description="Active status"),
        "tags": FieldRule(
            FieldType.ARRAY,
            array_item_type=FieldType.STRING,
            description="User tags",
        ),
    }


@pytest.fixture
def schema_validator(basic_schema: dict[str, FieldRule]) -> SchemaValidator:
    """Create a schema validator with basic schema."""
    return SchemaValidator(basic_schema)


@pytest.fixture
def strict_config(schema_validator: SchemaValidator) -> SanitizerConfig:
    """Create a strict sanitizer configuration."""
    return SanitizerConfig(
        schema_validator=schema_validator,
        strict_types=True,
        strict_operators=True,
        enable_pattern_validation=True,
        fail_on_schema_violation=True,
        fail_on_dangerous_operators=True,
        fail_on_dangerous_patterns=True,
        fail_on_complexity_exceeded=True,
        enable_logging=False,  # Disable logging for tests
    )


@pytest.fixture
def lenient_config(schema_validator: SchemaValidator) -> SanitizerConfig:
    """Create a lenient sanitizer configuration."""
    return SanitizerConfig(
        schema_validator=schema_validator,
        strict_types=False,
        strict_operators=False,
        enable_pattern_validation=True,
        fail_on_schema_violation=False,
        fail_on_dangerous_operators=False,
        fail_on_dangerous_patterns=False,
        fail_on_complexity_exceeded=False,
        enable_logging=False,  # Disable logging for tests
    )


@pytest.fixture
def strict_sanitizer(strict_config: SanitizerConfig) -> MongoSanitizer:
    """Create a strict sanitizer instance."""
    return MongoSanitizer(strict_config)


@pytest.fixture
def lenient_sanitizer(lenient_config: SanitizerConfig) -> MongoSanitizer:
    """Create a lenient sanitizer instance."""
    return MongoSanitizer(lenient_config)


@pytest.fixture
def valid_query() -> dict[str, Any]:
    """Create a valid MongoDB query for testing."""
    return {
        "name": "John Doe",
        "email": "john@example.com",
        "age": {"$gte": 18},
        "active": True,
        "tags": {"$in": ["user", "premium"]},
    }


@pytest.fixture
def dangerous_query() -> dict[str, Any]:
    """Create a dangerous MongoDB query for testing."""
    return {
        "name": "John Doe",
        "$where": "function() { return true; }",  # JavaScript execution
        "email": {"$regex": ".*"},  # Potentially dangerous regex
        "payload": "<script>alert('xss')</script>",  # Script injection
        "nested": {
            "deep": {
                "very": {
                    "deeply": {"nested": {"value": "test"}}  # Exceeds depth limits
                }
            }
        },
    }


@pytest.fixture
def complex_query() -> dict[str, Any]:
    """Create a complex query that exceeds limits."""
    # Create a query with many keys
    query = {}
    for i in range(150):  # Exceeds max_keys limit of 100
        query[f"field_{i}"] = f"value_{i}"

    # Add deeply nested structure
    nested = query
    for i in range(15):  # Exceeds max_depth limit of 10
        nested["nested"] = {}
        nested = nested["nested"]
    nested["final"] = "value"

    return query


@pytest.fixture
def invalid_schema_query() -> dict[str, Any]:
    """Create a query that violates schema rules."""
    return {
        "name": "",  # Too short (min_length=1)
        "email": "invalid-email",  # Doesn't match pattern
        "age": "not_a_number",  # Wrong type
        "unknown_field": "not_allowed",  # Not in schema
        "tags": "should_be_array",  # Wrong type
    }


# Sample test data for various scenarios
SAFE_QUERIES = [
    {"name": "John", "age": 25},
    {"active": True, "tags": ["user"]},
    {"_id": "507f1f77bcf86cd799439011"},  # Valid ObjectId
    {"email": "test@example.com", "active": {"$ne": False}},
]

DANGEROUS_QUERIES = [
    {"$where": "function() { return true; }"},
    {"name": {"$regex": "(a+)+$"}},  # ReDoS potential
    {"payload": "eval('malicious code')"},
    {"script": "<script>alert(1)</script>"},
    {"command": "rm -rf /"},
]

COMPLEX_QUERIES = [
    # Deep nesting
    {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": "deep"}}}}}}}}}}},
    # Many keys - create separately to avoid comprehension syntax issues
    dict((f"key_{i}", f"value_{i}") for i in range(200)),
    # Large arrays
    {"large_array": list(range(2000))},
    # Long strings
    {"long_string": "x" * 20000},
]
