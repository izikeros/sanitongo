#!/usr/bin/env python3
"""
Basic usage examples for the Sanitongo MongoDB query sanitizer.

This script demonstrates the fundamental features and usage patterns
of the Sanitongo library for securing MongoDB queries.
"""

from sanitongo import create_sanitizer, MongoSanitizer, SanitizerConfig
from sanitongo.exceptions import SecurityError, ValidationError
from sanitongo.schema import FieldRule, FieldType, SchemaValidator


def basic_sanitization_example():
    """Demonstrate basic query sanitization."""
    print("=== Basic Sanitization Example ===")

    # Create a sanitizer with default settings
    sanitizer = create_sanitizer(strict_mode=True)

    # Safe query
    safe_query = {"name": "John Doe", "age": {"$gte": 18}, "active": True}

    print("Safe query:", safe_query)
    result = sanitizer.sanitize_query(safe_query)
    print("Sanitized result:", result)
    print("Is safe:", sanitizer.is_query_safe(safe_query))
    print()


def dangerous_query_example():
    """Demonstrate handling of dangerous queries."""
    print("=== Dangerous Query Example ===")

    # Create sanitizer in lenient mode to see what gets removed
    sanitizer = create_sanitizer(strict_mode=False)

    dangerous_query = {
        "name": "John",
        "$where": "function() { return true; }",  # NoSQL injection
        "payload": "<script>alert('xss')</script>",  # XSS
        "command": "; rm -rf /",  # Command injection
    }

    print("Dangerous query:", dangerous_query)

    report = sanitizer.sanitize(dangerous_query)
    print("Sanitization successful:", report.success)
    print("Sanitized query:", report.sanitized_query)
    print("Removed items:", report.removed_items)
    print("Warnings:", report.warnings)
    print("Summary:", report.get_summary())
    print()


def schema_validation_example():
    """Demonstrate schema-based validation."""
    print("=== Schema Validation Example ===")

    # Define schema
    schema = {
        "_id": {"type": "objectid"},
        "name": {
            "type": "string",
            "required": True,
            "min_length": 1,
            "max_length": 100,
        },
        "email": {
            "type": "string",
            "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        },
        "age": {"type": "integer"},
        "active": {"type": "boolean"},
    }

    sanitizer = create_sanitizer(schema=schema, strict_mode=True)

    # Valid query
    valid_query = {
        "name": "Alice Smith",
        "email": "alice@example.com",
        "age": 28,
        "active": True,
    }

    print("Valid query:", valid_query)
    try:
        result = sanitizer.sanitize_query(valid_query)
        print("✅ Schema validation passed:", result)
    except Exception as e:
        print("❌ Schema validation failed:", e)

    # Invalid query
    invalid_query = {
        "name": "",  # Too short
        "email": "invalid-email",  # Wrong format
        "unknown_field": "not allowed",  # Not in schema
    }

    print("\nInvalid query:", invalid_query)
    try:
        result = sanitizer.sanitize_query(invalid_query)
        print("✅ Validation passed:", result)
    except Exception as e:
        print("❌ Schema validation failed:", e)
    print()


def custom_configuration_example():
    """Demonstrate custom configuration."""
    print("=== Custom Configuration Example ===")

    # Create custom configuration
    config = SanitizerConfig(
        strict_types=True,
        strict_operators=False,  # Remove operators instead of failing
        enable_pattern_validation=True,
        max_depth=5,  # Limit nesting depth
        max_keys=20,  # Limit number of keys
        enable_logging=False,  # Disable logging for example
        custom_dangerous_patterns={"bad_word": r"badword", "suspicious": r"eval\s*\("},
    )

    sanitizer = MongoSanitizer(config)

    test_query = {
        "normal": "field",
        "$where": "dangerous operator",  # Will be removed
        "nested": {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {"too_deep": "value"}  # Might exceed depth limit
                    }
                }
            }
        },
    }

    print("Test query:", test_query)
    report = sanitizer.sanitize(test_query)
    print("Success:", report.success)
    print("Modified query:", report.sanitized_query)
    if report.removed_items:
        print("Removed items:", report.removed_items)
    print()


def performance_example():
    """Demonstrate performance monitoring."""
    print("=== Performance Example ===")

    sanitizer = create_sanitizer(strict_mode=False)

    # Simple query
    simple_query = {"name": "John", "age": 30}

    # Complex query
    complex_query = {}
    for i in range(50):
        complex_query[f"field_{i}"] = f"value_{i}"

    for query_name, query in [("Simple", simple_query), ("Complex", complex_query)]:
        print(f"{query_name} query with {len(query)} fields")
        report = sanitizer.sanitize(query)
        print(f"Processing time: {report.performance_metrics['processing_time_ms']}ms")
        print(f"Layers processed: {report.performance_metrics['layers_processed']}")
        print()


def real_world_example():
    """Demonstrate real-world usage scenario."""
    print("=== Real-World Example ===")

    # Simulate a web API that accepts MongoDB queries
    def process_user_query(user_input, sanitizer):
        """Process a user-provided query safely."""
        try:
            # Sanitize the query
            report = sanitizer.sanitize(user_input)

            if not report.success:
                return {
                    "error": "Query sanitization failed",
                    "details": str(report.error),
                }

            if report.has_security_issues():
                return {
                    "error": "Security issues detected",
                    "issues": report.security_issues,
                }

            # In a real application, you would now use the sanitized query with MongoDB
            return {
                "success": True,
                "query": report.sanitized_query,
                "warnings": report.warnings if report.warnings else None,
                "processing_time": report.performance_metrics.get("processing_time_ms"),
            }

        except Exception as e:
            return {"error": "Query processing failed", "details": str(e)}

    # Create sanitizer for web API
    api_sanitizer = create_sanitizer(
        schema={
            "name": {"type": "string", "max_length": 100},
            "email": {"type": "string"},
            "status": {"type": "string"},
            "created_at": {"type": "datetime"},
            "tags": {"type": "array"},
        },
        strict_mode=False,  # Remove dangerous parts instead of failing
    )

    # Test various user inputs
    test_inputs = [
        # Normal user search
        {"name": "John Doe", "status": "active"},
        # User trying NoSQL injection
        {"name": {"$ne": None}, "$where": "this.admin == true"},
        # User with some XSS attempt
        {"name": "John", "bio": "<script>alert('xss')</script>"},
        # User with complex but legitimate query
        {"name": "Alice", "tags": {"$in": ["premium", "verified"]}, "status": "active"},
    ]

    for i, user_input in enumerate(test_inputs, 1):
        print(f"User Query {i}: {user_input}")
        result = process_user_query(user_input, api_sanitizer)
        print(f"API Response: {result}")
        print()


if __name__ == "__main__":
    print("Sanitongo MongoDB Query Sanitizer Examples")
    print("==========================================\n")

    basic_sanitization_example()
    dangerous_query_example()
    schema_validation_example()
    custom_configuration_example()
    performance_example()
    real_world_example()

    print("Examples completed! 🎉")
    print("\nNext steps:")
    print("- Check the documentation for more advanced features")
    print("- Run the security tests: pytest tests/test_security.py")
    print("- Customize the configuration for your use case")
