"""
Integration tests for MongoDB sanitization.

These tests require a running MongoDB instance and test the sanitizer
with actual database operations.
"""

import os
from typing import Any

import pytest

from sanitongo import create_sanitizer
from sanitongo.exceptions import ComplexityError, SecurityError, ValidationError

pytest_plugins = []

try:
    from pymongo import MongoClient

    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


@pytest.mark.integration
@pytest.mark.skipif(not PYMONGO_AVAILABLE, reason="pymongo not available")
class TestMongoDBIntegration:
    """Integration tests with actual MongoDB."""

    @pytest.fixture(scope="class")
    def mongodb_client(self):
        """Create MongoDB client for testing."""
        mongodb_uri = os.getenv(
            "MONGODB_URI",
            "mongodb://admin:password@localhost:27017/testdb?authSource=admin",
        )

        try:
            client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
            # Test connection
            client.admin.command("ping")
            yield client
        except Exception as e:
            pytest.skip(f"MongoDB not available: {e}")
        finally:
            if "client" in locals():
                client.close()

    @pytest.fixture(scope="function")
    def test_collection(self, mongodb_client):
        """Create a test collection for each test."""
        db = mongodb_client.testdb
        collection = db.test_collection

        # Clean up before test
        collection.drop()

        # Insert some test data
        test_data = [
            {"name": "Alice", "age": 30, "role": "admin"},
            {"name": "Bob", "age": 25, "role": "user"},
            {"name": "Charlie", "age": 35, "role": "user"},
        ]
        collection.insert_many(test_data)

        yield collection

        # Clean up after test
        collection.drop()

    def test_sanitizer_with_mongodb_connection(self, mongodb_client) -> None:
        """Test that sanitizer works with MongoDB connection."""
        sanitizer = create_sanitizer(strict_mode=True)

        # Test a safe query
        safe_query = {"name": "Alice"}
        result = sanitizer.sanitize_query(safe_query)
        assert result == safe_query

        # Test a dangerous query
        dangerous_query = {"$where": "function() { return true; }"}
        with pytest.raises(SecurityError):
            sanitizer.sanitize_query(dangerous_query)

    def test_sanitized_query_execution(self, test_collection):
        """Test executing sanitized queries against MongoDB."""
        sanitizer = create_sanitizer(strict_mode=False)  # Lenient mode

        # Test query that should work
        query = {"age": {"$gte": 25}}
        sanitized = sanitizer.sanitize_query(query)

        # Execute the sanitized query
        results = list(test_collection.find(sanitized))
        assert len(results) >= 2  # Should find Alice (30) and Charlie (35)

        # Verify all results meet the criteria
        for doc in results:
            assert doc["age"] >= 25

    def test_dangerous_query_protection(self, test_collection):
        """Test that dangerous queries are blocked."""
        sanitizer = create_sanitizer(strict_mode=True)

        # This should be blocked
        dangerous_queries = [
            {"$where": "function() { return true; }"},
            {"name": {"$regex": ".*", "$options": "e"}},  # Dangerous regex
        ]

        for dangerous_query in dangerous_queries:
            with pytest.raises(SecurityError):
                sanitizer.sanitize_query(dangerous_query)

    def test_query_complexity_limits(self, test_collection) -> None:
        """Test query complexity limits work with MongoDB."""
        sanitizer = create_sanitizer(strict_mode=True, max_depth=2)

        # Create a deeply nested query (should be blocked)
        deep_query: dict[str, Any] = {
            "level1": {"level2": {"level3": {"value": "deep"}}}
        }

        with pytest.raises(ComplexityError):
            sanitizer.sanitize_query(deep_query)

    def test_field_filtering_integration(self, test_collection) -> None:
        """Test field filtering with actual MongoDB queries."""
        # Define allowed fields schema
        schema = {
            "name": {"type": "string", "required": True},
            "age": {"type": "integer"},
            "role": {"type": "string", "allowed_values": ["admin", "user"]},
        }

        sanitizer = create_sanitizer(schema=schema, strict_mode=True)

        # This should work - all fields are allowed
        valid_query = {"name": "Alice", "age": {"$gte": 25}}
        sanitized = sanitizer.sanitize_query(valid_query)
        results = list(test_collection.find(sanitized))
        assert len(results) == 1
        assert results[0]["name"] == "Alice"

        # This should fail - unknown field
        with pytest.raises(ValidationError):
            invalid_query = {"unknown_field": "value"}
            sanitizer.sanitize_query(invalid_query)


@pytest.mark.integration
def test_mongodb_availability() -> None:
    """Basic test to verify MongoDB is available for integration tests."""
    if not PYMONGO_AVAILABLE:
        pytest.skip("pymongo not available")

    mongodb_uri = os.getenv(
        "MONGODB_URI",
        "mongodb://admin:password@localhost:27017/testdb?authSource=admin",
    )

    try:
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        client.close()
        # If we reach here, MongoDB is available
        assert True
    except Exception as e:
        pytest.fail(f"MongoDB not available for integration tests: {e}")
