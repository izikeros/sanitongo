"""
Schema validation module for MongoDB query sanitization.

This module provides schema-based validation to ensure queries only contain
allowed fields and follow defined data types and constraints.
"""

import re
from enum import Enum
from re import Pattern
from typing import Any

from .exceptions import SchemaViolationError, ValidationError


class FieldType(Enum):
    """Supported field types for schema validation."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    OBJECT_ID = "objectid"
    DATETIME = "datetime"
    ARRAY = "array"
    OBJECT = "object"
    ANY = "any"


class FieldRule:
    """Defines validation rules for a single field."""

    def __init__(
        self,
        field_type: FieldType,
        required: bool = False,
        allowed_values: list[Any] | None = None,
        min_length: int | None = None,
        max_length: int | None = None,
        pattern: str | Pattern[str] | None = None,
        nested_schema: dict[str, "FieldRule"] | None = None,
        array_item_type: FieldType | None = None,
        description: str | None = None,
    ) -> None:
        """Initialize field rule with validation constraints."""
        self.field_type = field_type
        self.required = required
        self.allowed_values = allowed_values
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = re.compile(pattern) if isinstance(pattern, str) else pattern
        self.nested_schema = nested_schema or {}
        self.array_item_type = array_item_type
        self.description = description

    def validate_value(self, value: Any, field_path: str) -> None:
        """Validate a value against this field rule."""
        if value is None and not self.required:
            return

        if value is None and self.required:
            raise ValidationError(f"Required field '{field_path}' is missing")

        # Type validation
        if not self._check_type(value):
            raise ValidationError(
                f"Field '{field_path}' has invalid type. "
                f"Expected {self.field_type.value}, got {type(value).__name__}"
            )

        # Value constraints
        if self.allowed_values and value not in self.allowed_values:
            raise ValidationError(
                f"Field '{field_path}' has invalid value. "
                f"Must be one of: {self.allowed_values}"
            )

        # String-specific validations
        if self.field_type == FieldType.STRING and isinstance(value, str):
            if self.min_length and len(value) < self.min_length:
                raise ValidationError(
                    f"Field '{field_path}' is too short. "
                    f"Minimum length: {self.min_length}"
                )
            if self.max_length and len(value) > self.max_length:
                raise ValidationError(
                    f"Field '{field_path}' is too long. "
                    f"Maximum length: {self.max_length}"
                )
            if self.pattern and not self.pattern.match(value):
                raise ValidationError(
                    f"Field '{field_path}' does not match required pattern"
                )

        # Array validation
        if self.field_type == FieldType.ARRAY and isinstance(value, list):
            if self.array_item_type:
                for i, item in enumerate(value):
                    item_rule = FieldRule(self.array_item_type)
                    item_rule.validate_value(item, f"{field_path}[{i}]")

        # Object validation
        if self.field_type == FieldType.OBJECT and isinstance(value, dict):
            if self.nested_schema:
                schema_validator = SchemaValidator(self.nested_schema)
                schema_validator.validate_query(value, field_path)

    def _check_type(self, value: Any) -> bool:
        """Check if value matches the expected type."""
        if self.field_type == FieldType.ANY:
            return True

        type_mapping = {
            FieldType.STRING: str,
            FieldType.INTEGER: int,
            FieldType.FLOAT: (int, float),
            FieldType.BOOLEAN: bool,
            FieldType.ARRAY: list,
            FieldType.OBJECT: dict,
        }

        expected_type = type_mapping.get(self.field_type)
        if expected_type:
            return isinstance(value, expected_type)

        # Special cases
        if self.field_type == FieldType.OBJECT_ID:
            return self._is_valid_object_id(value)
        if self.field_type == FieldType.DATETIME:
            return self._is_valid_datetime(value)

        return False

    def _is_valid_object_id(self, value: Any) -> bool:
        """Check if value is a valid MongoDB ObjectId."""
        if not isinstance(value, str):
            return False
        # MongoDB ObjectId is 24 character hex string
        return len(value) == 24 and all(c in "0123456789abcdefABCDEF" for c in value)

    def _is_valid_datetime(self, value: Any) -> bool:
        """Check if value is a valid datetime representation."""
        # Accept strings in ISO format or datetime objects
        if isinstance(value, str):
            # Simple ISO format check
            iso_pattern = re.compile(
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$"
            )
            return bool(iso_pattern.match(value))
        return hasattr(value, "year")  # Duck typing for datetime-like objects


class SchemaValidator:
    """Validates MongoDB queries against a predefined schema."""

    def __init__(self, schema: dict[str, FieldRule]) -> None:
        """Initialize validator with field schema."""
        self.schema = schema
        self._allowed_fields = set(schema.keys())

    def validate_query(self, query: dict[str, Any], path_prefix: str = "") -> None:
        """Validate a query dictionary against the schema."""
        if not isinstance(query, dict):
            raise ValidationError("Query must be a dictionary")

        # Check for unknown fields
        query_fields = set(query.keys())
        unknown_fields = query_fields - self._allowed_fields

        if unknown_fields:
            raise SchemaViolationError(
                f"Unknown fields in query: {sorted(unknown_fields)}",
                field_path=path_prefix,
                schema_rule="allowed_fields",
            )

        # Validate each field
        for field_name, field_rule in self.schema.items():
            field_path = f"{path_prefix}.{field_name}" if path_prefix else field_name
            value = query.get(field_name)

            try:
                field_rule.validate_value(value, field_path)
            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(
                    f"Validation failed for field '{field_path}': {e}"
                ) from e

    def get_allowed_fields(self) -> set[str]:
        """Get the set of allowed field names."""
        return self._allowed_fields.copy()

    def is_field_allowed(self, field_name: str) -> bool:
        """Check if a field name is allowed by the schema."""
        return field_name in self._allowed_fields

    def get_field_rule(self, field_name: str) -> FieldRule | None:
        """Get the validation rule for a specific field."""
        return self.schema.get(field_name)


def create_basic_schema() -> dict[str, FieldRule]:
    """Create a basic schema for common MongoDB document fields."""
    return {
        "_id": FieldRule(FieldType.OBJECT_ID, description="Document ID"),
        "name": FieldRule(
            FieldType.STRING,
            min_length=1,
            max_length=100,
            description="Document name",
        ),
        "email": FieldRule(
            FieldType.STRING,
            pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            description="Email address",
        ),
        "age": FieldRule(FieldType.INTEGER, description="Age in years"),
        "active": FieldRule(FieldType.BOOLEAN, description="Active status"),
        "created_at": FieldRule(FieldType.DATETIME, description="Creation timestamp"),
        "tags": FieldRule(
            FieldType.ARRAY,
            array_item_type=FieldType.STRING,
            description="Document tags",
        ),
    }
