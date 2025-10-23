"""
Layered protection system for MongoDB query sanitization.

This module implements the five-layer protection approach:
1. Type Validation - Ensure inputs are valid types
2. Schema Enforcement - Validate against allowed fields and types
3. Operator Filtering - Remove/validate MongoDB operators
4. Pattern Validation - Check for dangerous patterns in values
5. Complexity Limiting - Prevent DoS through query complexity
"""

from __future__ import annotations

import re
from re import Pattern
from typing import Any

from .exceptions import ComplexityError, PatternError, SecurityError, ValidationError
from .schema import SchemaValidator


class LayerResult:
    """Result of a single layer's processing."""

    def __init__(
        self,
        success: bool,
        modified_query: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        removed_items: dict[str, Any] | None = None,
    ) -> None:
        """Initialize layer result."""
        self.success = success
        self.modified_query = modified_query
        self.warnings = warnings or []
        self.removed_items = removed_items or {}


class TypeValidator:
    """Layer 1: Validates input types and basic structure."""

    def __init__(self, strict_mode: bool = True) -> None:
        """Initialize type validator."""
        self.strict_mode = strict_mode

    def validate(self, query: Any) -> LayerResult:
        """Validate query types and structure."""
        warnings = []

        # Basic type check
        if not isinstance(query, dict):
            if self.strict_mode:
                raise ValidationError(
                    f"Query must be a dictionary, got {type(query).__name__}"
                )
            return LayerResult(success=False)

        # Check for empty query
        if not query:
            warnings.append("Empty query detected")

        # Validate nested structure
        try:
            self._validate_nested_types(query, "")
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Type validation failed: {e}") from e

        return LayerResult(success=True, modified_query=query, warnings=warnings)

    def _validate_nested_types(self, obj: Any, path: str) -> None:
        """Recursively validate nested object types."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if not isinstance(key, str):
                    raise ValidationError(
                        f"Dictionary key at '{path}' must be string, got {type(key).__name__}"
                    )
                self._validate_nested_types(value, f"{path}.{key}" if path else key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._validate_nested_types(item, f"{path}[{i}]")
        elif obj is not None and not isinstance(obj, (str, int, float, bool)):
            # Allow None and basic types, but warn about complex objects
            raise ValidationError(f"Unsupported type at '{path}': {type(obj).__name__}")


class SchemaEnforcer:
    """Layer 2: Enforces field schema and validation rules."""

    def __init__(
        self,
        schema_validator: SchemaValidator | None = None,
        fail_on_violation: bool = True,
    ) -> None:
        """Initialize schema enforcer."""
        self.schema_validator = schema_validator
        self.fail_on_violation = fail_on_violation

    def validate(self, query: dict[str, Any]) -> LayerResult:
        """Enforce schema rules on the query."""
        if not self.schema_validator:
            # No schema defined, allow all fields
            return LayerResult(
                success=True, modified_query=query, warnings=["No schema defined"]
            )

        try:
            self.schema_validator.validate_query(query)
            return LayerResult(success=True, modified_query=query)
        except Exception as e:
            if self.fail_on_violation:
                raise ValidationError(f"Schema validation failed: {e}") from e
            else:
                # In lenient mode, return success with warnings
                warning_msg = f"Schema validation warning: {e}"
                return LayerResult(
                    success=True, modified_query=query, warnings=[warning_msg]
                )


class OperatorFilter:
    """Layer 3: Filters and validates MongoDB operators."""

    def __init__(
        self,
        allowed_operators: set[str] | None = None,
        dangerous_operators: set[str] | None = None,
        strict_mode: bool = True,
    ) -> None:
        """Initialize operator filter."""
        self.allowed_operators = allowed_operators or self._get_safe_operators()
        self.dangerous_operators = (
            dangerous_operators or self._get_dangerous_operators()
        )
        self.strict_mode = strict_mode

    def validate(self, query: dict[str, Any]) -> LayerResult:
        """Filter MongoDB operators from the query."""
        modified_query = {}
        removed_items = {}
        warnings = []

        self._process_dict(query, modified_query, removed_items, warnings, "")

        return LayerResult(
            success=True,
            modified_query=modified_query,
            warnings=warnings,
            removed_items=removed_items,
        )

    def _process_dict(
        self,
        source: dict[str, Any],
        target: dict[str, Any],
        removed: dict[str, Any],
        warnings: list[str],
        path: str,
    ) -> None:
        """Process dictionary removing dangerous operators."""
        for key, value in source.items():
            current_path = f"{path}.{key}" if path else key

            if key.startswith("$"):
                if key in self.dangerous_operators:
                    removed[current_path] = value
                    warnings.append(f"Removed dangerous operator: {key}")
                    if self.strict_mode:
                        raise SecurityError(
                            f"Dangerous operator detected: {key}",
                            threat_type="dangerous_operator",
                            detected_patterns=[key],
                        )
                    continue
                elif key not in self.allowed_operators:
                    removed[current_path] = value
                    warnings.append(f"Removed unknown operator: {key}")
                    continue

            if isinstance(value, dict):
                target[key] = {}
                self._process_dict(value, target[key], removed, warnings, current_path)
            elif isinstance(value, list):
                target[key] = []
                self._process_list(value, target[key], removed, warnings, current_path)
            else:
                target[key] = value

    def _process_list(
        self,
        source: list[Any],
        target: list[Any],
        removed: dict[str, Any],
        warnings: list[str],
        path: str,
    ) -> None:
        """Process list items recursively."""
        for i, item in enumerate(source):
            item_path = f"{path}[{i}]"
            if isinstance(item, dict):
                processed_item = {}
                self._process_dict(item, processed_item, removed, warnings, item_path)
                target.append(processed_item)
            elif isinstance(item, list):
                processed_list = []
                self._process_list(item, processed_list, removed, warnings, item_path)
                target.append(processed_list)
            else:
                target.append(item)

    def _get_safe_operators(self) -> set[str]:
        """Get set of safe MongoDB operators."""
        return {
            # Comparison
            "$eq",
            "$ne",
            "$gt",
            "$gte",
            "$lt",
            "$lte",
            "$in",
            "$nin",
            # Logical
            "$and",
            "$or",
            "$not",
            "$nor",
            # Element
            "$exists",
            "$type",
            # Array (limited set)
            "$all",
            "$size",
            # Text search (controlled)
            "$text",
        }

    def _get_dangerous_operators(self) -> set[str]:
        """Get set of dangerous MongoDB operators."""
        return {
            # JavaScript execution
            "$where",
            "$function",
            # Regex with potential for ReDoS
            "$regex",
            # Aggregation operators in wrong context
            "$expr",
            "$jsonSchema",
            # Modification operators
            "$set",
            "$unset",
            "$inc",
            "$push",
            "$pull",
            # Advanced array operators
            "$elemMatch",
            "$slice",
            "$position",
        }


class PatternValidator:
    """Layer 4: Validates patterns in string values."""

    def __init__(
        self,
        custom_patterns: dict[str, Pattern[str]] | None = None,
        fail_on_dangerous_patterns: bool = True,
    ) -> None:
        """Initialize pattern validator."""
        self.dangerous_patterns = self._get_dangerous_patterns()
        if custom_patterns:
            self.dangerous_patterns.update(custom_patterns)
        self.fail_on_dangerous_patterns = fail_on_dangerous_patterns

    def validate(self, query: dict[str, Any]) -> LayerResult:
        """Validate string patterns in the query."""
        warnings = []
        self._check_patterns(query, warnings, "")
        return LayerResult(success=True, modified_query=query, warnings=warnings)

    def _check_patterns(self, obj: Any, warnings: list[str], path: str) -> None:
        """Recursively check for dangerous patterns."""
        if isinstance(obj, str):
            for pattern_name, pattern in self.dangerous_patterns.items():
                if pattern.search(obj):
                    warning_msg = (
                        f"Dangerous pattern '{pattern_name}' detected at '{path}'"
                    )
                    warnings.append(warning_msg)
                    if self.fail_on_dangerous_patterns:
                        raise PatternError(
                            f"Dangerous pattern detected: {pattern_name}",
                            pattern_type=pattern_name,
                            field_path=path,
                            pattern_value=obj,
                        )
        elif isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                # Check the key itself for dangerous patterns, but skip MongoDB operators
                if not key.startswith("$"):
                    self._check_patterns(key, warnings, f"{current_path}#key")
                # Check the value
                self._check_patterns(value, warnings, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._check_patterns(item, warnings, f"{path}[{i}]")

    def _get_dangerous_patterns(self) -> dict[str, Pattern[str]]:
        """Get dangerous regex patterns to detect."""
        return {
            "javascript": re.compile(
                r"(?i)(function\s*\(|eval\s*\(|setTimeout|setInterval)", re.IGNORECASE
            ),
            "script_tags": re.compile(
                r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL
            ),
            "sql_injection": re.compile(
                r"(?i)(union\s+select|drop\s+table|insert\s+into)", re.IGNORECASE
            ),
            "command_injection": re.compile(r"[;&|`$()]", re.MULTILINE),
            "prototype_pollution": re.compile(
                r"__proto__|constructor|prototype", re.IGNORECASE
            ),
            "redos_suspicious": re.compile(
                r"(\+|\*|\{[\d,]*\})\+|\*\*|\+\+", re.MULTILINE
            ),
        }


class ComplexityLimiter:
    """Layer 5: Limits query complexity to prevent DoS attacks."""

    def __init__(
        self,
        max_depth: int = 10,
        max_keys: int = 100,
        max_array_length: int = 1000,
        max_string_length: int = 10000,
    ) -> None:
        """Initialize complexity limiter."""
        self.max_depth = max_depth
        self.max_keys = max_keys
        self.max_array_length = max_array_length
        self.max_string_length = max_string_length

    def validate(self, query: dict[str, Any]) -> LayerResult:
        """Check query complexity limits."""
        warnings = []

        # Check depth
        depth = self._calculate_depth(query)
        if depth > self.max_depth:
            raise ComplexityError(
                f"Query depth exceeds limit: {depth} > {self.max_depth}",
                limit_type="depth",
                current_value=depth,
                max_allowed=self.max_depth,
            )

        # Check key count
        key_count = self._count_keys(query)
        if key_count > self.max_keys:
            raise ComplexityError(
                f"Query key count exceeds limit: {key_count} > {self.max_keys}",
                limit_type="keys",
                current_value=key_count,
                max_allowed=self.max_keys,
            )

        # Check arrays and strings
        self._check_arrays_and_strings(query, "")

        return LayerResult(success=True, modified_query=query, warnings=warnings)

    def _calculate_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth."""
        if not isinstance(obj, (dict, list)):
            return current_depth

        max_child_depth = current_depth
        if isinstance(obj, dict):
            for value in obj.values():
                child_depth = self._calculate_depth(value, current_depth + 1)
                max_child_depth = max(max_child_depth, child_depth)
        elif isinstance(obj, list):
            for item in obj:
                child_depth = self._calculate_depth(item, current_depth + 1)
                max_child_depth = max(max_child_depth, child_depth)

        return max_child_depth

    def _count_keys(self, obj: Any) -> int:
        """Count total number of dictionary keys."""
        if isinstance(obj, dict):
            count = len(obj)
            for value in obj.values():
                count += self._count_keys(value)
            return count
        elif isinstance(obj, list):
            count = 0
            for item in obj:
                count += self._count_keys(item)
            return count
        return 0

    def _check_arrays_and_strings(self, obj: Any, path: str) -> None:
        """Check array lengths and string lengths."""
        if isinstance(obj, list):
            if len(obj) > self.max_array_length:
                raise ComplexityError(
                    f"Array at '{path}' exceeds length limit: {len(obj)} > {self.max_array_length}",
                    limit_type="array_length",
                    current_value=len(obj),
                    max_allowed=self.max_array_length,
                )
            for i, item in enumerate(obj):
                self._check_arrays_and_strings(item, f"{path}[{i}]")
        elif isinstance(obj, str):
            if len(obj) > self.max_string_length:
                raise ComplexityError(
                    f"String at '{path}' exceeds length limit: {len(obj)} > {self.max_string_length}",
                    limit_type="string_length",
                    current_value=len(obj),
                    max_allowed=self.max_string_length,
                )
        elif isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                self._check_arrays_and_strings(value, current_path)
