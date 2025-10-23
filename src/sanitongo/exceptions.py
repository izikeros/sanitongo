"""
Custom exceptions for the Sanitongo library.

This module defines all custom exceptions used throughout the MongoDB query
sanitization process, providing specific error types for different failure modes.
"""

from __future__ import annotations

from typing import Any


class SanitizerError(Exception):
    """Base exception for all sanitizer-related errors."""

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        """Initialize the exception with message and optional context."""
        super().__init__(message)
        self.context = context or {}


class ValidationError(SanitizerError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field_path: str | None = None,
        invalid_value: Any | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize validation error with field information."""
        super().__init__(message, context)
        self.field_path = field_path
        self.invalid_value = invalid_value


class SchemaViolationError(SanitizerError):
    """Raised when query violates the defined schema."""

    def __init__(
        self,
        message: str,
        field_path: str,
        schema_rule: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize schema violation error."""
        super().__init__(message, context)
        self.field_path = field_path
        self.schema_rule = schema_rule


class ComplexityError(SanitizerError):
    """Raised when query exceeds complexity limits."""

    def __init__(
        self,
        message: str,
        limit_type: str,
        current_value: int,
        max_allowed: int,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize complexity error with limit information."""
        super().__init__(message, context)
        self.limit_type = limit_type
        self.current_value = current_value
        self.max_allowed = max_allowed


class SecurityError(SanitizerError):
    """Raised when potentially malicious content is detected."""

    def __init__(
        self,
        message: str,
        threat_type: str,
        detected_patterns: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize security error with threat information."""
        super().__init__(message, context)
        self.threat_type = threat_type
        self.detected_patterns = detected_patterns or []


class ConfigurationError(SanitizerError):
    """Raised when sanitizer configuration is invalid."""


class PatternError(SecurityError):
    """Raised when dangerous patterns are detected in query values."""

    def __init__(
        self,
        message: str,
        pattern_type: str,
        field_path: str | None = None,
        pattern_value: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize pattern error."""
        super().__init__(
            message, pattern_type, [pattern_value] if pattern_value else [], context
        )
        self.pattern_type = pattern_type
        self.field_path = field_path
        self.pattern_value = pattern_value
