"""
Sanitongo - Modern MongoDB Query Sanitizer with Layered Security Protection.

A comprehensive security library for sanitizing MongoDB queries with multiple
layers of protection against NoSQL injection attacks and malicious queries.
"""

__version__ = "0.1.0"
__author__ = "Krystian Safjan"
__email__ = "krystian.safjan@example.com"

from .exceptions import (
    ComplexityError,
    SanitizerError,
    SchemaViolationError,
    SecurityError,
    ValidationError,
)
from .layers import (
    ComplexityLimiter,
    OperatorFilter,
    PatternValidator,
    SchemaEnforcer,
    TypeValidator,
)
from .sanitizer import MongoSanitizer, SanitizationReport, SanitizerConfig
from .schema import FieldType, SchemaValidator

__all__ = [
    # Main classes
    "MongoSanitizer",
    "SanitizerConfig",
    "SanitizationReport",
    # Exceptions
    "SanitizerError",
    "ValidationError",
    "SchemaViolationError",
    "ComplexityError",
    "SecurityError",
    # Schema
    "SchemaValidator",
    "FieldType",
    # Layers
    "TypeValidator",
    "SchemaEnforcer",
    "OperatorFilter",
    "PatternValidator",
    "ComplexityLimiter",
]
