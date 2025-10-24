"""
Sanitongo - Modern MongoDB Query Sanitizer with Layered Security Protection.

A comprehensive security library for sanitizing MongoDB queries with multiple
layers of protection against NoSQL injection attacks and malicious queries.
"""

__version__ = "0.1.1"
__author__ = "Krystian Safjan"
__email__ = "ksafjan@gmail.com"

from .exceptions import (
    ComplexityError,
    PatternError,
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
from .sanitizer import (
    MongoSanitizer,
    SanitizationReport,
    SanitizerConfig,
    create_sanitizer,
)
from .schema import FieldType, SchemaValidator

__all__ = [
    # Exceptions
    "ComplexityError",
    # Layers
    "ComplexityLimiter",
    # Schema
    "FieldType",
    # Main classes
    "MongoSanitizer",
    "OperatorFilter",
    "PatternError",
    "PatternValidator",
    "SanitizationReport",
    "SanitizerConfig",
    "SanitizerError",
    "SchemaEnforcer",
    "SchemaValidator",
    "SchemaViolationError",
    "SecurityError",
    "TypeValidator",
    "ValidationError",
    # Factory functions
    "create_sanitizer",
]
