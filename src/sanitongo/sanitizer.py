"""
Main MongoDB query sanitizer with layered protection.

This module provides the main sanitizer class that orchestrates all protection
layers and provides comprehensive query sanitization with detailed reporting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .exceptions import SanitizerError
from .layers import (
    ComplexityLimiter,
    LayerResult,
    OperatorFilter,
    PatternValidator,
    SchemaEnforcer,
    TypeValidator,
)
from .schema import SchemaValidator


@dataclass
class SanitizerConfig:
    """Configuration for the MongoDB sanitizer."""

    # Schema validation
    schema_validator: SchemaValidator | None = None

    # Type validation
    strict_types: bool = True

    # Operator filtering
    allowed_operators: set[str] | None = None
    dangerous_operators: set[str] | None = None
    strict_operators: bool = True

    # Pattern validation
    enable_pattern_validation: bool = True
    custom_dangerous_patterns: dict[str, str] | None = None

    # Complexity limits
    max_depth: int = 10
    max_keys: int = 100
    max_array_length: int = 1000
    max_string_length: int = 10000

    # Logging
    enable_logging: bool = True
    log_level: str = "INFO"
    log_removed_items: bool = True

    # Error handling
    fail_on_schema_violation: bool = True
    fail_on_dangerous_operators: bool = True
    fail_on_dangerous_patterns: bool = True
    fail_on_complexity_exceeded: bool = True


@dataclass
class SanitizationReport:
    """Detailed report of the sanitization process."""

    original_query: dict[str, Any]
    sanitized_query: dict[str, Any]
    success: bool
    layers_processed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    removed_items: dict[str, Any] = field(default_factory=dict)
    security_issues: list[str] = field(default_factory=list)
    performance_metrics: dict[str, Any] = field(default_factory=dict)
    error: Exception | None = None

    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return bool(self.warnings)

    def has_security_issues(self) -> bool:
        """Check if there are any security issues."""
        return bool(self.security_issues)

    def has_modifications(self) -> bool:
        """Check if the query was modified."""
        return self.original_query != self.sanitized_query

    def get_summary(self) -> str:
        """Get a summary of the sanitization results."""
        if not self.success:
            return f"Sanitization failed: {self.error}"

        parts = []
        if self.has_modifications():
            parts.append(f"Query modified ({len(self.removed_items)} items removed)")
        if self.has_warnings():
            parts.append(f"{len(self.warnings)} warnings")
        if self.has_security_issues():
            parts.append(f"{len(self.security_issues)} security issues")

        if not parts:
            return "Query passed sanitization without issues"

        return "Sanitization completed with: " + ", ".join(parts)


class MongoSanitizer:
    """
    Main MongoDB query sanitizer with layered protection.

    Implements a five-layer protection system:
    1. Type Validation
    2. Schema Enforcement
    3. Operator Filtering
    4. Pattern Validation
    5. Complexity Limiting
    """

    def __init__(self, config: SanitizerConfig | None = None) -> None:
        """Initialize the sanitizer with configuration."""
        self.config = config or SanitizerConfig()
        self.logger = self._setup_logging()

        # Initialize protection layers
        self._init_layers()

    def sanitize(self, query: Any) -> SanitizationReport:
        """
        Sanitize a MongoDB query through all protection layers.

        Args:
            query: The MongoDB query to sanitize

        Returns:
            SanitizationReport with detailed results
        """
        import time

        start_time = time.time()

        # Create initial report
        report = SanitizationReport(
            original_query=query.copy() if isinstance(query, dict) else query,
            sanitized_query=query,
            success=False,
        )

        try:
            current_query = query

            # Layer 1: Type Validation
            result = self._run_layer(
                "Type Validation", self.type_validator, current_query, report
            )
            current_query = result.modified_query or current_query

            # Layer 2: Schema Enforcement
            if isinstance(current_query, dict):
                result = self._run_layer(
                    "Schema Enforcement", self.schema_enforcer, current_query, report
                )
                current_query = result.modified_query or current_query

            # Layer 3: Operator Filtering
            if isinstance(current_query, dict):
                result = self._run_layer(
                    "Operator Filtering", self.operator_filter, current_query, report
                )
                current_query = result.modified_query or current_query
                if result.removed_items:
                    report.removed_items.update(result.removed_items)

            # Layer 4: Pattern Validation
            if isinstance(current_query, dict):
                result = self._run_layer(
                    "Pattern Validation", self.pattern_validator, current_query, report
                )
                current_query = result.modified_query or current_query

            # Layer 5: Complexity Limiting
            if isinstance(current_query, dict):
                result = self._run_layer(
                    "Complexity Limiting",
                    self.complexity_limiter,
                    current_query,
                    report,
                )
                current_query = result.modified_query or current_query

            # Finalize report
            report.sanitized_query = current_query
            report.success = True

            # Log results
            if self.config.enable_logging:
                self._log_sanitization_results(report)

        except Exception as e:
            report.error = e
            report.success = False
            if self.config.enable_logging:
                self.logger.error(f"Sanitization failed: {e}")

            # Re-raise based on configuration
            if self._should_reraise_error(e):
                raise

        # Performance metrics
        report.performance_metrics = {
            "processing_time_ms": round((time.time() - start_time) * 1000, 2),
            "layers_processed": len(report.layers_processed),
        }

        return report

    def sanitize_query(self, query: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize a query and return only the cleaned query.

        This is a convenience method that returns just the sanitized query
        without the full report.
        """
        report = self.sanitize(query)
        if not report.success:
            raise SanitizerError(f"Query sanitization failed: {report.error}")
        return report.sanitized_query

    def is_query_safe(self, query: Any) -> bool:
        """
        Check if a query is safe without modifying it.

        Returns True if the query passes all validation layers.
        """
        try:
            report = self.sanitize(query)
            return report.success and not report.has_security_issues()
        except Exception:
            return False

    def _init_layers(self) -> None:
        """Initialize all protection layers."""
        self.type_validator = TypeValidator(strict_mode=self.config.strict_types)

        self.schema_enforcer = SchemaEnforcer(
            schema_validator=self.config.schema_validator,
            fail_on_violation=self.config.fail_on_schema_violation,
        )

        self.operator_filter = OperatorFilter(
            allowed_operators=self.config.allowed_operators,
            dangerous_operators=self.config.dangerous_operators,
            strict_mode=self.config.strict_operators,
        )

        if self.config.enable_pattern_validation:
            custom_patterns = {}
            if self.config.custom_dangerous_patterns:
                import re

                custom_patterns = {
                    name: re.compile(pattern)
                    for name, pattern in self.config.custom_dangerous_patterns.items()
                }
            self.pattern_validator = PatternValidator(
                custom_patterns=custom_patterns,
                fail_on_dangerous_patterns=self.config.fail_on_dangerous_patterns,
            )
        else:
            self.pattern_validator = None

        self.complexity_limiter = ComplexityLimiter(
            max_depth=self.config.max_depth,
            max_keys=self.config.max_keys,
            max_array_length=self.config.max_array_length,
            max_string_length=self.config.max_string_length,
        )

    def _run_layer(
        self,
        layer_name: str,
        layer_instance: Any,
        query: Any,
        report: SanitizationReport,
    ) -> LayerResult:
        """Run a single protection layer and update the report."""
        if layer_instance is None:
            return LayerResult(success=True, modified_query=query)

        try:
            result = layer_instance.validate(query)
            report.layers_processed.append(layer_name)
            report.warnings.extend(result.warnings)

            if self.config.enable_logging and result.warnings:
                for warning in result.warnings:
                    self.logger.warning(f"{layer_name}: {warning}")

            return result

        except Exception as e:
            if self.config.enable_logging:
                self.logger.error(f"{layer_name} failed: {e}")
            raise

    def _should_reraise_error(self, error: Exception) -> bool:
        """Determine if an error should be re-raised based on config."""
        from .exceptions import (
            ComplexityError,
            PatternError,
            SchemaViolationError,
            SecurityError,
        )

        if isinstance(error, SchemaViolationError):
            return self.config.fail_on_schema_violation
        elif isinstance(error, SecurityError):
            return self.config.fail_on_dangerous_operators
        elif isinstance(error, PatternError):
            return self.config.fail_on_dangerous_patterns
        elif isinstance(error, ComplexityError):
            return self.config.fail_on_complexity_exceeded

        return True  # Re-raise unexpected errors

    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the sanitizer."""
        logger = logging.getLogger("sanitongo")

        if not logger.handlers and self.config.enable_logging:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, self.config.log_level.upper()))

        return logger

    def _log_sanitization_results(self, report: SanitizationReport) -> None:
        """Log the results of sanitization."""
        if report.success:
            self.logger.info(f"Sanitization completed: {report.get_summary()}")

            if self.config.log_removed_items and report.removed_items:
                self.logger.warning(f"Removed items: {report.removed_items}")

            if report.has_security_issues():
                for issue in report.security_issues:
                    self.logger.warning(f"Security issue: {issue}")
        else:
            self.logger.error(f"Sanitization failed: {report.error}")

    def get_config(self) -> SanitizerConfig:
        """Get the current configuration."""
        return self.config

    def update_config(self, **kwargs: Any) -> None:
        """Update sanitizer configuration."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
            else:
                raise ValueError(f"Unknown configuration option: {key}")

        # Re-initialize layers with new config
        self._init_layers()


def create_sanitizer(
    schema: dict[str, Any] | None = None,
    strict_mode: bool = True,
    **config_kwargs: Any,
) -> MongoSanitizer:
    """
    Create a MongoDB sanitizer with common configuration.

    Args:
        schema: Optional schema definition for field validation
        strict_mode: Whether to use strict validation mode
        **config_kwargs: Additional configuration options

    Returns:
        Configured MongoSanitizer instance
    """
    config = SanitizerConfig(
        strict_types=strict_mode,
        strict_operators=strict_mode,
        fail_on_dangerous_patterns=strict_mode,
        **config_kwargs,
    )

    if schema:
        from .schema import FieldRule, FieldType, SchemaValidator

        # Convert simple schema to FieldRule objects if needed
        schema_rules = {}
        for field_name, field_config in schema.items():
            if isinstance(field_config, FieldRule):
                schema_rules[field_name] = field_config
            elif isinstance(field_config, dict):
                # Create FieldRule from dict config
                field_type = FieldType(field_config.get("type", "any"))
                schema_rules[field_name] = FieldRule(
                    field_type=field_type,
                    required=field_config.get("required", False),
                    allowed_values=field_config.get("allowed_values"),
                    min_length=field_config.get("min_length"),
                    max_length=field_config.get("max_length"),
                    pattern=field_config.get("pattern"),
                )
            else:
                # Assume it's a field type string
                schema_rules[field_name] = FieldRule(FieldType(field_config))

        config.schema_validator = SchemaValidator(schema_rules)

    return MongoSanitizer(config)
