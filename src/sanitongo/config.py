"""
Configuration management and utilities for the Sanitongo library.

This module provides configuration loading, validation, and management
functionality for the MongoDB query sanitizer.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .exceptions import ConfigurationError
from .sanitizer import SanitizerConfig
from .schema import FieldRule, FieldType, SchemaValidator


class ConfigManager:
    """Manages sanitizer configuration from various sources."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        """Initialize configuration manager."""
        self.config_path = Path(config_path) if config_path else None
        self._config_cache: dict[str, Any] = {}

    def load_config(
        self, config_source: str | Path | dict[str, Any] | None = None
    ) -> SanitizerConfig:
        """
        Load configuration from various sources.

        Args:
            config_source: Can be a file path, dict, or None for defaults

        Returns:
            SanitizerConfig instance
        """
        if config_source is None:
            return self._load_default_config()
        elif isinstance(config_source, dict):
            return self._load_from_dict(config_source)
        elif isinstance(config_source, (str, Path)):
            return self._load_from_file(Path(config_source))
        else:
            raise ConfigurationError(
                f"Unsupported config source type: {type(config_source)}"
            )

    def _load_default_config(self) -> SanitizerConfig:
        """Load default configuration."""
        return SanitizerConfig()

    def _load_from_dict(self, config_dict: dict[str, Any]) -> SanitizerConfig:
        """Load configuration from dictionary."""
        try:
            # Handle schema configuration
            schema_validator = None
            if "schema" in config_dict:
                schema_validator = self._build_schema_validator(config_dict["schema"])

            # Create config with validated parameters
            config_params = {}
            for key, value in config_dict.items():
                if key == "schema":
                    continue  # Handled separately
                elif hasattr(SanitizerConfig, key):
                    config_params[key] = value
                else:
                    raise ConfigurationError(f"Unknown configuration parameter: {key}")

            config = SanitizerConfig(schema_validator=schema_validator, **config_params)
            return config

        except Exception as e:
            raise ConfigurationError(
                f"Failed to load configuration from dict: {e}"
            ) from e

    def _load_from_file(self, file_path: Path) -> SanitizerConfig:
        """Load configuration from file."""
        if not file_path.exists():
            raise ConfigurationError(f"Configuration file not found: {file_path}")

        try:
            if file_path.suffix.lower() == ".json":
                with file_path.open() as f:
                    config_dict = json.load(f)
            else:
                raise ConfigurationError(
                    f"Unsupported configuration file format: {file_path.suffix}"
                )

            return self._load_from_dict(config_dict)

        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in configuration file: {e}") from e
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration file: {e}") from e

    def _build_schema_validator(self, schema_config: dict[str, Any]) -> SchemaValidator:
        """Build schema validator from configuration."""
        schema_rules = {}

        for field_name, field_config in schema_config.items():
            if isinstance(field_config, str):
                # Simple type specification
                field_type = FieldType(field_config)
                schema_rules[field_name] = FieldRule(field_type)
            elif isinstance(field_config, dict):
                # Detailed field configuration
                field_type = FieldType(field_config.get("type", "any"))
                schema_rules[field_name] = FieldRule(
                    field_type=field_type,
                    required=field_config.get("required", False),
                    allowed_values=field_config.get("allowed_values"),
                    min_length=field_config.get("min_length"),
                    max_length=field_config.get("max_length"),
                    pattern=field_config.get("pattern"),
                    description=field_config.get("description"),
                )
            else:
                raise ConfigurationError(
                    f"Invalid field configuration for '{field_name}': {field_config}"
                )

        return SchemaValidator(schema_rules)

    def save_config(self, config: SanitizerConfig, file_path: str | Path) -> None:
        """Save configuration to file."""
        file_path = Path(file_path)

        # Convert config to serializable format
        config_dict = self._config_to_dict(config)

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)

            if file_path.suffix.lower() == ".json":
                with file_path.open("w") as f:
                    json.dump(config_dict, f, indent=2)
            else:
                raise ConfigurationError(
                    f"Unsupported output file format: {file_path.suffix}"
                )

        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}") from e

    def _config_to_dict(self, config: SanitizerConfig) -> dict[str, Any]:
        """Convert SanitizerConfig to dictionary."""
        config_dict = {}

        self._add_basic_config_fields(config, config_dict)
        self._add_schema_config(config, config_dict)
        self._add_operator_config(config, config_dict)
        self._add_pattern_config(config, config_dict)

        return config_dict

    def _add_basic_config_fields(
        self, config: SanitizerConfig, config_dict: dict[str, Any]
    ) -> None:
        """Add basic configuration fields to dictionary."""
        basic_fields = [
            "strict_types",
            "strict_operators",
            "enable_pattern_validation",
            "max_depth",
            "max_keys",
            "max_array_length",
            "max_string_length",
            "enable_logging",
            "log_level",
            "log_removed_items",
            "fail_on_schema_violation",
            "fail_on_dangerous_operators",
            "fail_on_dangerous_patterns",
            "fail_on_complexity_exceeded",
        ]

        for field_name in basic_fields:
            if hasattr(config, field_name):
                config_dict[field_name] = getattr(config, field_name)

    def _add_schema_config(
        self, config: SanitizerConfig, config_dict: dict[str, Any]
    ) -> None:
        """Add schema configuration to dictionary."""
        if not config.schema_validator:
            return

        schema_dict = {}
        for field_name, field_rule in config.schema_validator.schema.items():
            field_config = {
                "type": field_rule.field_type.value,
                "required": field_rule.required,
            }

            # Add optional field properties
            optional_props = [
                ("allowed_values", field_rule.allowed_values),
                ("min_length", field_rule.min_length),
                ("max_length", field_rule.max_length),
                ("description", field_rule.description),
            ]

            for prop_name, prop_value in optional_props:
                if prop_value:
                    field_config[prop_name] = prop_value

            if field_rule.pattern:
                field_config["pattern"] = field_rule.pattern.pattern

            schema_dict[field_name] = field_config

        config_dict["schema"] = schema_dict

    def _add_operator_config(
        self, config: SanitizerConfig, config_dict: dict[str, Any]
    ) -> None:
        """Add operator configuration to dictionary."""
        if config.allowed_operators:
            config_dict["allowed_operators"] = list(config.allowed_operators)
        if config.dangerous_operators:
            config_dict["dangerous_operators"] = list(config.dangerous_operators)

    def _add_pattern_config(
        self, config: SanitizerConfig, config_dict: dict[str, Any]
    ) -> None:
        """Add pattern configuration to dictionary."""
        if config.custom_dangerous_patterns:
            config_dict["custom_dangerous_patterns"] = config.custom_dangerous_patterns


def load_config_from_env() -> SanitizerConfig:
    """Load configuration from environment variables."""
    config_params = {}

    # Environment variable mappings
    env_mappings = {
        "SANITONGO_STRICT_TYPES": ("strict_types", bool),
        "SANITONGO_STRICT_OPERATORS": ("strict_operators", bool),
        "SANITONGO_ENABLE_PATTERN_VALIDATION": ("enable_pattern_validation", bool),
        "SANITONGO_MAX_DEPTH": ("max_depth", int),
        "SANITONGO_MAX_KEYS": ("max_keys", int),
        "SANITONGO_MAX_ARRAY_LENGTH": ("max_array_length", int),
        "SANITONGO_MAX_STRING_LENGTH": ("max_string_length", int),
        "SANITONGO_ENABLE_LOGGING": ("enable_logging", bool),
        "SANITONGO_LOG_LEVEL": ("log_level", str),
        "SANITONGO_LOG_REMOVED_ITEMS": ("log_removed_items", bool),
    }

    for env_var, (param_name, param_type) in env_mappings.items():
        env_value = os.getenv(env_var)
        if env_value is not None:
            try:
                if param_type is bool:
                    config_params[param_name] = env_value.lower() in (
                        "true",
                        "1",
                        "yes",
                        "on",
                    )
                elif param_type is int:
                    config_params[param_name] = int(env_value)
                else:
                    config_params[param_name] = env_value
            except ValueError as e:
                raise ConfigurationError(
                    f"Invalid value for {env_var}: {env_value}"
                ) from e

    return SanitizerConfig(**config_params)


def create_example_config() -> dict[str, Any]:
    """Create an example configuration dictionary."""
    return {
        "strict_types": True,
        "strict_operators": True,
        "enable_pattern_validation": True,
        "max_depth": 10,
        "max_keys": 100,
        "max_array_length": 1000,
        "max_string_length": 10000,
        "enable_logging": True,
        "log_level": "INFO",
        "log_removed_items": True,
        "fail_on_schema_violation": True,
        "fail_on_dangerous_operators": True,
        "fail_on_dangerous_patterns": True,
        "fail_on_complexity_exceeded": True,
        "schema": {
            "_id": {"type": "objectid", "description": "Document ID"},
            "name": {
                "type": "string",
                "required": True,
                "min_length": 1,
                "max_length": 100,
                "description": "User name",
            },
            "email": {
                "type": "string",
                "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
                "description": "Email address",
            },
            "age": {"type": "integer", "description": "Age in years"},
            "active": {"type": "boolean", "description": "Active status"},
            "tags": {"type": "array", "description": "User tags"},
        },
        "custom_dangerous_patterns": {
            "suspicious_eval": r"eval\s*\(",
            "script_injection": r"<script[^>]*>.*?</script>",
        },
    }


def generate_config_file(output_path: str | Path) -> None:
    """Generate an example configuration file."""
    ConfigManager()
    example_config = create_example_config()

    output_path = Path(output_path)
    with output_path.open("w") as f:
        json.dump(example_config, f, indent=2)

    print(f"Example configuration file created at: {output_path}")
