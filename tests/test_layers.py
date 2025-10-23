"""Tests for the layered protection system."""

import pytest

from sanitongo.exceptions import (
    ComplexityError,
    PatternError,
    SecurityError,
    ValidationError,
)
from sanitongo.layers import (
    ComplexityLimiter,
    OperatorFilter,
    PatternValidator,
    SchemaEnforcer,
    TypeValidator,
)


class TestTypeValidator:
    """Test cases for TypeValidator layer."""

    def test_valid_dict_input(self) -> None:
        """Test validation of valid dictionary input."""
        validator = TypeValidator()
        result = validator.validate({"name": "John", "age": 30})

        assert result.success is True
        assert result.modified_query is not None

    def test_invalid_type_strict_mode(self) -> None:
        """Test validation of invalid type in strict mode."""
        validator = TypeValidator(strict_mode=True)

        with pytest.raises(ValidationError):
            validator.validate("not_a_dict")

    def test_invalid_type_lenient_mode(self) -> None:
        """Test validation of invalid type in lenient mode."""
        validator = TypeValidator(strict_mode=False)
        result = validator.validate("not_a_dict")

        assert result.success is False

    def test_empty_dict(self) -> None:
        """Test validation of empty dictionary."""
        validator = TypeValidator()
        result = validator.validate({})

        assert result.success is True
        assert len(result.warnings) > 0

    def test_nested_invalid_types(self) -> None:
        """Test validation of nested invalid types."""
        validator = TypeValidator()

        with pytest.raises(ValidationError):
            validator.validate({"nested": {"invalid": object()}})

    def test_non_string_keys(self) -> None:
        """Test validation with non-string keys."""
        validator = TypeValidator()

        with pytest.raises(ValidationError):
            validator.validate({123: "value"})


class TestOperatorFilter:
    """Test cases for OperatorFilter layer."""

    def test_safe_operators(self) -> None:
        """Test handling of safe operators."""
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"name": {"$eq": "John"}, "age": {"$gte": 18}}

        result = filter_layer.validate(query)

        assert result.success is True
        assert "$eq" in str(result.modified_query)
        assert "$gte" in str(result.modified_query)

    def test_dangerous_operators_strict(self) -> None:
        """Test handling of dangerous operators in strict mode."""
        filter_layer = OperatorFilter(strict_mode=True)
        query = {"$where": "function() { return true; }"}

        with pytest.raises(SecurityError):
            filter_layer.validate(query)

    def test_dangerous_operators_lenient(self) -> None:
        """Test handling of dangerous operators in lenient mode."""
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"$where": "function() { return true; }", "name": "John"}

        result = filter_layer.validate(query)

        assert result.success is True
        assert "$where" not in result.modified_query
        assert "name" in result.modified_query
        assert len(result.warnings) > 0

    def test_nested_dangerous_operators(self) -> None:
        """Test removal of nested dangerous operators."""
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"user": {"profile": {"$where": "malicious"}}, "normal": "field"}

        result = filter_layer.validate(query)

        assert result.success is True
        assert "$where" not in str(result.modified_query)
        assert result.modified_query["normal"] == "field"

    def test_array_processing(self) -> None:
        """Test processing of arrays with operators."""
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"conditions": [{"$where": "bad"}, {"name": "good"}]}

        result = filter_layer.validate(query)

        assert result.success is True
        assert len(result.modified_query["conditions"]) == 2
        assert "$where" not in str(result.modified_query)

    def test_custom_allowed_operators(self) -> None:
        """Test with custom allowed operators."""
        allowed_ops = {"$eq", "$ne"}
        filter_layer = OperatorFilter(allowed_operators=allowed_ops, strict_mode=False)
        query = {"name": {"$eq": "John"}, "age": {"$gte": 18}}

        result = filter_layer.validate(query)

        assert result.success is True
        assert "$eq" in str(result.modified_query)
        assert "$gte" not in str(result.modified_query)  # Should be removed


class TestPatternValidator:
    """Test cases for PatternValidator layer."""

    def test_safe_strings(self) -> None:
        """Test validation of safe string patterns."""
        validator = PatternValidator()
        query = {"name": "John Doe", "description": "A normal user"}

        result = validator.validate(query)

        assert result.success is True
        assert len(result.warnings) == 0

    def test_javascript_injection(self) -> None:
        """Test detection of JavaScript injection patterns."""
        validator = PatternValidator()
        query = {"payload": "function() { alert('xss'); }"}

        with pytest.raises(PatternError) as exc_info:
            validator.validate(query)

        assert "javascript" in exc_info.value.pattern_type

    def test_script_tags(self) -> None:
        """Test detection of script tag injection."""
        validator = PatternValidator()
        query = {"content": "<script>alert('xss')</script>"}

        with pytest.raises(PatternError):
            validator.validate(query)

    def test_nested_pattern_detection(self) -> None:
        """Test pattern detection in nested structures."""
        validator = PatternValidator()
        query = {"user": {"profile": {"bio": "eval('malicious code')"}}}

        with pytest.raises(PatternError):
            validator.validate(query)

    def test_array_pattern_detection(self) -> None:
        """Test pattern detection in arrays."""
        validator = PatternValidator()
        query = {"items": ["safe", "function() { bad(); }", "also_safe"]}

        with pytest.raises(PatternError):
            validator.validate(query)

    def test_custom_patterns(self) -> None:
        """Test custom dangerous patterns."""
        import re

        custom_patterns = {"bad_word": re.compile(r"badword", re.IGNORECASE)}
        validator = PatternValidator(custom_patterns=custom_patterns)
        query = {"text": "This contains a BADWORD"}

        with pytest.raises(PatternError) as exc_info:
            validator.validate(query)

        assert exc_info.value.pattern_type == "bad_word"


class TestComplexityLimiter:
    """Test cases for ComplexityLimiter layer."""

    def test_simple_query(self) -> None:
        """Test validation of simple query."""
        limiter = ComplexityLimiter()
        query = {"name": "John", "age": 30}

        result = limiter.validate(query)

        assert result.success is True

    def test_depth_limit_exceeded(self) -> None:
        """Test query exceeding depth limit."""
        limiter = ComplexityLimiter(max_depth=3)

        # Create deeply nested query
        query = {"a": {"b": {"c": {"d": {"e": "too_deep"}}}}}

        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)

        assert exc_info.value.limit_type == "depth"
        assert exc_info.value.current_value > exc_info.value.max_allowed

    def test_key_count_limit_exceeded(self) -> None:
        """Test query exceeding key count limit."""
        limiter = ComplexityLimiter(max_keys=5)

        # Create query with many keys
        query = {f"key_{i}": f"value_{i}" for i in range(10)}

        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)

        assert exc_info.value.limit_type == "keys"

    def test_array_length_limit_exceeded(self) -> None:
        """Test query with array exceeding length limit."""
        limiter = ComplexityLimiter(max_array_length=10)
        query = {"large_array": list(range(20))}

        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)

        assert exc_info.value.limit_type == "array_length"

    def test_string_length_limit_exceeded(self) -> None:
        """Test query with string exceeding length limit."""
        limiter = ComplexityLimiter(max_string_length=100)
        query = {"long_string": "x" * 200}

        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)

        assert exc_info.value.limit_type == "string_length"

    def test_nested_arrays_and_strings(self) -> None:
        """Test validation of nested arrays and strings."""
        limiter = ComplexityLimiter(max_array_length=5, max_string_length=10)
        query = {"nested": {"array": [1, 2, 3], "string": "short"}}  # OK  # OK

        result = limiter.validate(query)
        assert result.success is True

    def test_depth_calculation(self) -> None:
        """Test correct depth calculation."""
        limiter = ComplexityLimiter(max_depth=5)

        # Exactly at limit should pass
        query = {"a": {"b": {"c": {"d": {"e": "value"}}}}}  # depth 5
        result = limiter.validate(query)
        assert result.success is True

        # Over limit should fail
        query = {"a": {"b": {"c": {"d": {"e": {"f": "value"}}}}}}  # depth 6
        with pytest.raises(ComplexityError):
            limiter.validate(query)


class TestSchemaEnforcer:
    """Test cases for SchemaEnforcer layer."""

    def test_no_schema_defined(self) -> None:
        """Test enforcer with no schema defined."""
        enforcer = SchemaEnforcer()
        query = {"any": "field", "should": "pass"}

        result = enforcer.validate(query)

        assert result.success is True
        assert len(result.warnings) > 0  # Should warn about no schema

    def test_valid_schema_query(self, schema_validator) -> None:
        """Test enforcer with valid query against schema."""
        enforcer = SchemaEnforcer(schema_validator)
        query = {
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30,
            "active": True,
        }

        result = enforcer.validate(query)
        assert result.success is True

    def test_schema_violation(self, schema_validator) -> None:
        """Test enforcer with query violating schema."""
        enforcer = SchemaEnforcer(schema_validator)
        query = {"unknown_field": "not_allowed", "name": "John"}

        with pytest.raises((ValidationError, Exception)):
            enforcer.validate(query)
