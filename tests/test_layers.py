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
        validator = TypeValidator()
        query = {"name": "John", "age": 30, "tags": ["a", "b"]}
        result = validator.validate(query)
        assert result.success
        assert result.modified_query == query

    def test_invalid_type_strict_mode(self) -> None:
        validator = TypeValidator(strict_mode=True)
        with pytest.raises(ValidationError):
            validator.validate([1, 2, 3])

    def test_invalid_type_lenient_mode(self) -> None:
        validator = TypeValidator(strict_mode=False)
        result = validator.validate(123)
        assert not result.success

    def test_empty_dict(self) -> None:
        validator = TypeValidator()
        result = validator.validate({})
        assert result.success
        assert result.warnings

    def test_nested_invalid_types(self) -> None:
        validator = TypeValidator()
        with pytest.raises(ValidationError):
            validator.validate({"nested": {"invalid": {1, 2}}})

    def test_non_string_keys(self) -> None:
        validator = TypeValidator()
        with pytest.raises(ValidationError):
            validator.validate({123: "value"})


class TestOperatorFilter:
    """Test cases for OperatorFilter layer."""

    def test_safe_operators(self) -> None:
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"name": {"$eq": "John"}, "age": {"$gte": 18}}
        result = filter_layer.validate(query)
        assert result.success
        assert result.modified_query["name"]["$eq"] == "John"
        assert result.modified_query["age"]["$gte"] == 18

    def test_dangerous_operators_strict(self) -> None:
        filter_layer = OperatorFilter(strict_mode=True)
        query = {"$where": "function() { return true; }"}
        with pytest.raises(SecurityError):
            filter_layer.validate(query)

    def test_dangerous_operators_lenient(self) -> None:
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"$where": "function() { return true; }", "name": "John"}
        result = filter_layer.validate(query)
        assert result.success
        assert "$where" not in result.modified_query
        assert result.modified_query["name"] == "John"
        assert result.warnings

    def test_nested_dangerous_operators(self) -> None:
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"user": {"profile": {"$where": "malicious"}}, "normal": "field"}
        result = filter_layer.validate(query)
        assert result.success
        assert "$where" not in str(result.modified_query)
        assert result.modified_query["normal"] == "field"

    def test_array_processing(self) -> None:
        filter_layer = OperatorFilter(strict_mode=False)
        query = {"conditions": [{"$where": "bad"}, {"name": "good"}]}
        result = filter_layer.validate(query)
        assert result.success
        assert len(result.modified_query["conditions"]) == 2
        assert "$where" not in str(result.modified_query)

    def test_custom_allowed_operators(self) -> None:
        allowed_ops = {"$eq", "$ne"}
        filter_layer = OperatorFilter(allowed_operators=allowed_ops, strict_mode=False)
        query = {"name": {"$eq": "John"}, "age": {"$gte": 18}}
        result = filter_layer.validate(query)
        assert result.success
        assert "$eq" in str(result.modified_query)
        assert "$gte" not in str(result.modified_query)


class TestPatternValidator:
    """Test cases for PatternValidator layer."""

    def test_safe_strings(self) -> None:
        validator = PatternValidator()
        query = {"name": "John Doe", "description": "A normal user"}
        result = validator.validate(query)
        assert result.success
        assert not result.warnings

    def test_javascript_injection(self) -> None:
        validator = PatternValidator()
        query = {"payload": "function() { alert('xss'); }"}
        with pytest.raises(PatternError) as exc_info:
            validator.validate(query)
        assert "javascript" in exc_info.value.pattern_type

    def test_script_tags(self) -> None:
        validator = PatternValidator()
        query = {"content": "<script>alert('xss')</script>"}
        with pytest.raises(PatternError):
            validator.validate(query)

    def test_nested_pattern_detection(self) -> None:
        validator = PatternValidator()
        query = {"user": {"profile": {"bio": "eval('malicious code')"}}}
        with pytest.raises(PatternError):
            validator.validate(query)

    def test_array_pattern_detection(self) -> None:
        validator = PatternValidator()
        query = {"items": ["safe", "function() { bad(); }", "also_safe"]}
        with pytest.raises(PatternError):
            validator.validate(query)

    def test_custom_patterns(self) -> None:
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
        limiter = ComplexityLimiter()
        query = {"name": "John", "age": 30}
        result = limiter.validate(query)
        assert result.success

    def test_depth_limit_exceeded(self) -> None:
        limiter = ComplexityLimiter(max_depth=3)
        query = {"a": {"b": {"c": {"d": {"e": "too_deep"}}}}}
        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)
        assert exc_info.value.limit_type == "depth"
        assert exc_info.value.current_value > exc_info.value.max_allowed

    def test_key_count_limit_exceeded(self) -> None:
        limiter = ComplexityLimiter(max_keys=5)
        query = {f"key_{i}": f"value_{i}" for i in range(10)}
        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)
        assert exc_info.value.limit_type == "keys"

    def test_array_length_limit_exceeded(self) -> None:
        limiter = ComplexityLimiter(max_array_length=10)
        query = {"large_array": list(range(20))}
        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)
        assert exc_info.value.limit_type == "array_length"

    def test_string_length_limit_exceeded(self) -> None:
        limiter = ComplexityLimiter(max_string_length=100)
        query = {"long_string": "x" * 200}
        with pytest.raises(ComplexityError) as exc_info:
            limiter.validate(query)
        assert exc_info.value.limit_type == "string_length"

    def test_nested_arrays_and_strings(self) -> None:
        limiter = ComplexityLimiter(max_array_length=5, max_string_length=10)
        query = {"nested": {"array": [1, 2, 3], "string": "short"}}
        result = limiter.validate(query)
        assert result.success

    def test_depth_calculation(self) -> None:
        limiter = ComplexityLimiter(max_depth=5)
        query = {"a": {"b": {"c": {"d": {"e": "value"}}}}}
        result = limiter.validate(query)
        assert result.success
        query = {"a": {"b": {"c": {"d": {"e": {"f": "value"}}}}}}
        with pytest.raises(ComplexityError):
            limiter.validate(query)


class TestSchemaEnforcer:
    """Test cases for SchemaEnforcer layer."""

    def test_no_schema_defined(self) -> None:
        enforcer = SchemaEnforcer()
        query = {"any": "field", "should": "pass"}
        result = enforcer.validate(query)
        assert result.success
        assert result.warnings

    def test_valid_schema_query(self, schema_validator) -> None:
        enforcer = SchemaEnforcer(schema_validator)
        query = {
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30,
            "active": True,
        }
        result = enforcer.validate(query)
        assert result.success

    def test_schema_violation(self, schema_validator) -> None:
        enforcer = SchemaEnforcer(schema_validator)
        query = {"unknown_field": "not_allowed", "name": "John"}
        with pytest.raises((ValidationError, Exception)):
            enforcer.validate(query)
