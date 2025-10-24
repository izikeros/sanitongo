# Sanitongo 🛡️

> Modern MongoDB Query Sanitizer with Layered Security Protection

[![CI/CD Pipeline](https://github.com/izikeros/sanitongo/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/izikeros/sanitongo/actions)
[![codecov](https://codecov.io/gh/izikeros/sanitongo/branch/main/graph/badge.svg)](https://codecov.io/gh/izikeros/sanitongo)
[![PyPI version](https://badge.fury.io/py/sanitongo.svg)](https://badge.fury.io/py/sanitongo)
[![Python versions](https://img.shields.io/pypi/pyversions/sanitongo.svg)](https://pypi.org/project/sanitongo/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Sanitongo is a comprehensive security library for sanitizing MongoDB queries with multiple layers of protection against NoSQL injection attacks, malicious queries, and complexity-based DoS attacks.

## Features

### Five-Layer Protection System

1. **Type Validation** - Ensure inputs are valid types and structures
2. **Schema Enforcement** - Validate against predefined field schemas  
3. **Operator Filtering** - Remove/validate MongoDB operators
4. **Pattern Validation** - Detect dangerous patterns in string values
5. **Complexity Limiting** - Prevent DoS through query complexity limits

### Security Features

- **NoSQL Injection Prevention** - Blocks `$where`, `$function`, and other dangerous operators
- **JavaScript Injection Protection** - Detects and prevents JS code execution attempts
- **ReDoS Prevention** - Identifies potentially dangerous regex patterns
- **XSS Protection** - Blocks script tags and malicious HTML
- **Command Injection Prevention** - Detects shell command injection attempts
- **Prototype Pollution Protection** - Prevents `__proto__` and constructor manipulation
- **Complexity DoS Prevention** - Limits query depth, key count, array sizes, and string lengths

### Modern Architecture

- **Layered Design** - Each protection layer operates independently
- **Configurable** - Extensive configuration options for different security postures
- **Detailed Reporting** - Comprehensive sanitization reports with security insights
- **Type Safety** - Full TypeScript-style type hints and validation
- **Performance Focused** - Optimized for production use
- **Extensive Testing** - Security-focused test suites

## Installation

```bash
pip install sanitongo
```

For development with all dependencies:

```bash
pip install "sanitongo[dev]"
```

For documentation building:

```bash
pip install "sanitongo[docs]"
```

For testing (includes MongoDB integration tests):

```bash
pip install "sanitongo[test]"
```

## Quick Start

### Basic Usage

```python
from sanitongo import create_sanitizer

# Create a sanitizer with default settings
sanitizer = create_sanitizer(strict_mode=True)

# Sanitize a query
query = {
    "name": "John Doe",
    "age": {"$gte": 18},
    "email": "john@example.com"
}

# Safe sanitization
sanitized_query = sanitizer.sanitize_query(query)
print(sanitized_query)  # Clean query ready for MongoDB

# Check if query is safe without modification
is_safe = sanitizer.is_query_safe(query)
print(f"Query is safe: {is_safe}")
```

### Detailed Sanitization Report

```python
from sanitongo import MongoSanitizer, SanitizerConfig

# Create sanitizer with custom config
config = SanitizerConfig(
    strict_operators=False,  # Remove dangerous operators instead of failing
    enable_logging=True,
    log_level="INFO"
)
sanitizer = MongoSanitizer(config)

# Dangerous query example
dangerous_query = {
    "name": "John",
    "$where": "function() { return true; }",  # Dangerous JS execution
    "payload": "<script>alert('xss')</script>",  # XSS attempt
}

# Get detailed report
report = sanitizer.sanitize(dangerous_query)

print(f"Success: {report.success}")
print(f"Modified: {report.has_modifications()}")
print(f"Warnings: {len(report.warnings)}")
print(f"Removed items: {report.removed_items}")
print(f"Security issues: {report.security_issues}")
print(f"Summary: {report.get_summary()}")
```

### Schema-Based Validation

```python
from sanitongo import create_sanitizer

# Define your schema using simple field configs
schema = {
    "_id": {"type": "objectid"},
    "name": {
        "type": "string",
        "required": True,
        "min_length": 1,
        "max_length": 100
    },
    "email": {
        "type": "string", 
        "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    },
    "age": {"type": "integer"},
    "active": {"type": "boolean"},
    "tags": {"type": "array"}
}

# Create sanitizer with schema
sanitizer = create_sanitizer(schema=schema, strict_mode=True)

# Valid query
valid_query = {
    "name": "John Doe",
    "email": "john@example.com", 
    "age": 30,
    "active": True
}

result = sanitizer.sanitize_query(valid_query)  # ✅ Passes

# Invalid query with schema violations
invalid_query = {
    "name": "",  # Too short
    "email": "invalid-email",  # Wrong format
    "unknown_field": "not allowed"  # Not in schema
}

try:
    sanitizer.sanitize_query(invalid_query)  # ❌ Raises ValidationError
except Exception as e:
    print(f"Validation failed: {e}")
```

## Configuration

### Basic Configuration

```python
from sanitongo import SanitizerConfig, MongoSanitizer

config = SanitizerConfig(
    # Type validation
    strict_types=True,
    
    # Operator filtering  
    strict_operators=True,
    dangerous_operators={"$where", "$function", "$regex"},
    allowed_operators={"$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin"},
    
    # Pattern validation
    enable_pattern_validation=True,
    custom_dangerous_patterns={
        "sql_injection": r"(?i)(union\s+select|drop\s+table)",
        "custom_threat": r"malicious_pattern"
    },
    
    # Complexity limits
    max_depth=10,
    max_keys=100, 
    max_array_length=1000,
    max_string_length=10000,
    
    # Error handling
    fail_on_schema_violation=True,
    fail_on_dangerous_operators=True,
    fail_on_dangerous_patterns=True,
    fail_on_complexity_exceeded=True,
    
    # Logging
    enable_logging=True,
    log_level="INFO",
    log_removed_items=True
)

sanitizer = MongoSanitizer(config)
```

### Advanced Configuration

```python
from sanitongo import SanitizerConfig, MongoSanitizer

# Create detailed configuration
config = SanitizerConfig(
    strict_types=True,
    strict_operators=False,  # Remove dangerous operators instead of failing
    enable_pattern_validation=True,
    max_depth=15,
    max_keys=200,
    enable_logging=True,
    log_level="WARNING"
)

sanitizer = MongoSanitizer(config)
```

### Schema-Based Configuration

```python
from sanitongo import SanitizerConfig, MongoSanitizer
from sanitongo.schema import SchemaValidator, FieldRule, FieldType

# Define schema rules
schema_rules = {
    "_id": FieldRule(FieldType.OBJECT_ID),
    "name": FieldRule(
        FieldType.STRING,
        required=True,
        min_length=1,
        max_length=100
    ),
    "email": FieldRule(
        FieldType.STRING,
        pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    ),
    "age": FieldRule(FieldType.INTEGER),
    "active": FieldRule(FieldType.BOOLEAN)
}

# Create schema validator
schema_validator = SchemaValidator(schema_rules)

# Create configuration with schema
config = SanitizerConfig(
    schema_validator=schema_validator,
    strict_types=True,
    enable_logging=True
)

sanitizer = MongoSanitizer(config)
```

## Security Features

### Attack Prevention Examples

```python
from sanitongo import create_sanitizer

sanitizer = create_sanitizer(strict_mode=True)

# NoSQL Injection Prevention
malicious_queries = [
    {"$where": "function() { return true; }"},
    {"$where": "this.username == 'admin'"},
    {"username": {"$ne": None}},
]

# JavaScript Injection Prevention  
js_attacks = [
    {"payload": "function() { while(true) {} }"},
    {"code": "eval('rm -rf /')"},
    {"script": "setTimeout(() => { attack(); }, 1000)"},
]

# XSS Prevention
xss_attacks = [
    {"html": "<script>alert('xss')</script>"},
    {"payload": "<img src=x onerror=alert('xss')>"},
    {"injection": "javascript:alert('xss')"},
]

# All of these will be blocked or sanitized
for attack in malicious_queries + js_attacks + xss_attacks:
    try:
        sanitizer.sanitize_query(attack)
        print("❌ Attack not blocked!")
    except Exception as e:
        print(f"✅ Attack blocked: {type(e).__name__}")
```

### Complexity DoS Prevention

```python
# These will be blocked by complexity limits
complex_attacks = [
    # Deep nesting attack
    {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": "deep"}}}}}}}}}}},
    
    # Key explosion attack  
    {f"key_{i}": f"value_{i}" for i in range(500)},
    
    # Large array attack
    {"large_array": list(range(5000))},
    
    # Long string attack
    {"long_string": "A" * 50000}
]

for attack in complex_attacks:
    try:
        sanitizer.sanitize_query(attack)
        print("❌ Complexity attack not blocked!")
    except Exception as e:
        print(f"✅ Complexity attack blocked: {type(e).__name__}")
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/sanitongo --cov-report=html

# Run only security tests
pytest tests/test_security.py -m security

# Run performance benchmarks
pytest --benchmark-only
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/izikeros/sanitongo.git
cd sanitongo

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
make test

# Run linting
make lint

# Format code
make format
```

## Implementation Status

### Fully Implemented
- **Core Protection Layers**: All five security layers are implemented and tested
- **Basic API**: `MongoSanitizer`, `SanitizerConfig`, and `create_sanitizer` 
- **Schema Validation**: Field types, constraints, and validation rules
- **Security Features**: NoSQL injection, XSS, pattern detection, complexity limits
- **Error Handling**: Comprehensive exception hierarchy
- **Testing**: 83 tests with 69% code coverage

### Partially Implemented  
- **Configuration Management**: Basic config loading exists but needs more testing
- **Advanced Schema Types**: Some field types may need refinement
- **Documentation**: API docs could be expanded

### Planned Features
- **JSON/YAML Configuration**: File-based configuration loading
- **Environment Variables**: Configuration from environment  
- **Advanced Patterns**: More sophisticated threat detection
- **Performance Optimizations**: Further speed improvements

## Performance

Sanitongo is designed for production use with minimal performance impact:

- **Lightweight**: Small memory footprint
- **Fast**: Optimized algorithms for each protection layer
- **Scalable**: Handles complex queries efficiently
- **Configurable**: Adjust security vs. performance trade-offs

Benchmark results (from automated tests):

- Simple queries: ~45-80μs processing time
- Complex queries: ~100-200μs processing time  
- Schema validation: ~38-45μs processing time
- Memory usage: <10MB for typical configurations

## Security Considerations

### When to Use Strict Mode

**Use strict mode when:**

- Handling untrusted user input
- Building public APIs
- Processing queries from external sources
- Maximum security is required

**Use lenient mode when:**

- Processing internal/trusted queries
- You need detailed sanitization reports
- Gradual security implementation
- Legacy system integration

### Security Best Practices

1. **Always validate input** - Use schema validation for all external input
2. **Log security events** - Enable logging for security auditing
3. **Monitor removed items** - Track what gets sanitized
4. **Regular updates** - Keep sanitongo updated for latest security fixes
5. **Test thoroughly** - Include security tests in your test suite

## API Reference

### Main Classes

- **`MongoSanitizer`** - Main sanitizer class with full configuration
- **`SanitizerConfig`** - Configuration container
- **`SanitizationReport`** - Detailed sanitization results  
- **`SchemaValidator`** - Schema-based field validation

### Exceptions

- **`SanitizerError`** - Base exception class
- **`ValidationError`** - Input validation failures
- **`SchemaViolationError`** - Schema constraint violations
- **`SecurityError`** - Security threats detected
- **`ComplexityError`** - Query complexity limits exceeded
- **`PatternError`** - Dangerous patterns detected

### Factory Functions

- **`create_sanitizer()`** - Create sanitizer with common configurations

### Schema Components

- **`FieldType`** - Enum of supported field types (STRING, INTEGER, BOOLEAN, etc.)
- **`FieldRule`** - Validation rules for individual fields  
- **`SchemaValidator`** - Schema-based field validation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the MongoDB security community for vulnerability research
- Inspired by various NoSQL injection prevention techniques
- Built with modern Python security best practices

## Support

- **Documentation**: [GitHub Wiki](https://github.com/izikeros/sanitongo/wiki)
- **Issues**: [GitHub Issues](https://github.com/izikeros/sanitongo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/izikeros/sanitongo/discussions)
- **Security**: Report security issues privately to ksafjan@gmail.com
