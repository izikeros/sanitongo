# Getting Started

## Installation

### Using pip

```bash
pip install sanitongo
```

### Using uv

```bash
uv add sanitongo
```

### Development Installation

```bash
git clone https://github.com/izikeros/sanitongo.git
cd sanitongo
make dev
```

## Basic Usage

### Creating a Sanitizer

```python
from sanitongo import create_sanitizer

# Default configuration
sanitizer = create_sanitizer()

# Strict mode - blocks more potentially dangerous patterns
sanitizer = create_sanitizer(strict_mode=True)
```

### Validating Queries

```python
query = {"username": "admin", "password": {"$ne": None}}

# Check if query is safe
if sanitizer.is_query_safe(query):
    # Query passed validation
    safe_query = sanitizer.sanitize_query(query)
else:
    # Query contains potentially dangerous patterns
    print("Query blocked!")
```

### Handling Blocked Queries

```python
from sanitongo import create_sanitizer, SanitizationError

sanitizer = create_sanitizer(strict_mode=True)

try:
    result = sanitizer.sanitize_query(malicious_query)
except SanitizationError as e:
    print(f"Query blocked: {e}")
```

## Configuration

### Custom Rules

```python
from sanitongo import create_sanitizer, SanitizerConfig

config = SanitizerConfig(
    blocked_operators=["$where", "$expr"],
    max_depth=10,
    allow_regex=False,
)

sanitizer = create_sanitizer(config=config)
```

## Next Steps

- See [API Reference](api.md) for full documentation
- Check the [examples](https://github.com/izikeros/sanitongo/tree/main/examples) directory
