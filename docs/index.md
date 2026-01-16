# sanitongo

Modern MongoDB query sanitizer with layered security protection.

## Features

- **Layered Security**: Multiple protection layers against NoSQL injection
- **Pydantic Integration**: Type-safe configuration and validation
- **Flexible Rules**: Customizable sanitization rules
- **Production Ready**: Battle-tested security patterns

## Installation

```bash
pip install sanitongo
```

Or with uv:

```bash
uv add sanitongo
```

## Quick Start

```python
from sanitongo import create_sanitizer

# Create a sanitizer with strict mode
sanitizer = create_sanitizer(strict_mode=True)

# Check if a query is safe
query = {"name": "John", "age": {"$gte": 18}}
if sanitizer.is_query_safe(query):
    result = sanitizer.sanitize_query(query)
else:
    print("Query blocked!")
```

## Links

- [Getting Started](getting-started.md) - Detailed setup and usage guide
- [API Reference](api.md) - Full API documentation
- [GitHub Repository](https://github.com/izikeros/sanitongo)
- [PyPI Package](https://pypi.org/project/sanitongo/)

## Author

Created by [Krystian Safjan](https://safjan.com)
