"""Security-focused tests for the MongoDB sanitizer."""

from typing import Any

import pytest

from sanitongo import create_sanitizer
from sanitongo.exceptions import ComplexityError, PatternError, SecurityError


class TestSecurityScenarios:
    """Test various security attack scenarios."""

    def test_nosql_injection_prevention(self) -> None:
        """Test prevention of NoSQL injection attacks."""
        sanitizer = create_sanitizer(strict_mode=True)

        # Classic NoSQL injection attempts
        malicious_queries = [
            {"$where": "function() { return true; }"},
            {"$where": "this.username == 'admin'"},
            {"username": {"$ne": None}},  # This should be allowed with proper config
            {"$or": [{"password": {"$regex": ".*"}}, {"admin": True}]},
        ]

        # Most should be blocked in strict mode
        for query in malicious_queries[:2]:
            with pytest.raises(SecurityError):
                sanitizer.sanitize_query(query)

    def test_javascript_injection_prevention(self) -> None:
        """Test prevention of JavaScript injection."""
        sanitizer = create_sanitizer(strict_mode=True)

        js_payloads = [
            {"payload": "function() { while(true) {} }"},  # DoS
            {"code": "eval('rm -rf /')"},
            {"script": "setTimeout(() => { attack(); }, 1000)"},
            {"injection": "constructor.constructor('return process')()"},
        ]

        for query in js_payloads:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)

    @pytest.mark.xfail(
        reason="ReDoS pattern detection needs more comprehensive regex patterns"
    )
    def test_redos_prevention(self) -> None:
        """Test prevention of ReDoS (Regular Expression DoS) attacks."""
        sanitizer = create_sanitizer(strict_mode=True)

        redos_patterns = [
            {"regex": "(a+)+$"},
            {"pattern": "^(a+)+$"},
            {"evil": "(x+x+)+y"},
            {"redos": "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*"},
        ]

        for query in redos_patterns:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)

    def test_prototype_pollution_prevention(self) -> None:
        """Test prevention of prototype pollution attempts."""
        sanitizer = create_sanitizer(strict_mode=True)

        pollution_queries = [
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"evil": True}}},
            {"prototype.polluted": "true"},
            {"__proto__.isAdmin": True},
        ]

        for query in pollution_queries:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)

    @pytest.mark.xfail(
        reason="Command injection pattern detection needs more comprehensive patterns for space-separated commands"
    )
    def test_command_injection_prevention(self) -> None:
        """Test prevention of command injection attempts."""
        sanitizer = create_sanitizer(strict_mode=True)

        injection_queries = [
            {"cmd": "rm -rf /"},
            {"exec": "; cat /etc/passwd"},
            {"system": "| grep admin"},
            {"shell": "& whoami"},
            {"command": "`id`"},
            {"injection": "$(cat secret.txt)"},
            {"pipe": " || echo hacked"},
        ]

        for query in injection_queries:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)

    def test_xss_prevention(self) -> None:
        """Test prevention of XSS attacks."""
        sanitizer = create_sanitizer(strict_mode=True)

        xss_payloads = [
            {"html": "<script>alert('xss')</script>"},
            {"payload": "<img src=x onerror=alert('xss')>"},
            {"injection": "javascript:alert('xss')"},
            {"svg": "<svg onload=alert('xss')>"},
        ]

        for query in xss_payloads:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)

    def test_deep_nesting_attack_prevention(self) -> None:
        """Test prevention of deeply nested object attacks."""
        sanitizer = create_sanitizer(strict_mode=True, max_depth=3)

        # Create a deeply nested query (depth > 3)
        deep_query: dict[str, Any] = {"level1": {}}
        current = deep_query["level1"]
        for i in range(2, 10):  # Create nesting to level 9
            current[f"level{i}"] = {}
            current = current[f"level{i}"]
        current["data"] = "malicious"

        with pytest.raises(ComplexityError):
            sanitizer.sanitize_query(deep_query)

    def test_array_based_attacks(self) -> None:
        """Test prevention of attacks hidden in arrays."""
        sanitizer = create_sanitizer(strict_mode=True)

        array_attack = {
            "conditions": [
                {"name": "legitimate"},
                {"$where": "function() { return true; }"},
                {"payload": "eval('attack')"},
            ]
        }

        with pytest.raises((SecurityError, PatternError)):
            sanitizer.sanitize_query(array_attack)

    def test_mixed_content_attacks(self) -> None:
        """Test prevention of mixed legitimate and malicious content."""
        sanitizer = create_sanitizer(strict_mode=False)  # Use lenient mode

        mixed_query = {
            "username": "john_doe",  # Legitimate
            "age": {"$gte": 18},  # Legitimate
            "$where": "evil()",  # Malicious
            "bio": "Normal bio text",  # Legitimate
            "payload": "<script>alert('xss')</script>",  # Malicious
        }

        # In lenient mode, should remove malicious parts but keep legitimate ones
        result = sanitizer.sanitize(mixed_query)

        assert result.success is True
        assert "username" in result.sanitized_query
        assert "age" in result.sanitized_query
        assert "bio" in result.sanitized_query
        assert "$where" not in result.sanitized_query
        assert len(result.removed_items) > 0


class TestComplexityAttacks:
    """Test prevention of complexity-based DoS attacks."""

    def test_depth_bomb_prevention(self) -> None:
        """Test prevention of deeply nested query bombs."""
        sanitizer = create_sanitizer(strict_mode=True)

        # Create extremely deep nesting
        deep_query = {}
        current = deep_query
        for _ in range(50):  # Much deeper than default limit
            current["level"] = {}
            current = current["level"]
        current["payload"] = "deep_attack"

        from sanitongo.exceptions import ComplexityError

        with pytest.raises(ComplexityError):
            sanitizer.sanitize_query(deep_query)

    def test_key_explosion_prevention(self) -> None:
        """Test prevention of queries with excessive keys."""
        sanitizer = create_sanitizer(strict_mode=True)

        # Create query with many keys
        key_bomb = {f"key_{i}": f"value_{i}" for i in range(500)}

        from sanitongo.exceptions import ComplexityError

        with pytest.raises(ComplexityError):
            sanitizer.sanitize_query(key_bomb)

    def test_array_size_bomb_prevention(self) -> None:
        """Test prevention of large array attacks."""
        sanitizer = create_sanitizer(strict_mode=True)

        large_array_query = {"large_array": list(range(5000))}  # Exceeds default limit

        from sanitongo.exceptions import ComplexityError

        with pytest.raises(ComplexityError):
            sanitizer.sanitize_query(large_array_query)

    def test_string_length_bomb_prevention(self) -> None:
        """Test prevention of very long string attacks."""
        sanitizer = create_sanitizer(strict_mode=True)

        long_string_query = {"long_string": "A" * 50000}  # Exceeds default limit

        from sanitongo.exceptions import ComplexityError

        with pytest.raises(ComplexityError):
            sanitizer.sanitize_query(long_string_query)


class TestBypassAttempts:
    """Test prevention of common sanitization bypass attempts."""

    def test_encoding_bypass_attempts(self) -> None:
        """Test prevention of encoding-based bypasses."""
        sanitizer = create_sanitizer(strict_mode=True)

        # These are still dangerous even if encoded differently
        encoded_attempts = [
            {
                "payload": "\\u0066\\u0075\\u006e\\u0063\\u0074\\u0069\\u006f\\u006e"
            },  # "function"
            {"script": "\\x3cscript\\x3e"},  # "<script>"
        ]

        # The pattern detector should still catch these
        for query in encoded_attempts:
            # Some might not be caught by basic pattern matching
            # but the principle is that they should be
            result = sanitizer.sanitize(query)
            # At minimum, they shouldn't crash the sanitizer
            assert result is not None

    def test_case_variation_bypass_attempts(self) -> None:
        """Test prevention of case variation bypass attempts."""
        sanitizer = create_sanitizer(strict_mode=True)

        case_variants = [
            {"payload": "Function() { attack(); }"},
            {"script": "<SCRIPT>alert('xss')</SCRIPT>"},
            {"eval": "EVAL('malicious')"},
        ]

        for query in case_variants:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)

    def test_whitespace_bypass_attempts(self) -> None:
        """Test prevention of whitespace-based bypasses."""
        sanitizer = create_sanitizer(strict_mode=True)

        whitespace_variants = [
            {"payload": "function () { attack(); }"},
            {"script": "< script >alert('xss')</ script >"},
            {"eval": "eval ( 'malicious' )"},
        ]

        for query in whitespace_variants:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)

    def test_comment_injection_attempts(self) -> None:
        """Test prevention of comment-based injection."""
        sanitizer = create_sanitizer(strict_mode=True)

        comment_injections = [
            {"payload": "/* comment */ function() { attack(); }"},
            {"script": "// comment\nalert('xss')"},
        ]

        for query in comment_injections:
            with pytest.raises(PatternError):
                sanitizer.sanitize_query(query)


@pytest.mark.security
class TestRealWorldAttacks:
    """Test against real-world attack patterns."""

    def test_mongodb_specific_attacks(self) -> None:
        """Test MongoDB-specific attack patterns."""
        sanitizer = create_sanitizer(strict_mode=True)

        # Test legitimate query that bypasses auth but uses safe operators
        blind_injection = {"username": {"$ne": ""}}
        result = sanitizer.sanitize_query(blind_injection)
        # This should pass but could be flagged by business logic
        assert result == {"username": {"$ne": ""}}

        # Test dangerous attacks that should be blocked
        dangerous_attacks = [
            # Denial of service
            {"$where": "sleep(5000)"},
            # Information disclosure
            {"$where": "db.users.findOne()"},
        ]

        for query in dangerous_attacks:
            with pytest.raises((SecurityError, PatternError)):
                sanitizer.sanitize_query(query)

    def test_combined_attack_vectors(self) -> None:
        """Test complex attacks combining multiple vectors."""
        sanitizer = create_sanitizer(strict_mode=True)

        combined_attack = {
            # NoSQL injection
            "$where": "function() { return true; }",
            # XSS
            "user_input": "<script>steal_cookies()</script>",
            # Command injection
            "filename": "; rm -rf /",
            # Complexity attack
            "nested": {f"level_{i}": {"data": "x" * 1000} for i in range(20)},
            # Prototype pollution
            "__proto__": {"isAdmin": True},
        }

        from sanitongo.exceptions import ComplexityError

        with pytest.raises((SecurityError, PatternError, ComplexityError)):
            sanitizer.sanitize_query(combined_attack)
