import datetime

from sanitongo.sanitizer import MongoSanitizer, SanitizerConfig
from sanitongo.schema import FieldRule, FieldType, SchemaValidator

# Mock ObjectId to avoid dependency on bson if not installed,
# or try to import it if available.
try:
    from bson import ObjectId
except ImportError:

    class ObjectId:
        def __init__(self, oid=None):
            self.oid = oid or "507f1f77bcf86cd799439011"

        def __str__(self):
            return self.oid


def test_type_validator_with_objects():
    print("\n--- Testing TypeValidator with ObjectId and Datetime ---")
    config = SanitizerConfig(
        strict_types=True,
        # minimal schema to allow these fields if they pass TypeValidator
        schema_validator=SchemaValidator(
            {"oid": FieldRule(FieldType.OBJECT_ID), "dt": FieldRule(FieldType.DATETIME)}
        ),
    )
    sanitizer = MongoSanitizer(config)

    query = {"oid": ObjectId(), "dt": datetime.datetime.now()}

    try:
        report = sanitizer.sanitize(query)
        if report.success:
            print("SUCCESS: ObjectId and Datetime passed validation.")
        else:
            print(f"FAILED: {report.error}")
    except Exception as e:
        print(f"EXCEPTION: {e}")


def test_regex_conflict():
    print("\n--- Testing Schema vs OperatorFilter conflict for $regex ---")
    # Schema allows regex for 'name', but OperatorFilter treats $regex as dangerous by default
    config = SanitizerConfig(
        strict_operators=True,
        fail_on_dangerous_operators=False,  # Let it just remove it to see
        schema_validator=SchemaValidator(
            {
                "name": FieldRule(
                    FieldType.STRING,
                    # Explicitly testing if schema validation handles $regex
                )
            }
        ),
    )
    # Default config puts $regex in dangerous_operators

    sanitizer = MongoSanitizer(config)

    query = {"name": {"$regex": "^test"}}

    report = sanitizer.sanitize(query)
    print(f"Report success: {report.success}")
    print(f"Removed items: {report.removed_items}")
    print(f"Sanitized query: {report.sanitized_query}")

    if "name" in report.sanitized_query and "$regex" in report.sanitized_query["name"]:
        print("RESULT: $regex was PRESERVED")
    else:
        print("RESULT: $regex was REMOVED")


def test_proto_pollution_keys():
    print("\n--- Testing __proto__ as key ---")
    # relaxed schema to allow arbitrary fields for this test?
    # Or just no schema to test TypeValidator/Complexity checks.
    config = SanitizerConfig(
        schema_validator=None,  # No schema means all fields allowed by schema enforcer
        enable_pattern_validation=True,
    )
    sanitizer = MongoSanitizer(config)

    query = {
        "__proto__": {"polluted": True},
        "constructor": {"prototype": {"polluted": True}},
    }

    report = sanitizer.sanitize(query)
    print(f"Report success: {report.success}")
    print(f"Warnings: {report.warnings}")
    print(f"Security issues: {report.security_issues}")
    print(f"Sanitized query: {report.sanitized_query}")


if __name__ == "__main__":
    test_type_validator_with_objects()
    test_regex_conflict()
    test_proto_pollution_keys()
