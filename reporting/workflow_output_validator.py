"""Read-only integrity validation for generated audit workflow artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


class WorkflowOutputValidationError(ValueError):
    """Raised when workflow output expectations are invalid."""


def validate_workflow_outputs(output_dir, expected_names):
    """Validate expected artifacts without modifying any input files."""
    root = Path(output_dir).resolve()
    names = list(expected_names)

    if not root.is_dir():
        raise WorkflowOutputValidationError(
            f"Output directory does not exist: {root}"
        )

    if not names:
        raise WorkflowOutputValidationError(
            "At least one expected artifact must be specified."
        )

    if len(names) != len(set(names)):
        raise WorkflowOutputValidationError(
            "Expected artifact names contain duplicates."
        )

    results = []
    errors = []

    for name in names:
        relative = Path(name)

        if relative.is_absolute() or ".." in relative.parts:
            raise WorkflowOutputValidationError(
                f"Unsafe artifact path: {name}"
            )

        path = (root / relative).resolve()

        if path != root and root not in path.parents:
            raise WorkflowOutputValidationError(
                f"Artifact path escapes output directory: {name}"
            )

        item = {
            "name": str(relative),
            "exists": False,
            "size_bytes": 0,
            "valid": False,
            "error": None,
        }

        if not path.is_file():
            item["error"] = "MISSING_FILE"
            errors.append({"name": str(relative), "type": "MISSING_FILE"})
            results.append(item)
            continue

        item["exists"] = True
        item["size_bytes"] = path.stat().st_size

        if item["size_bytes"] == 0:
            item["error"] = "EMPTY_FILE"
            errors.append({"name": str(relative), "type": "EMPTY_FILE"})
            results.append(item)
            continue

        if path.suffix.lower() == ".json":
            try:
                with path.open("r", encoding="utf-8") as handle:
                    json.load(handle)
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                item["error"] = f"INVALID_JSON: {type(exc).__name__}"
                errors.append({
                    "name": str(relative),
                    "type": "INVALID_JSON",
                })
                results.append(item)
                continue

        item["valid"] = True
        results.append(item)

    return {
        "tool": "LPE-Audit Workflow Output Validator",
        "schema_version": "1.0",
        "output_directory": str(root),
        "expected_count": len(names),
        "valid_count": sum(item["valid"] for item in results),
        "error_count": len(errors),
        "status": "PASS" if not errors else "FAIL",
        "read_only": True,
        "automatic_remediation": False,
        "artifacts": results,
        "errors": errors,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate generated LPE-Audit workflow artifacts."
    )
    parser.add_argument("output_dir", help="Directory containing workflow outputs")
    parser.add_argument(
        "--expect",
        nargs="+",
        required=True,
        help="Expected artifact filenames relative to output_dir",
    )
    parser.add_argument(
        "--json-output",
        help="Optional path for a JSON validation summary",
    )
    args = parser.parse_args(argv)

    try:
        result = validate_workflow_outputs(args.output_dir, args.expect)
    except WorkflowOutputValidationError as exc:
        parser.error(str(exc))

    serialized = json.dumps(result, indent=2, ensure_ascii=False) + "\\n"

    if args.json_output:
        destination = Path(args.json_output).resolve()
        output_root = Path(args.output_dir).resolve()

        if destination == output_root or output_root in destination.parents:
            parser.error(
                "Validation summary must be outside the directory being validated."
            )

        if destination.exists():
            parser.error(
                f"Refusing to overwrite existing validation summary: {destination}"
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(serialized, encoding="utf-8")

    print(f"Status: {result['status']}")
    print(f"Artifacts valid: {result['valid_count']}/{result['expected_count']}")
    print(f"Issues: {result['error_count']}")
    print(f"Read-only: {result['read_only']}")

    if args.json_output:
        print(f"Summary: {Path(args.json_output).resolve()}")

    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
