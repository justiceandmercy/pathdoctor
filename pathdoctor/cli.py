"""Command-line interface for pathdoctor."""

import argparse
import json
import sys

from .audit import audit, format_report, parse_entries, shadowed_binaries


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pathdoctor", description="Audit your PATH for common issues."
    )
    parser.add_argument("--path", help="PATH string to audit (default: $PATH)")
    parser.add_argument(
        "--shadow", action="store_true", help="Detect shadowed binaries"
    )
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args(argv)

    findings = audit(args.path)
    shadow = shadowed_binaries(parse_entries(args.path)) if args.shadow else None

    if args.json:
        out = dict(findings)
        if shadow is not None:
            out["shadowed"] = shadow
        print(json.dumps(out, indent=2))
    else:
        print(format_report(findings, shadow))

    has_issues = bool(
        findings["missing"]
        or findings["empty"]
        or findings["nonabs"]
        or findings["duplicates"]
        or shadow
    )
    return 1 if has_issues else 0


if __name__ == "__main__":
    sys.exit(main())
