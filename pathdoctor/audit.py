"""Core audit logic for pathdoctor."""

import os
from collections import Counter, defaultdict


def parse_entries(path_str=None):
    """Split a PATH string into a list of entries."""
    if path_str is None:
        path_str = os.environ.get("PATH", "")
    return path_str.split(os.pathsep)


def audit(path_str=None):
    """Audit a PATH string and return a findings dict."""
    entries = parse_entries(path_str)
    findings = {
        "entries": entries,
        "missing": [],
        "empty": [],
        "nonabs": [],
        "duplicates": [],
    }
    seen = Counter()
    for entry in entries:
        if entry == "":
            findings["empty"].append(entry)
            continue
        if not os.path.isabs(entry):
            findings["nonabs"].append(entry)
        if not os.path.isdir(entry):
            findings["missing"].append(entry)
        seen[entry] += 1
    findings["duplicates"] = [p for p, c in seen.items() if c > 1]
    return findings


def shadowed_binaries(entries=None, names=None):
    """Return binaries present in more than one PATH directory."""
    if entries is None:
        entries = parse_entries()
    result = defaultdict(list)
    for directory in entries:
        if not directory or not os.path.isdir(directory):
            continue
        try:
            for name in os.listdir(directory):
                full = os.path.join(directory, name)
                if not os.path.isfile(full) or not os.access(full, os.X_OK):
                    continue
                if names and name not in names:
                    continue
                result[name].append(directory)
        except OSError:
            continue
    return {k: v for k, v in result.items() if len(v) > 1}


def format_report(findings, shadow=None):
    """Render findings as a human-readable report."""
    lines = ["PATH audit", "=" * 40, f"entries: {len(findings['entries'])}"]
    if findings["missing"]:
        lines.append("\nMissing directories:")
        lines.extend(f"  - {m}" for m in findings["missing"])
    if findings["empty"]:
        lines.append("\nEmpty entries:")
        lines.extend("  - (empty)" for _ in findings["empty"])
    if findings["nonabs"]:
        lines.append("\nNon-absolute entries:")
        lines.extend(f"  - {n}" for n in findings["nonabs"])
    if findings["duplicates"]:
        lines.append("\nDuplicate entries:")
        lines.extend(f"  - {d}" for d in findings["duplicates"])
    if shadow:
        lines.append("\nShadowed binaries (first wins):")
        for name, dirs in sorted(shadow.items()):
            lines.append(f"  - {name}: " + " -> ".join(dirs))
    if not any([findings["missing"], findings["empty"], findings["nonabs"], findings["duplicates"], shadow]):
        lines.append("\nNo issues found.")
    return "\n".join(lines)
